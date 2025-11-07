#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#ifndef KSU_HAS_PATH_UMOUNT
#include <linux/syscalls.h> // sys_umount (<4.17) & ksys_umount (4.17+)
#endif
#include <linux/binfmts.h>
#include <linux/err.h>

#include "allowlist.h"
#include "arch.h"
#include "core_hook.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "throne_tracker.h"
#include "throne_comm.h"
#include "kernel_compat.h"
#include "supercalls.h"

bool ksu_module_mounted = false;

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC	0x1cd1
#endif

extern int __ksu_handle_devpts(struct inode *inode); // sucompat.c

#ifdef CONFIG_COMPAT
bool ksu_is_compat __read_mostly = false;
#endif

extern int handle_sepolicy(unsigned long arg3, void __user *arg4);

static bool ksu_kernel_umount_enabled = true;

static int kernel_umount_feature_get(u64 *value)
{
	*value = ksu_kernel_umount_enabled ? 1 : 0;
	return 0;
}

static int kernel_umount_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_kernel_umount_enabled = enable;
	pr_info("kernel_umount: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
	.feature_id = KSU_FEATURE_KERNEL_UMOUNT,
	.name = "kernel_umount",
	.get_handler = kernel_umount_feature_get,
	.set_handler = kernel_umount_feature_set,
};

static inline bool is_allow_su(void)
{
	if (is_manager()) {
		// we are manager, allow!
		return true;
	}
	return ksu_is_allow_uid(current_uid().val);
}

static inline bool is_unsupported_uid(uid_t uid)
{
#define LAST_APPLICATION_UID 19999
	uid_t appid = uid % 100000;
	return appid > LAST_APPLICATION_UID;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
static struct group_info root_groups = {
	.usage = REFCOUNT_INIT(2),
};
#else
static struct group_info root_groups = { .usage = ATOMIC_INIT(2) };
#endif

static void setup_groups(struct root_profile *profile, struct cred *cred)
{
	if (profile->groups_count > KSU_MAX_GROUPS) {
		pr_warn("Failed to setgroups, too large group: %d!\n",
			profile->uid);
		return;
	}

	if (profile->groups_count == 1 && profile->groups[0] == 0) {
		// setgroup to root and return early.
		if (cred->group_info)
			put_group_info(cred->group_info);
		cred->group_info = get_group_info(&root_groups);
		return;
	}

	u32 ngroups = profile->groups_count;
	struct group_info *group_info = groups_alloc(ngroups);
	if (!group_info) {
		pr_warn("Failed to setgroups, ENOMEM for: %d\n", profile->uid);
		return;
	}

	int i;
	for (i = 0; i < ngroups; i++) {
		gid_t gid = profile->groups[i];
		kgid_t kgid = make_kgid(current_user_ns(), gid);
		if (!gid_valid(kgid)) {
			pr_warn("Failed to setgroups, invalid gid: %d\n", gid);
			put_group_info(group_info);
			return;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
		group_info->gid[i] = kgid;
#else
		GROUP_AT(group_info, i) = kgid;
#endif
	}

	groups_sort(group_info);
	set_groups(cred, group_info);
	put_group_info(group_info);
}

static void disable_seccomp(struct task_struct *tsk)
{
	assert_spin_locked(&tsk->sighand->siglock);

	// disable seccomp
#if defined(CONFIG_GENERIC_ENTRY) &&                                           \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	clear_syscall_work(SECCOMP);
#else
	clear_thread_flag(TIF_SECCOMP);
#endif

#ifdef CONFIG_SECCOMP
	tsk->seccomp.mode = 0;
	if (tsk->seccomp.filter) {
		// 5.9+ have filter_count and use seccomp_filter_release
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
		seccomp_filter_release(tsk);
		atomic_set(&tsk->seccomp.filter_count, 0);
#else
		// for 6.11+ kernel support?
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
		put_seccomp_filter(tsk);
#endif
		tsk->seccomp.filter = NULL;
#endif
	}
#endif
}

void escape_to_root(void)
{
	struct cred *cred;

	cred = prepare_creds();
	if (!cred) {
		pr_warn("prepare_creds failed!\n");
		return;
	}

	if (cred->euid.val == 0) {
		pr_warn("Already root, don't escape!\n");
		abort_creds(cred);
		return;
	}

	struct root_profile *profile = ksu_get_root_profile(cred->uid.val);

	cred->uid.val = profile->uid;
	cred->suid.val = profile->uid;
	cred->euid.val = profile->uid;
	cred->fsuid.val = profile->uid;

	cred->gid.val = profile->gid;
	cred->fsgid.val = profile->gid;
	cred->sgid.val = profile->gid;
	cred->egid.val = profile->gid;
	cred->securebits = 0;

	BUILD_BUG_ON(sizeof(profile->capabilities.effective) !=
		     sizeof(kernel_cap_t));

	// setup capabilities
	// we need CAP_DAC_READ_SEARCH becuase `/data/adb/ksud` is not accessible for non root process
	// we add it here but don't add it to cap_inhertiable, it would be dropped automaticly after exec!
	u64 cap_for_ksud =
		profile->capabilities.effective | CAP_DAC_READ_SEARCH;
	memcpy(&cred->cap_effective, &cap_for_ksud,
	       sizeof(cred->cap_effective));
	memcpy(&cred->cap_permitted, &profile->capabilities.effective,
	       sizeof(cred->cap_permitted));
	memcpy(&cred->cap_bset, &profile->capabilities.effective,
	       sizeof(cred->cap_bset));

	setup_groups(profile, cred);

	commit_creds(cred);

	spin_lock_irq(&current->sighand->siglock);
	disable_seccomp(current);
	spin_unlock_irq(&current->sighand->siglock);

	setup_selinux(profile->selinux_domain);
}

void nuke_ext4_sysfs(void)
{
#ifdef CONFIG_EXT4_FS
	struct path path;
	int err = kern_path("/data/adb/modules", 0, &path);
	if (err) {
		pr_err("%s: failed to get path, err %d\n", __func__, err);
		return;
	}

	struct super_block *sb = path.dentry->d_inode->i_sb;
	const char *name = sb->s_type->name;
	if (strcmp(name, "ext4") != 0) {
		pr_info("skipping s_type: %s\n", name);
		path_put(&path);
		return;
	}

	ext4_unregister_sysfs(sb);
	path_put(&path);
#endif
}

static bool is_appuid(kuid_t uid)
{
#define PER_USER_RANGE 100000
#define FIRST_APPLICATION_UID 10000
#define LAST_APPLICATION_UID 19999

	uid_t appid = uid.val % PER_USER_RANGE;
	return appid >= FIRST_APPLICATION_UID && appid <= LAST_APPLICATION_UID;
}

static bool should_umount(struct path *path)
{
	if (!path) {
		return false;
	}

	if (current->nsproxy->mnt_ns == init_nsproxy.mnt_ns) {
		pr_info("ignore global mnt namespace process: %d\n",
			current_uid().val);
		return false;
	}

	if (path->mnt && path->mnt->mnt_sb && path->mnt->mnt_sb->s_type) {
		const char *fstype = path->mnt->mnt_sb->s_type->name;
		return strcmp(fstype, "overlay") == 0;
	}
	return false;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) ||                           \
	defined(KSU_HAS_PATH_UMOUNT)
#define ksu_umount_mnt(__unused, path, flags) (path_umount(path, flags))
#else
static int ksu_sys_umount(const char *mnt, int flags)
{
	char __user *usermnt = (char __user *)mnt;
	mm_segment_t old_fs;
	int ret; // although asmlinkage long

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	ret = ksys_umount(usermnt, flags);
#else
	ret = sys_umount(usermnt, flags); // cuz asmlinkage long sys##name
#endif
	set_fs(old_fs);
	return ret;
}

#define ksu_umount_mnt(mnt, __unused, flags)                                   \
	({                                                                     \
		int ret;                                                       \
		path_put(__unused);                                            \
		ret = ksu_sys_umount(mnt, flags);                              \
		ret;                                                           \
	})

#endif

static void try_umount(const char *mnt, bool check_mnt, int flags)
{
	struct path path;
	int ret;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		return;
	}

	if (path.dentry != path.mnt->mnt_root) {
		// it is not root mountpoint, maybe umounted by others already.
		path_put(&path);
		return;
	}

	// we are only interest in some specific mounts
	if (check_mnt && !should_umount(&path)) {
		path_put(&path);
		return;
	}

	ret = ksu_umount_mnt(mnt, &path, flags);
	if (ret) {
#ifdef CONFIG_KSU_DEBUG
		pr_info("%s: path: %s, ret: %d\n", __func__, mnt, ret);
#endif
	}
}

static void ksu_do_umount_lists(void)
{
	// fixme: use `collect_mounts` and `iterate_mount` to iterate all mountpoint and
	// filter the mountpoint whose target is `/data/adb`
	try_umount("/odm", true, 0);
	try_umount("/system", true, 0);
	try_umount("/vendor", true, 0);
	try_umount("/product", true, 0);
	try_umount("/system_ext", true, 0);
	try_umount("/data/adb/modules", false, MNT_DETACH);

	try_umount("/debug_ramdisk", false, MNT_DETACH);
	try_umount("/sbin", false, MNT_DETACH);
}

#if defined(MODULE) || defined(CONFIG_KSU_KPROBES_HOOK)
struct umount_tw {
	struct callback_head cb;
	const struct cred *old_cred;
};

static void umount_tw_func(struct callback_head *cb)
{
	struct umount_tw *tw = container_of(cb, struct umount_tw, cb);
	const struct cred *saved = NULL;
	if (tw->old_cred) {
		saved = override_creds(tw->old_cred);
	}

	ksu_do_umount_lists();

	if (saved)
		revert_creds(saved);

	if (tw->old_cred)
		put_cred(tw->old_cred);

	kfree(tw);
}
#endif

int ksu_handle_setuid(struct cred *new, const struct cred *old)
{
	if (!new || !old) {
		return 0;
	}

	kuid_t new_uid = new->uid;
	kuid_t old_uid = old->uid;
	// pr_info("handle_setuid from %d to %d\n", old_uid.val, new_uid.val);

	if (0 != old_uid.val) {
		// old process is not root, ignore it.
		return 0;
	}

	if (!is_appuid(new_uid) || is_unsupported_uid(new_uid.val)) {
		// pr_info("handle setuid ignore non application or isolated uid: %d\n", new_uid.val);
		return 0;
	}

	// if on private space, see if its possibly the manager
	if (new_uid.val > 100000 &&
	    new_uid.val % 100000 == ksu_get_manager_uid()) {
		ksu_set_manager_uid(new_uid.val);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	if (ksu_get_manager_uid() == new_uid.val) {
		pr_info("install fd for ksu manager(uid=%d)\n", new_uid.val);
		ksu_install_fd();
		spin_lock_irq(&current->sighand->siglock);
		ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
		spin_unlock_irq(&current->sighand->siglock);
		return 0;
	}

	if (ksu_is_allow_uid(new_uid.val)) {
		if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
		    current->seccomp.filter) {
			spin_lock_irq(&current->sighand->siglock);
			ksu_seccomp_allow_cache(current->seccomp.filter,
						__NR_reboot);
			spin_unlock_irq(&current->sighand->siglock);
		}
	}
#else
	if (ksu_is_allow_uid(new_uid.val)) {
		spin_lock_irq(&current->sighand->siglock);
		disable_seccomp(current);
		spin_unlock_irq(&current->sighand->siglock);

		if (ksu_get_manager_uid() == new_uid.val) {
			pr_info("install fd for ksu manager(uid=%d)\n", new_uid.val);
			ksu_install_fd();
		}

		return 0;
	}
#endif

	// this hook is used for umounting overlayfs for some uid, if there isn't any module mounted, just ignore it!
	if (!ksu_module_mounted) {
		return 0;
	}

	if (!ksu_kernel_umount_enabled) {
		return 0;
	}

	if (!ksu_uid_should_umount(new_uid.val)) {
		return 0;
	} else {
#ifdef CONFIG_KSU_DEBUG
		pr_info("uid: %d should not umount!\n", current_uid().val);
#endif
	}

	// check old process's selinux context, if it is not zygote, ignore it!
	// because some su apps may setuid to untrusted_app but they are in global mount namespace
	// when we umount for such process, that is a disaster!
	if (!is_zygote(old->security)) {
		pr_info("handle umount ignore non zygote child: %d\n",
			current->pid);
		return 0;
	}
#ifdef CONFIG_KSU_DEBUG
	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid.val,
		current->pid);
#endif

#if defined(MODULE) || defined(CONFIG_KSU_KPROBES_HOOK)
	struct umount_tw *tw;
	tw = kmalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;

	tw->old_cred = get_current_cred();
	tw->cb.func = umount_tw_func;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 8)
	int err = task_work_add(current, &tw->cb, TWA_RESUME);
#else
	int err = task_work_add(current, &tw->cb, true);
#endif

	if (err) {
		if (tw->old_cred) {
			put_cred(tw->old_cred);
		}
		kfree(tw);
		pr_warn("unmount add task_work failed\n");
	}
#else
	ksu_do_umount_lists();
#endif

	return 0;
}

int ksu_inode_permission(struct inode *inode, int mask)
{
	if (inode && inode->i_sb 
		&& unlikely(inode->i_sb->s_magic == DEVPTS_SUPER_MAGIC)) {
		//pr_info("%s: handling devpts for: %s \n", __func__, current->comm);
		__ksu_handle_devpts(inode);
	}
	return 0;
}

int ksu_bprm_check(struct linux_binprm *bprm)
{
	char *filename = (char *)bprm->filename;
	
	if (likely(!ksu_execveat_hook))
		return 0;

#ifdef CONFIG_COMPAT
	static bool compat_check_done __read_mostly = false;
	if ( unlikely(!compat_check_done) && unlikely(!strcmp(filename, "/data/adb/ksud"))
		&& !memcmp(bprm->buf, "\x7f\x45\x4c\x46", 4) ) {
		if (bprm->buf[4] == 0x01 )
			ksu_is_compat = true;

		pr_info("%s: %s ELF magic found! ksu_is_compat: %d \n", __func__, filename, ksu_is_compat);
		compat_check_done = true;
	}
#endif

	ksu_handle_pre_ksud(filename);

	return 0;

}

int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
			  void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;

#ifdef CONFIG_KSU_DEBUG
	pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1,
		magic2);
#endif

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		int fd = ksu_install_fd();
		// downstream: dereference all arg usage!
		if (copy_to_user((void __user *)*arg, &fd, sizeof(fd))) {
			pr_err("install ksu fd reply err\n");
		}
		return 0;
	}

	// extensions

	return 0;
}

// -- For old kernel compat?
#if !defined(MODULE) && !defined(CONFIG_KSU_KPROBES_HOOK)
static int ksu_task_fix_setuid(struct cred *new,
					      const struct cred *old, int flags)
{
	return ksu_handle_setuid(new, old);
}

// kernel 4.4 and 4.9
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
static int ksu_key_permission(key_ref_t key_ref, const struct cred *cred,
			      unsigned perm)
{
	if (init_session_keyring != NULL) {
		return 0;
	}
	if (strcmp(current->comm, "init")) {
		// we are only interested in `init` process
		return 0;
	}
	init_session_keyring = cred->session_keyring;
	pr_info("kernel_compat: got init_session_keyring\n");
	return 0;
}
#endif

#include <linux/lsm_hooks.h>
static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
	LSM_HOOK_INIT(inode_permission, ksu_inode_permission),
	#ifndef CONFIG_KSU_KPROBES_HOOK
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	LSM_HOOK_INIT(key_permission, ksu_key_permission)
#endif
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
static const struct lsm_id ksu_lsmid = {
	.name = "ksu",
	.id = 912,
};
#endif

static void ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), &ksu_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	// https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
	pr_info("LSM hooks initialized.\n");
}
#else
static void ksu_lsm_hook_init(void)
{
}
#endif

// -- For KPROBE and LKM handler
#if defined(MODULE) || defined(CONFIG_KSU_KPROBES_HOOK)
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	int cmd = (int)PT_REGS_PARM3(real_regs);
	void __user **arg = (void __user **)&PT_REGS_SYSCALL_PARM4(real_regs);

	return ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
}

static struct kprobe reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = reboot_handler_pre,
};

// 2. cap_task_fix_setuid hook for handling setuid
static int cap_task_fix_setuid_handler_pre(struct kprobe *p,
					   struct pt_regs *regs)
{
	struct cred *new = (struct cred *)PT_REGS_PARM1(regs);
	const struct cred *old = (const struct cred *)PT_REGS_PARM2(regs);

	ksu_handle_setuid(new, old);

	return 0;
}

static struct kprobe cap_task_fix_setuid_kp = {
	.symbol_name = "cap_task_fix_setuid",
	.pre_handler = cap_task_fix_setuid_handler_pre,
};

static int ksu_kprobe_init(void)
{
	int rc = 0;

	// Register reboot kprobe
	rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("reboot kprobe failed: %d\n", rc);
		return rc;
	}
	pr_info("reboot kprobe registered successfully\n");

	// Register cap_task_fix_setuid kprobe
	rc = register_kprobe(&cap_task_fix_setuid_kp);
	if (rc) {
		pr_err("cap_task_fix_setuid kprobe failed: %d\n", rc);
		unregister_kprobe(&reboot_kp);
		return rc;
	}
	pr_info("cap_task_fix_setuid kprobe registered successfully\n");

	return 0;
}

static void ksu_kprobe_exit(void)
{
	unregister_kprobe(&cap_task_fix_setuid_kp);
	unregister_kprobe(&reboot_kp);
}

void __init ksu_core_init(void)
{
	int rc = ksu_kprobe_init();
	if (rc) {
		pr_err("ksu_kprobe_init failed: %d\n", rc);
	}

	if (ksu_register_feature_handler(&kernel_umount_handler)) {
		pr_err("Failed to register umount feature handler\n");
	}
}

void ksu_core_exit(void)
{
	pr_info("ksu_core_exit\n");
	ksu_kprobe_exit();
	ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
}
#else

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();

	if (ksu_register_feature_handler(&kernel_umount_handler)) {
		pr_err("Failed to register umount feature handler\n");
	}
}

void ksu_core_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
	ksu_uid_exit();
	ksu_throne_comm_exit();
}

#endif
