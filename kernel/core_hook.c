#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/mount.h>

#include <linux/fs.h>
#include <linux/namei.h>

#ifdef MODULE
#include <linux/list.h>
#include <linux/irqflags.h>
#include <linux/mm_types.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>
#endif

#include "allowlist.h"
#include "arch.h"
#include "core_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "throne_tracker.h"
#include "kernel_compat.h"

#include "kpm/kpm.h"
#include "dynamic_sign.h"

static bool ksu_module_mounted = false;

extern int handle_sepolicy(unsigned long arg3, void __user *arg4);

static bool ksu_su_compat_enabled = true;
extern void ksu_sucompat_init();
extern void ksu_sucompat_exit();

static inline bool is_allow_su()
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

static struct group_info root_groups = { .usage = ATOMIC_INIT(2) };

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
		group_info->gid[i] = kgid;
	}

	groups_sort(group_info);
	set_groups(cred, group_info);
	put_group_info(group_info);
}

static void disable_seccomp()
{
	assert_spin_locked(&current->sighand->siglock);
	// disable seccomp
#if defined(CONFIG_GENERIC_ENTRY) &&                                           \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	current_thread_info()->syscall_work &= ~SYSCALL_WORK_SECCOMP;
#else
	current_thread_info()->flags &= ~(TIF_SECCOMP | _TIF_SECCOMP);
#endif

#ifdef CONFIG_SECCOMP
	current->seccomp.mode = 0;
	current->seccomp.filter = NULL;
#else
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

	// Refer to kernel/seccomp.c: seccomp_set_mode_strict
	// When disabling Seccomp, ensure that current->sighand->siglock is held during the operation.
	spin_lock_irq(&current->sighand->siglock);
	disable_seccomp();
	spin_unlock_irq(&current->sighand->siglock);

	setup_selinux(profile->selinux_domain);
}

int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry)
{
	if (!current->mm) {
		// skip kernel threads
		return 0;
	}

	if (current_uid().val != 1000) {
		// skip non system uid
		return 0;
	}

	if (!old_dentry || !new_dentry) {
		return 0;
	}

	// /data/system/packages.list.tmp -> /data/system/packages.list
	if (strcmp(new_dentry->d_iname, "packages.list")) {
		return 0;
	}

	char path[128];
	char *buf = dentry_path_raw(new_dentry, path, sizeof(path));
	if (IS_ERR(buf)) {
		pr_err("dentry_path_raw failed.\n");
		return 0;
	}

	if (!strstr(buf, "/system/packages.list")) {
		return 0;
	}
	pr_info("renameat: %s -> %s, new path: %s\n", old_dentry->d_iname,
		new_dentry->d_iname, buf);

	track_throne();

	return 0;
}

#ifdef CONFIG_EXT4_FS
static void nuke_ext4_sysfs() {
	struct path path;
	int err = kern_path("/data/adb/modules", 0, &path);
	if (err) {
		pr_err("nuke path err: %d\n", err);
		return;
	}

	struct super_block* sb = path.dentry->d_inode->i_sb;
	const char* name = sb->s_type->name;
	if (strcmp(name, "ext4") != 0) {
		pr_info("nuke but module aren't mounted\n");
		return;
	}

	ext4_unregister_sysfs(sb);
	path_put(&path);
}
#else
static inline void nuke_ext4_sysfs() { }
#endif

static bool is_system_bin_su()
{
	// YES in_execve becomes 0 when it succeeds.
	if (!current->mm || current->in_execve) 
		return false;

	// quick af check
	return (current->mm->exe_file && !strcmp(current->mm->exe_file->f_path.dentry->d_name.name, "su"));
}

int ksu_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
		     unsigned long arg4, unsigned long arg5)
{
	// if success, we modify the arg5 as result!
	u32 *result = (u32 *)arg5;
	u32 reply_ok = KERNEL_SU_OPTION;

	if (KERNEL_SU_OPTION != option) {
		return 0;
	}

	// TODO: find it in throne tracker!
	uid_t current_uid_val = current_uid().val;
	uid_t manager_uid = ksu_get_manager_uid();
	if (current_uid_val != manager_uid &&
	    current_uid_val % 100000 == manager_uid) {
		ksu_set_manager_uid(current_uid_val);
	}

	bool from_root = 0 == current_uid().val;
	bool from_manager = is_manager();

	if (!from_root && !from_manager 
		&& !(is_allow_su() && is_system_bin_su())) {
		// only root or manager can access this interface
		return 0;
	}

#ifdef CONFIG_KSU_DEBUG
	pr_info("option: 0x%x, cmd: %ld\n", option, arg2);
#endif

	if (arg2 == CMD_BECOME_MANAGER) {
		if (from_manager) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("become_manager: prctl reply error\n");
			}
			return 0;
		}
		return 0;
	}

	if (arg2 == CMD_GRANT_ROOT) {
		if (is_allow_su()) {
			pr_info("allow root for: %d\n", current_uid().val);
			escape_to_root();
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("grant_root: prctl reply error\n");
			}
		}
		return 0;
	}

	// Both root manager and root processes should be allowed to get version
	if (arg2 == CMD_GET_VERSION) {
		u32 version = KERNEL_SU_VERSION;
		if (copy_to_user(arg3, &version, sizeof(version))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		u32 version_flags = 2;
#ifdef MODULE
		version_flags |= 0x1;
#endif
		if (arg4 &&
		    copy_to_user(arg4, &version_flags, sizeof(version_flags))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	// Allow root manager to get full version strings
	if (arg2 == CMD_GET_FULL_VERSION) {
		char ksu_version_full[KSU_FULL_VERSION_STRING] = {0};
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
		strscpy(ksu_version_full, KSU_VERSION_FULL, KSU_FULL_VERSION_STRING);
#else
		strlcpy(ksu_version_full, KSU_VERSION_FULL, KSU_FULL_VERSION_STRING);
#endif
		if (copy_to_user((void __user *)arg3, ksu_version_full, KSU_FULL_VERSION_STRING)) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
			return -EFAULT;
		}
		return 0;
	}

	// Allow the root manager to configure dynamic signatures
	if (arg2 == CMD_DYNAMIC_SIGN) {
    	if (!from_root && !from_manager) {
        	return 0;
    	}
    
    	struct dynamic_sign_user_config config;
    
    	if (copy_from_user(&config, (void __user *)arg3, sizeof(config))) {
        	pr_err("copy dynamic sign config failed\n");
        	return 0;
    	}
    
    	int ret = ksu_handle_dynamic_sign(&config);
    	
    	if (ret == 0 && config.operation == DYNAMIC_SIGN_OP_GET) {
        	if (copy_to_user((void __user *)arg3, &config, sizeof(config))) {
            	pr_err("copy dynamic sign config back failed\n");
            	return 0;
        	}
    	}
    	
    	if (ret == 0) {
        	if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
            	pr_err("dynamic_sign: prctl reply error\n");
        	}
    	}
    	return 0;
	}

	// Allow root manager to get active managers
	if (arg2 == CMD_GET_MANAGERS) {
		if (!from_root && !from_manager) {
			return 0;
		}
		
		struct manager_list_info manager_info;
		int ret = ksu_get_active_managers(&manager_info);
		
		if (ret == 0) {
			if (copy_to_user((void __user *)arg3, &manager_info, sizeof(manager_info))) {
				pr_err("copy manager list failed\n");
				return 0;
			}
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("get_managers: prctl reply error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_REPORT_EVENT) {
		if (!from_root) {
			return 0;
		}
		switch (arg3) {
		case EVENT_POST_FS_DATA: {
			static bool post_fs_data_lock = false;
			if (!post_fs_data_lock) {
				post_fs_data_lock = true;
				pr_info("post-fs-data triggered\n");
				on_post_fs_data();
				// Initializing Dynamic Signatures
        		ksu_dynamic_sign_init();
        		pr_info("Dynamic sign config loaded during post-fs-data\n");
			}
			break;
		}
		case EVENT_BOOT_COMPLETED: {
			static bool boot_complete_lock = false;
			if (!boot_complete_lock) {
				boot_complete_lock = true;
				pr_info("boot_complete triggered\n");
			}
			break;
		}
		case EVENT_MODULE_MOUNTED: {
			ksu_module_mounted = true;
			pr_info("module mounted!\n");
			nuke_ext4_sysfs();
			break;
		}
		default:
			break;
		}
		return 0;
	}

	if (arg2 == CMD_SET_SEPOLICY) {
		if (!from_root) {
			return 0;
		}
		if (!handle_sepolicy(arg3, arg4)) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("sepolicy: prctl reply error\n");
			}
		}

		return 0;
	}

	if (arg2 == CMD_CHECK_SAFEMODE) {
		if (ksu_is_safe_mode()) {
			pr_warn("safemode enabled!\n");
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("safemode: prctl reply error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_GET_ALLOW_LIST || arg2 == CMD_GET_DENY_LIST) {
		u32 array[128];
		u32 array_length;
		bool success = ksu_get_allow_list(array, &array_length,
						  arg2 == CMD_GET_ALLOW_LIST);
		if (success) {
			if (!copy_to_user(arg4, &array_length,
					  sizeof(array_length)) &&
			    !copy_to_user(arg3, array,
					  sizeof(u32) * array_length)) {
				if (copy_to_user(result, &reply_ok,
						 sizeof(reply_ok))) {
					pr_err("prctl reply error, cmd: %lu\n",
					       arg2);
				}
			} else {
				pr_err("prctl copy allowlist error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_UID_GRANTED_ROOT || arg2 == CMD_UID_SHOULD_UMOUNT) {
		uid_t target_uid = (uid_t)arg3;
		bool allow = false;
		if (arg2 == CMD_UID_GRANTED_ROOT) {
			allow = ksu_is_allow_uid(target_uid);
		} else if (arg2 == CMD_UID_SHOULD_UMOUNT) {
			allow = ksu_uid_should_umount(target_uid);
		} else {
			pr_err("unknown cmd: %lu\n", arg2);
		}
		if (!copy_to_user(arg4, &allow, sizeof(allow))) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
		} else {
			pr_err("prctl copy err, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_ENABLE_SU) {
		bool enabled = (arg3 != 0);
		if (enabled == ksu_su_compat_enabled) {
			pr_info("cmd enable su but no need to change.\n");
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {// return the reply_ok directly
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
			return 0;
		}

		if (enabled) {
			ksu_sucompat_init();
		} else {
			ksu_sucompat_exit();
		}
		ksu_su_compat_enabled = enabled;

		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}

		return 0;
	}

	#ifdef CONFIG_KPM
	// ADD: 添加KPM模块控制
	if(sukisu_is_kpm_control_code(arg2)) {
		int res;

		pr_info("KPM: calling before arg2=%d\n", (int) arg2);
		
		res = sukisu_handle_kpm(arg2, arg3, arg4, arg5);

		return 0;
	}
	#endif

	if (arg2 == CMD_ENABLE_KPM) {
    	bool KPM_Enabled = IS_ENABLED(CONFIG_KPM);
    	if (copy_to_user((void __user *)arg3, &KPM_Enabled, sizeof(KPM_Enabled)))
        	pr_info("KPM: copy_to_user() failed\n");
    	return 0;
	}

	// all other cmds are for 'root manager'
	if (!from_manager) {
		return 0;
	}

	// we are already manager
	if (arg2 == CMD_GET_APP_PROFILE) {
		struct app_profile profile;
		if (copy_from_user(&profile, arg3, sizeof(profile))) {
			pr_err("copy profile failed\n");
			return 0;
		}

		bool success = ksu_get_app_profile(&profile);
		if (success) {
			if (copy_to_user(arg3, &profile, sizeof(profile))) {
				pr_err("copy profile failed\n");
				return 0;
			}
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
		}
		return 0;
	}

	if (arg2 == CMD_SET_APP_PROFILE) {
		struct app_profile profile;
		if (copy_from_user(&profile, arg3, sizeof(profile))) {
			pr_err("copy profile failed\n");
			return 0;
		}

		// todo: validate the params
		if (ksu_set_app_profile(&profile, true)) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
		}
		return 0;
	}

	if (arg2 == CMD_IS_SU_ENABLED) {
		if (copy_to_user(arg3, &ksu_su_compat_enabled,
				 sizeof(ksu_su_compat_enabled))) {
			pr_err("copy su compat failed\n");
			return 0;
		}
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	return 0;
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

static void ksu_umount_mnt(struct path *path, int flags)
{
	int err = path_umount(path, flags);
	if (err) {
		pr_info("umount %s failed: %d\n", path->dentry->d_iname, err);
	}
}

static void try_umount(const char *mnt, bool check_mnt, int flags)
{
	struct path path;
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

	ksu_umount_mnt(&path, flags);
}

int ksu_handle_setuid(struct cred *new, const struct cred *old)
{
	// this hook is used for umounting overlayfs for some uid, if there isn't any module mounted, just ignore it!
	if (!ksu_module_mounted) {
		return 0;
	}

	if (!new || !old) {
		return 0;
	}

	kuid_t new_uid = new->uid;
	kuid_t old_uid = old->uid;

	if (0 != old_uid.val) {
		// old process is not root, ignore it.
		return 0;
	}

	if (!is_appuid(new_uid) || is_unsupported_uid(new_uid.val)) {
		// pr_info("handle setuid ignore non application or isolated uid: %d\n", new_uid.val);
		return 0;
	}

	if (ksu_is_allow_uid(new_uid.val)) {
		// pr_info("handle setuid ignore allowed application: %d\n", new_uid.val);
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
	bool is_zygote_child = is_zygote(old->security);
	if (!is_zygote_child) {
		pr_info("handle umount ignore non zygote child: %d\n",
			current->pid);
		return 0;
	}
#ifdef CONFIG_KSU_DEBUG
	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid.val,
		current->pid);
#endif

	// fixme: use `collect_mounts` and `iterate_mount` to iterate all mountpoint and
	// filter the mountpoint whose target is `/data/adb`
	try_umount("/system", true, 0);
	try_umount("/vendor", true, 0);
	try_umount("/product", true, 0);
	try_umount("/system_ext", true, 0);
	try_umount("/data/adb/modules", false, MNT_DETACH);

	// try umount ksu temp path
	try_umount("/debug_ramdisk", false, MNT_DETACH);

	return 0;
}

// Init functons

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int option = (int)PT_REGS_PARM1(real_regs);
	unsigned long arg2 = (unsigned long)PT_REGS_PARM2(real_regs);
	unsigned long arg3 = (unsigned long)PT_REGS_PARM3(real_regs);
	// PRCTL_SYMBOL is the arch-specificed one, which receive raw pt_regs from syscall
	unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	unsigned long arg5 = (unsigned long)PT_REGS_PARM5(real_regs);

	return ksu_handle_prctl(option, arg2, arg3, arg4, arg5);
}

static struct kprobe prctl_kp = {
	.symbol_name = PRCTL_SYMBOL,
	.pre_handler = handler_pre,
};

static int renameat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	// https://elixir.bootlin.com/linux/v5.12-rc1/source/include/linux/fs.h
	struct renamedata *rd = PT_REGS_PARM1(regs);
	struct dentry *old_entry = rd->old_dentry;
	struct dentry *new_entry = rd->new_dentry;
#else
	struct dentry *old_entry = (struct dentry *)PT_REGS_PARM2(regs);
	struct dentry *new_entry = (struct dentry *)PT_REGS_CCALL_PARM4(regs);
#endif

	return ksu_handle_rename(old_entry, new_entry);
}

static struct kprobe renameat_kp = {
	.symbol_name = "vfs_rename",
	.pre_handler = renameat_handler_pre,
};

__maybe_unused int ksu_kprobe_init(void)
{
	int rc = 0;
	rc = register_kprobe(&prctl_kp);

	if (rc) {
		pr_info("prctl kprobe failed: %d.\n", rc);
		return rc;
	}

	rc = register_kprobe(&renameat_kp);
	pr_info("renameat kp: %d\n", rc);

	return rc;
}

__maybe_unused int ksu_kprobe_exit(void)
{
	unregister_kprobe(&prctl_kp);
	unregister_kprobe(&renameat_kp);
	return 0;
}

static int ksu_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			  unsigned long arg4, unsigned long arg5)
{
	ksu_handle_prctl(option, arg2, arg3, arg4, arg5);
	return -ENOSYS;
}

static int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	return ksu_handle_rename(old_dentry, new_dentry);
}

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	return ksu_handle_setuid(new, old);
}

#ifndef MODULE
static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(task_prctl, ksu_task_prctl),
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
};

void __init ksu_lsm_hook_init(void)
{
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
}

#else
static int override_security_head(void *head, const void *new_head, size_t len)
{
	unsigned long base = (unsigned long)head & PAGE_MASK;
	unsigned long offset = offset_in_page(head);

	// this is impossible for our case because the page alignment
	// but be careful for other cases!
	BUG_ON(offset + len > PAGE_SIZE);
	struct page *page = phys_to_page(__pa(base));
	if (!page) {
		return -EFAULT;
	}

	void *addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!addr) {
		return -ENOMEM;
	}
	local_irq_disable();
	memcpy(addr + offset, new_head, len);
	local_irq_enable();
	vunmap(addr);
	return 0;
}

static void free_security_hook_list(struct hlist_head *head)
{
	struct hlist_node *temp;
	struct security_hook_list *entry;

	if (!head)
		return;

	hlist_for_each_entry_safe (entry, temp, head, list) {
		hlist_del(&entry->list);
		kfree(entry);
	}

	kfree(head);
}

struct hlist_head *copy_security_hlist(struct hlist_head *orig)
{
	struct hlist_head *new_head = kmalloc(sizeof(*new_head), GFP_KERNEL);
	if (!new_head)
		return NULL;

	INIT_HLIST_HEAD(new_head);

	struct security_hook_list *entry;
	struct security_hook_list *new_entry;

	hlist_for_each_entry (entry, orig, list) {
		new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry) {
			free_security_hook_list(new_head);
			return NULL;
		}

		*new_entry = *entry;

		hlist_add_tail_rcu(&new_entry->list, new_head);
	}

	return new_head;
}

#define LSM_SEARCH_MAX 180 // This should be enough to iterate
static void *find_head_addr(void *security_ptr, int *index)
{
	if (!security_ptr) {
		return NULL;
	}
	struct hlist_head *head_start =
		(struct hlist_head *)&security_hook_heads;

	for (int i = 0; i < LSM_SEARCH_MAX; i++) {
		struct hlist_head *head = head_start + i;
		struct security_hook_list *pos;
		hlist_for_each_entry (pos, head, list) {
			if (pos->hook.capget == security_ptr) {
				if (index) {
					*index = i;
				}
				return head;
			}
		}
	}

	return NULL;
}

#define GET_SYMBOL_ADDR(sym)                                                   \
	({                                                                     \
		void *addr = kallsyms_lookup_name(#sym ".cfi_jt");             \
		if (!addr) {                                                   \
			addr = kallsyms_lookup_name(#sym);                     \
		}                                                              \
		addr;                                                          \
	})

#define KSU_LSM_HOOK_HACK_INIT(head_ptr, name, func)                           \
	do {                                                                   \
		static struct security_hook_list hook = {                      \
			.hook = { .name = func }                               \
		};                                                             \
		hook.head = head_ptr;                                          \
		hook.lsm = "ksu";                                              \
		struct hlist_head *new_head = copy_security_hlist(hook.head);  \
		if (!new_head) {                                               \
			pr_err("Failed to copy security list: %s\n", #name);   \
			break;                                                 \
		}                                                              \
		hlist_add_tail_rcu(&hook.list, new_head);                      \
		if (override_security_head(hook.head, new_head,                \
					   sizeof(*new_head))) {               \
			free_security_hook_list(new_head);                     \
			pr_err("Failed to hack lsm for: %s\n", #name);         \
		}                                                              \
	} while (0)

void __init ksu_lsm_hook_init(void)
{
	void *cap_prctl = GET_SYMBOL_ADDR(cap_task_prctl);
	void *prctl_head = find_head_addr(cap_prctl, NULL);
	if (prctl_head) {
		if (prctl_head != &security_hook_heads.task_prctl) {
			pr_warn("prctl's address has shifted!\n");
		}
		KSU_LSM_HOOK_HACK_INIT(prctl_head, task_prctl, ksu_task_prctl);
	} else {
		pr_warn("Failed to find task_prctl!\n");
	}

	int inode_killpriv_index = -1;
	void *cap_killpriv = GET_SYMBOL_ADDR(cap_inode_killpriv);
	find_head_addr(cap_killpriv, &inode_killpriv_index);
	if (inode_killpriv_index < 0) {
		pr_warn("Failed to find inode_rename, use kprobe instead!\n");
		register_kprobe(&renameat_kp);
	} else {
		int inode_rename_index = inode_killpriv_index +
					 &security_hook_heads.inode_rename -
					 &security_hook_heads.inode_killpriv;
		struct hlist_head *head_start =
			(struct hlist_head *)&security_hook_heads;
		void *inode_rename_head = head_start + inode_rename_index;
		if (inode_rename_head != &security_hook_heads.inode_rename) {
			pr_warn("inode_rename's address has shifted!\n");
		}
		KSU_LSM_HOOK_HACK_INIT(inode_rename_head, inode_rename,
				       ksu_inode_rename);
	}
	void *cap_setuid = GET_SYMBOL_ADDR(cap_task_fix_setuid);
	void *setuid_head = find_head_addr(cap_setuid, NULL);
	if (setuid_head) {
		if (setuid_head != &security_hook_heads.task_fix_setuid) {
			pr_warn("setuid's address has shifted!\n");
		}
		KSU_LSM_HOOK_HACK_INIT(setuid_head, task_fix_setuid,
				       ksu_task_fix_setuid);
	} else {
		pr_warn("Failed to find task_fix_setuid!\n");
	}
	smp_mb();
}
#endif

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}

void ksu_core_exit(void)
{
#ifdef CONFIG_KPROBE
	pr_info("ksu_core_kprobe_exit\n");
	// we dont use this now
	// ksu_kprobe_exit();
#endif
}
