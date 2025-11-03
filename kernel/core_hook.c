#include "linux/slab.h"
#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
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
#include <linux/security.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/binfmts.h>
#include <linux/tty.h>

#include "allowlist.h"
#include "arch.h"
#include "core_hook.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "kernel_compat.h"
#include "supercalls.h"
#include "sulog.h"

#ifdef CONFIG_KSU_MANUAL_SU
#include "manual_su.h"
#endif

bool ksu_module_mounted = false;

#ifdef CONFIG_COMPAT
bool ksu_is_compat __read_mostly = false;
#endif

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC    0x1cd1
#endif

extern int __ksu_handle_devpts(struct inode *inode); // sucompat.c

#ifdef CONFIG_KSU_MANUAL_SU
static void ksu_try_escalate_for_uid(uid_t uid)
{
    if (!is_pending_root(uid))
        return;
    
    pr_info("pending_root: UID=%d temporarily allowed\n", uid);
    remove_pending_root(uid);
}
#endif

static struct workqueue_struct *ksu_workqueue;

struct ksu_umount_work {
    struct work_struct work;
    struct mnt_namespace *mnt_ns;
};

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION (6, 7, 0)
    static struct group_info root_groups = { .usage = REFCOUNT_INIT(2), };
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
    clear_syscall_work(SECCOMP);
#else
    clear_thread_flag(TIF_SECCOMP);
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
#if __SULOG_GATE
        ksu_sulog_report_su_grant(current_euid().val, NULL, "escape_to_root_failed");
#endif
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
#if __SULOG_GATE
    ksu_sulog_report_su_grant(current_euid().val, NULL, "escape_to_root");
#endif
}

#ifdef CONFIG_KSU_MANUAL_SU

static void disable_seccomp_for_task(struct task_struct *tsk)
{
    if (!tsk->seccomp.filter && tsk->seccomp.mode == SECCOMP_MODE_DISABLED)
        return;

    if (WARN_ON(!spin_is_locked(&tsk->sighand->siglock)))
        return;

#ifdef CONFIG_SECCOMP
    tsk->seccomp.mode = 0;
    if (tsk->seccomp.filter) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
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

void escape_to_root_for_cmd_su(uid_t target_uid, pid_t target_pid)
{
    struct cred *newcreds;
    struct task_struct *target_task;

    pr_info("cmd_su: escape_to_root_for_cmd_su called for UID: %d, PID: %d\n", target_uid, target_pid);

    // Find target task by PID
    rcu_read_lock();
    target_task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (!target_task) {
        rcu_read_unlock(); 
        pr_err("cmd_su: target task not found for PID: %d\n", target_pid);
#if __SULOG_GATE
        ksu_sulog_report_su_grant(target_uid, "cmd_su", "target_not_found");
#endif
        return;
    }
    get_task_struct(target_task);
    rcu_read_unlock();

    if (task_uid(target_task).val == 0) {
        pr_warn("cmd_su: target task is already root, PID: %d\n", target_pid);
        put_task_struct(target_task);
        return;
    }

    newcreds = prepare_kernel_cred(target_task);
    if (newcreds == NULL) {
        pr_err("cmd_su: failed to allocate new cred for PID: %d\n", target_pid);
#if __SULOG_GATE
        ksu_sulog_report_su_grant(target_uid, "cmd_su", "cred_alloc_failed");
#endif
        put_task_struct(target_task);
        return;
    }

    struct root_profile *profile = ksu_get_root_profile(target_uid);

    newcreds->uid.val = profile->uid;
    newcreds->suid.val = profile->uid;
    newcreds->euid.val = profile->uid;
    newcreds->fsuid.val = profile->uid;

    newcreds->gid.val = profile->gid;
    newcreds->fsgid.val = profile->gid;
    newcreds->sgid.val = profile->gid;
    newcreds->egid.val = profile->gid;
    newcreds->securebits = 0;

    u64 cap_for_cmd_su = profile->capabilities.effective | CAP_DAC_READ_SEARCH | CAP_SETUID | CAP_SETGID;
    memcpy(&newcreds->cap_effective, &cap_for_cmd_su, sizeof(newcreds->cap_effective));
    memcpy(&newcreds->cap_permitted, &profile->capabilities.effective, sizeof(newcreds->cap_permitted));
    memcpy(&newcreds->cap_bset, &profile->capabilities.effective, sizeof(newcreds->cap_bset));

    setup_groups(profile, newcreds);
    task_lock(target_task);

    const struct cred *old_creds = get_task_cred(target_task);

    rcu_assign_pointer(target_task->real_cred, newcreds);
    rcu_assign_pointer(target_task->cred, get_cred(newcreds));
    task_unlock(target_task);

    if (target_task->sighand) {
        spin_lock_irq(&target_task->sighand->siglock);
        disable_seccomp_for_task(target_task);
        spin_unlock_irq(&target_task->sighand->siglock);
    }

    setup_selinux(profile->selinux_domain);
    put_cred(old_creds);
    wake_up_process(target_task);

    if (target_task->signal->tty) {
        struct inode *inode = target_task->signal->tty->driver_data;
        if (inode && inode->i_sb->s_magic == DEVPTS_SUPER_MAGIC) {
            __ksu_handle_devpts(inode);
        }
    }

    put_task_struct(target_task);
#if __SULOG_GATE
    ksu_sulog_report_su_grant(target_uid, "cmd_su", "manual_escalation");
#endif
    pr_info("cmd_su: privilege escalation completed for UID: %d, PID: %d\n", target_uid, target_pid);
}
#endif


#ifdef CONFIG_EXT4_FS
void nuke_ext4_sysfs(void) 
{
    struct path path;
    int err = kern_path("/data/adb/modules", 0, &path);
    if (err) {
        pr_err("nuke path err: %d\n", err);
        return;
    }

    struct super_block *sb = path.dentry->d_inode->i_sb;
    const char *name = sb->s_type->name;
    if (strcmp(name, "ext4") != 0) {
        pr_info("nuke but module aren't mounted\n");
        return;
    }

    ext4_unregister_sysfs(sb);
    path_put(&path);
}
#else
inline void nuke_ext4_sysfs(void) 
{

}
#endif

bool is_system_uid(void)
{
    if (!current->mm || current->in_execve) {
        return 0;
    }
    
    uid_t caller_uid = current_uid().val;
    return caller_uid <= 2000;
}

#if __SULOG_GATE
static void sulog_prctl_cmd(uid_t uid, unsigned long cmd)
{
    const char *name = NULL;

    switch (cmd) {

#ifdef CONFIG_KSU_MANUAL_SU
    case CMD_MANUAL_SU_REQUEST:             name = "prctl_manual_su_request"; break;
#endif

    default:                                name = "prctl_unknown"; break;
    }

    ksu_sulog_report_syscall(uid, NULL, name, NULL);
}
#endif

int ksu_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
             unsigned long arg4, unsigned long arg5)
{
    // if success, we modify the arg5 as result!
    __maybe_unused u32 *result = (u32 *)arg5;
	__maybe_unused u32 reply_ok = KERNEL_SU_OPTION;

    if (likely(ksu_is_current_proc_umounted()))
        return 0; // prevent side channel attack in ksu side

    if (KERNEL_SU_OPTION != option)
        return 0;
    
#if __SULOG_GATE
    sulog_prctl_cmd(current_uid().val, arg2);
#endif

    if (!is_system_uid()) {
        return 0;
    }

#ifdef CONFIG_KSU_DEBUG
    pr_info("option: 0x%x, cmd: %ld\n", option, arg2);
#endif

#ifdef CONFIG_KSU_MANUAL_SU
    if (arg2 == CMD_MANUAL_SU_REQUEST) {
        struct manual_su_request request;
        int su_option = (int)arg3;
        
        if (copy_from_user(&request, (void __user *)arg4, sizeof(request))) {
            pr_err("manual_su: failed to copy request from user\n");
            return 0;
        }

        int ret = ksu_handle_manual_su_request(su_option, &request);

        // Copy back result for token generation
        if (ret == 0 && su_option == MANUAL_SU_OP_GENERATE_TOKEN) {
            if (copy_to_user((void __user *)arg4, &request, sizeof(request))) {
                pr_err("manual_su: failed to copy request back to user\n");
                return 0;
            }
        }
        
        if (ret == 0) {
            if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
                pr_err("manual_su: prctl reply error\n");
            }
        }
        return 0;
    }
#endif

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

static void do_umount_work(struct work_struct *work)
{
    struct ksu_umount_work *umount_work = container_of(work, struct ksu_umount_work, work);
    struct mnt_namespace *old_mnt_ns = current->nsproxy->mnt_ns;

    current->nsproxy->mnt_ns = umount_work->mnt_ns;

    try_umount("/odm", true, 0);
    try_umount("/system", true, 0);
    try_umount("/vendor", true, 0);
    try_umount("/product", true, 0);
    try_umount("/system_ext", true, 0);
    try_umount("/data/adb/modules", false, MNT_DETACH);

    // try umount ksu temp path
    try_umount("/debug_ramdisk", false, MNT_DETACH);

    // fixme: dec refcount
    current->nsproxy->mnt_ns = old_mnt_ns;

    kfree(umount_work);
}

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

    if (ksu_get_manager_uid() == new_uid.val) {
        pr_info("install fd for: %d\n", new_uid.val);

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
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
            spin_unlock_irq(&current->sighand->siglock);
        }
    }

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
    bool is_zygote_child = is_zygote(old->security);
    if (!is_zygote_child) {
        pr_info("handle umount ignore non zygote child: %d\n", current->pid);
        return 0;
    }
    
#if __SULOG_GATE
    ksu_sulog_report_syscall(new_uid.val, NULL, "setuid", NULL);
#endif

#ifdef CONFIG_KSU_DEBUG
    // umount the target mnt
    pr_info("handle umount for uid: %d, pid: %d\n", new_uid.val, current->pid);
#endif

    // fixme: use `collect_mounts` and `iterate_mount` to iterate all mountpoint and
    // filter the mountpoint whose target is `/data/adb`
    struct ksu_umount_work *umount_work = kmalloc(sizeof(struct ksu_umount_work), GFP_ATOMIC);
    if (!umount_work) {
        pr_err("Failed to allocate umount_work\n");
        return 0;
    }

    // fixme: inc refcount
    umount_work->mnt_ns = current->nsproxy->mnt_ns;

    INIT_WORK(&umount_work->work, do_umount_work);

    queue_work(ksu_workqueue, &umount_work->work);

    get_task_struct(current); // delay fix
    ksu_set_current_proc_umounted();
    put_task_struct(current);

    return 0;
}

extern void ksu_handle_reboot(int magic1, int magic2, void __user * arg); // supercalls.c

// Init functons - kprobe hooks

// 1. Reboot hook for installing fd
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int magic1 = (int)PT_REGS_PARM1(real_regs);
    int magic2 = (int)PT_REGS_PARM2(real_regs);
    unsigned long arg4;

    // Check if this is a request to install KSU fd
    arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
    ksu_handle_reboot(magic1, magic2, (void __user *) arg4);

    return 0;
}

static struct kprobe reboot_kp = {
    .symbol_name = REBOOT_SYMBOL,
    .pre_handler = reboot_handler_pre,
};

// 2. cap_task_fix_setuid hook for handling setuid
static int cap_task_fix_setuid_handler_pre(struct kprobe *p, struct pt_regs *regs)
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

// 3. prctl hook for handling ksu prctl commands
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

// 4.inode_permission hook for handling devpts
static int ksu_inode_permission_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct inode *inode = (struct inode *)PT_REGS_PARM1(regs);

    if (inode && inode->i_sb && unlikely(inode->i_sb->s_magic == DEVPTS_SUPER_MAGIC)) {
        // pr_info("%s: handling devpts for: %s \n", __func__, current->comm);
        __ksu_handle_devpts(inode);
    }

    return 0;
}

static struct kprobe ksu_inode_permission_kp = {
    .symbol_name = "security_inode_permission",
    .pre_handler = ksu_inode_permission_handler_pre,
};


// 5. bprm_check_security hook for handling ksud compatibility
static int ksu_bprm_check_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(regs);
    char *filename = (char *)bprm->filename;

    if (likely(!ksu_execveat_hook))
        return 0;

#ifdef CONFIG_COMPAT
    static bool compat_check_done __read_mostly = false;
    if (unlikely(!compat_check_done) && unlikely(!strcmp(filename, "/data/adb/ksud"))
        && !memcmp(bprm->buf, "\x7f\x45\x4c\x46", 4)) {
        if (bprm->buf[4] == 0x01)
            ksu_is_compat = true;

        pr_info("%s: %s ELF magic found! ksu_is_compat: %d \n", __func__, filename, ksu_is_compat);
        compat_check_done = true;
    }
#endif

    ksu_handle_pre_ksud(filename);

#ifdef CONFIG_KSU_MANUAL_SU
    ksu_try_escalate_for_uid(current_uid().val);
#endif

    return 0;
}

static struct kprobe ksu_bprm_check_kp = {
    .symbol_name = "security_bprm_check",
    .pre_handler = ksu_bprm_check_handler_pre,
};

#ifdef CONFIG_KSU_MANUAL_SU
// 6. task_alloc hook for handling manual su escalation
static int ksu_task_alloc_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(regs);

    ksu_try_escalate_for_uid(task_uid(task).val);
    return 0;
}

static struct kprobe ksu_task_alloc_kp = {
    .symbol_name = "security_task_alloc",
    .pre_handler = ksu_task_alloc_handler_pre,
};
#endif

__maybe_unused int ksu_kprobe_init(void)
{
    int rc = 0;

    // Register reboot kprobe
    rc = register_kprobe(&reboot_kp);
    if (rc) {
        pr_err("reboot kprobe failed: %d\n", rc);
    } else {
        pr_info("reboot kprobe registered successfully\n");
    }

    rc = register_kprobe(&cap_task_fix_setuid_kp);
    if (rc) {
        pr_err("cap_task_fix_setuid kprobe failed: %d\n", rc);
        unregister_kprobe(&reboot_kp);
    } else {
        pr_info("cap_task_fix_setuid_kp kprobe registered successfully\n");
    }
    

    // Register prctl kprobe
    rc = register_kprobe(&prctl_kp);
    if (rc) {
        pr_info("prctl kprobe failed: %d.\n", rc);
    } else {
        pr_info("prctl kprobe registered successfully.\n");
    }

    // Register inode_permission kprobe
    rc = register_kprobe(&ksu_inode_permission_kp);
    if (rc) {
        pr_err("inode_permission kprobe failed: %d\n", rc);
    } else {
        pr_info("inode_permission kprobe registered successfully\n");
    }

    // Register bprm_check_security kprobe
    rc = register_kprobe(&ksu_bprm_check_kp);
    if (rc) {
        pr_err("bprm_check_security kprobe failed: %d\n", rc);
    } else {
        pr_info("bprm_check_security kprobe registered successfully\n");
    }

#ifdef CONFIG_KSU_MANUAL_SU
    // Register task_alloc kprobe
    rc = register_kprobe(&ksu_task_alloc_kp);
    if (rc) {
        pr_err("task_alloc kprobe failed: %d\n", rc);
    } else {
        pr_info("task_alloc kprobe registered successfully\n");
    }
#endif

    return 0;
}

__maybe_unused int ksu_kprobe_exit(void)
{
    unregister_kprobe(&reboot_kp);
    unregister_kprobe(&cap_task_fix_setuid_kp);
    unregister_kprobe(&prctl_kp);
    unregister_kprobe(&ksu_inode_permission_kp);
    unregister_kprobe(&ksu_bprm_check_kp);
#ifdef CONFIG_KSU_MANUAL_SU
    unregister_kprobe(&ksu_task_alloc_kp);
#endif
    return 0;
}

void __init ksu_core_init(void)
{
    if (ksu_register_feature_handler(&kernel_umount_handler)) {
        pr_err("Failed to register kernel_umount feature handler\n");
    }

    ksu_workqueue = alloc_workqueue("ksu_umount", WQ_UNBOUND, 0);
    if (!ksu_workqueue) {
        pr_err("Failed to create ksu workqueue\n");
    }
#ifdef CONFIG_KPROBES
    int rc = ksu_kprobe_init();
    if (rc) {
        pr_err("ksu_kprobe_init failed: %d\n", rc);
    }
#endif
}

void ksu_core_exit(void)
{
    ksu_uid_exit();
    ksu_throne_comm_exit();
#if __SULOG_GATE
    ksu_sulog_exit();
#endif
#ifdef CONFIG_KPROBES
    pr_info("ksu_core_exit\n");
    ksu_kprobe_exit();
#endif
    if (ksu_workqueue) {
        flush_workqueue(ksu_workqueue);
        destroy_workqueue(ksu_workqueue);
    }
}
