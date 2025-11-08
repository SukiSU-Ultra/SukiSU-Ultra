#include <linux/compiler.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kallsyms.h>
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
#include <linux/lsm_hooks.h>
#include <linux/binfmts.h>
#include <linux/tty.h>

#ifndef KSU_HAS_PATH_UMOUNT
#include <linux/syscalls.h> // sys_umount (<4.17) & ksys_umount (4.17+)
#endif

#ifdef MODULE
#include <linux/list.h>
#include <linux/irqflags.h>
#include <linux/mm_types.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>
#endif

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#include <linux/susfs_def.h>
#endif // #ifdef CONFIG_KSU_SUSFS

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
#include "sucompat.h"
#include "sulog.h"


#ifdef CONFIG_KSU_SUSFS
bool susfs_is_boot_completed_triggered = false;
extern u32 susfs_zygote_sid;
extern bool susfs_is_mnt_devname_ksu(struct path *path);
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
extern void susfs_run_sus_path_loop(uid_t uid);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
extern bool susfs_is_log_enabled __read_mostly;
#endif // #ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
static bool susfs_is_umount_for_zygote_system_process_enabled = false;
static bool susfs_is_umount_for_zygote_iso_service_enabled = false;
extern bool susfs_hide_sus_mnts_for_all_procs;
extern void susfs_reorder_mnt_id(void);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
extern bool susfs_is_auto_add_sus_bind_mount_enabled;
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
extern bool susfs_is_auto_add_sus_ksu_default_mount_enabled;
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
extern bool susfs_is_auto_add_try_umount_for_bind_mount_enabled;
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_SU
extern bool susfs_is_sus_su_ready;
extern int susfs_sus_su_working_mode;
extern bool susfs_is_sus_su_hooks_enabled __read_mostly;
extern bool ksu_devpts_hook;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_SU

static inline void susfs_on_post_fs_data(void) {
    struct path path;
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    if (!kern_path(DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS, 0, &path)) {
        susfs_is_umount_for_zygote_system_process_enabled = true;
        path_put(&path);
    }
    pr_info("susfs_is_umount_for_zygote_system_process_enabled: %d\n", susfs_is_umount_for_zygote_system_process_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
    if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT, 0, &path)) {
        susfs_is_auto_add_sus_bind_mount_enabled = false;
        path_put(&path);
    }
    pr_info("susfs_is_auto_add_sus_bind_mount_enabled: %d\n", susfs_is_auto_add_sus_bind_mount_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
    if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT, 0, &path)) {
        susfs_is_auto_add_sus_ksu_default_mount_enabled = false;
        path_put(&path);
    }
    pr_info("susfs_is_auto_add_sus_ksu_default_mount_enabled: %d\n", susfs_is_auto_add_sus_ksu_default_mount_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
    if (!kern_path(DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT, 0, &path)) {
        susfs_is_auto_add_try_umount_for_bind_mount_enabled = false;
        path_put(&path);
    }
    pr_info("susfs_is_auto_add_try_umount_for_bind_mount_enabled: %d\n", susfs_is_auto_add_try_umount_for_bind_mount_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
}

static inline bool is_some_system_uid(uid_t uid)
{
    return (uid >= 1000 && uid < 10000);
}

static inline bool is_zygote_isolated_service_uid(uid_t uid)
{
    return ((uid >= 90000 && uid < 100000) || (uid >= 1090000 && uid < 1100000));
}

static inline bool is_zygote_normal_app_uid(uid_t uid)
{
    return ((uid >= 10000 && uid < 19999) || (uid >= 1010000 && uid < 1019999));
}

#endif // #ifdef CONFIG_KSU_SUSFS

bool ksu_module_mounted __read_mostly = false;

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

static bool ksu_kernel_umount_enabled = true;
static bool ksu_enhanced_security_enabled = false;

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

static int enhanced_security_feature_get(u64 *value)
{
    *value = ksu_enhanced_security_enabled ? 1 : 0;
    return 0;
}

static int enhanced_security_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_enhanced_security_enabled = enable;
    pr_info("enhanced_security: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler enhanced_security_handler = {
    .feature_id = KSU_FEATURE_ENHANCED_SECURITY,
    .name = "enhanced_security",
    .get_handler = enhanced_security_feature_get,
    .set_handler = enhanced_security_feature_set,
};

static inline bool is_allow_su(void)
{
    if (is_manager()) {
        // we are manager, allow!
        return true;
    }
    return ksu_is_allow_uid_for_current(current_uid().val);
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
    struct task_struct *p = current;
    struct task_struct *t;

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

    for_each_thread (p, t) {
        ksu_set_task_tracepoint_flag(t);
    }
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
    struct task_struct *p = current;
    struct task_struct *t;

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
    for_each_thread (p, t) {
        ksu_set_task_tracepoint_flag(t);
    }
    pr_info("cmd_su: privilege escalation completed for UID: %d, PID: %d\n", target_uid, target_pid);
}
#endif

void nuke_ext4_sysfs(void) 
{
#ifdef CONFIG_EXT4_FS
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
        path_put(&path);
        return;
    }

    ext4_unregister_sysfs(sb);
     path_put(&path);
#endif
}

static bool is_system_bin_su()
{
    if (!current->mm || current->in_execve) {
        return 0;
    }

    // quick af check
    return (current->mm->exe_file && !strcmp(current->mm->exe_file->f_path.dentry->d_name.name, "su"));
}

#ifdef CONFIG_KSU_MANUAL_SU
static bool is_system_uid(void)
{
    if (!current->mm || current->in_execve) {
        return 0;
    }
    
    uid_t caller_uid = current_uid().val;
    return caller_uid <= 2000;
}
#endif

#if __SULOG_GATE
static void sulog_prctl_cmd(uid_t uid, unsigned long cmd)
{
    const char *name = NULL;

    switch (cmd) {

#ifdef CONFIG_KSU_SUSFS
    case CMD_SUSFS_ADD_SUS_PATH:            name = "prctl_susfs_add_sus_path"; break;
    case CMD_SUSFS_ADD_SUS_PATH_LOOP:       name = "prctl_susfs_add_sus_path_loop"; break;
    case CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH: name = "prctl_susfs_set_android_data_root_path"; break;
    case CMD_SUSFS_SET_SDCARD_ROOT_PATH:    name = "prctl_susfs_set_sdcard_root_path"; break;
    case CMD_SUSFS_ADD_SUS_MOUNT:           name = "prctl_susfs_add_sus_mount"; break;
    case CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS: name = "prctl_susfs_hide_sus_mnts_for_all_procs"; break;
    case CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE: name = "prctl_susfs_umount_for_zygote_iso_service"; break;
    case CMD_SUSFS_ADD_SUS_KSTAT:           name = "prctl_susfs_add_sus_kstat"; break;
    case CMD_SUSFS_UPDATE_SUS_KSTAT:        name = "prctl_susfs_update_sus_kstat"; break;
    case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY: name = "prctl_susfs_add_sus_kstat_statically"; break;
    case CMD_SUSFS_ADD_TRY_UMOUNT:          name = "prctl_susfs_add_try_umount"; break;
    case CMD_SUSFS_SET_UNAME:               name = "prctl_susfs_set_uname"; break;
    case CMD_SUSFS_ENABLE_LOG:              name = "prctl_susfs_enable_log"; break;
    case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG: name = "prctl_susfs_set_cmdline_or_bootconfig"; break;
    case CMD_SUSFS_ADD_OPEN_REDIRECT:       name = "prctl_susfs_add_open_redirect"; break;
    case CMD_SUSFS_SHOW_VERSION:            name = "prctl_susfs_show_version"; break;
    case CMD_SUSFS_SHOW_ENABLED_FEATURES:   name = "prctl_susfs_show_enabled_features"; break;
    case CMD_SUSFS_SHOW_VARIANT:            name = "prctl_susfs_show_variant"; break;
#ifdef CONFIG_KSU_SUSFS_SUS_SU
    case CMD_SUSFS_SUS_SU:                  name = "prctl_susfs_sus_su"; break;
    case CMD_SUSFS_IS_SUS_SU_READY:         name = "prctl_susfs_is_sus_su_ready"; break;
    case CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE: name = "prctl_susfs_show_sus_su_working_mode"; break;
#endif
    case CMD_SUSFS_ADD_SUS_MAP:             name = "prctl_susfs_add_sus_map"; break;
    case CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING: name = "prctl_susfs_enable_avc_log_spoofing"; break;
#endif

    default:                                name = "prctl_unknown"; break;
    }

    ksu_sulog_report_syscall(uid, NULL, name, NULL);
}
#endif

int ksu_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
             unsigned long arg4, unsigned long arg5)
{


#ifdef CONFIG_KSU_SUSFS
    // - We straight up check if process is supposed to be umounted, return 0 if so
    // - This is to prevent side channel attack as much as possible
    if (likely(susfs_is_current_proc_umounted()))
        return 0;
#endif

    // if success, we modify the arg5 as result!
    u32 *result = (u32 *)arg5;
    u32 reply_ok = KERNEL_SU_OPTION;

    if (KERNEL_SU_OPTION != option) {
        return 0;
    }

    bool from_root = 0 == current_uid().val;
    bool from_manager = is_manager();
    
#if __SULOG_GATE
    sulog_prctl_cmd(current_uid().val, arg2);
#endif

    if (!from_root && !from_manager && !is_allow_su()) {
        // only root or manager can access this interface
        return 0;
    }

#ifdef CONFIG_KSU_DEBUG
    pr_info("option: 0x%x, cmd: %ld\n", option, arg2);
#endif

#ifdef CONFIG_KSU_SUSFS
    int susfs_cmd_err = 0;
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
    if (arg2 == CMD_SUSFS_ADD_SUS_PATH) {
        susfs_cmd_err = susfs_add_sus_path((struct st_susfs_sus_path __user*)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_SUS_PATH -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_ADD_SUS_PATH_LOOP) {
        susfs_cmd_err = susfs_add_sus_path_loop((struct st_susfs_sus_path __user*)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_SUS_PATH_LOOP -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH) {
        susfs_cmd_err = susfs_set_i_state_on_external_dir((char __user*)arg3, CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH);
        pr_info("susfs: CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_SET_SDCARD_ROOT_PATH) {
        susfs_cmd_err = susfs_set_i_state_on_external_dir((char __user*)arg3, CMD_SUSFS_SET_SDCARD_ROOT_PATH);
        pr_info("susfs: CMD_SUSFS_SET_SDCARD_ROOT_PATH -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    if (arg2 == CMD_SUSFS_ADD_SUS_MOUNT) {
        susfs_cmd_err = susfs_add_sus_mount((struct st_susfs_sus_mount __user*)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS) {
        if (arg3 != 0 && arg3 != 1) {
            pr_err("susfs: CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS -> arg3 can only be 0 or 1\n");
            return 0;
        }
        susfs_hide_sus_mnts_for_all_procs = arg3;
        pr_info("susfs: CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS -> susfs_hide_sus_mnts_for_all_procs: %lu\n", arg3);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE) {
        if (arg3 != 0 && arg3 != 1) {
            pr_err("susfs: CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE -> arg3 can only be 0 or 1\n");
            return 0;
        }
        susfs_is_umount_for_zygote_iso_service_enabled = arg3;
        pr_info("susfs: CMD_SUSFS_UMOUNT_FOR_ZYGOTE_ISO_SERVICE -> susfs_is_umount_for_zygote_iso_service_enabled: %lu\n", arg3);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
    if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT) {
        susfs_cmd_err = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user*)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_UPDATE_SUS_KSTAT) {
        susfs_cmd_err = susfs_update_sus_kstat((struct st_susfs_sus_kstat __user*)arg3);
        pr_info("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
        susfs_cmd_err = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user*)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
    if (arg2 == CMD_SUSFS_ADD_TRY_UMOUNT) {
        susfs_cmd_err = susfs_add_try_umount((struct st_susfs_try_umount __user*)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif //#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
    if (arg2 == CMD_SUSFS_SET_UNAME) {
        susfs_cmd_err = susfs_set_uname((struct st_susfs_uname __user*)arg3);
        pr_info("susfs: CMD_SUSFS_SET_UNAME -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
    if (arg2 == CMD_SUSFS_ENABLE_LOG) {
        if (arg3 != 0 && arg3 != 1) {
            pr_err("susfs: CMD_SUSFS_ENABLE_LOG -> arg3 can only be 0 or 1\n");
            return 0;
        }
        susfs_set_log(arg3);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif //#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
    if (arg2 == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
        susfs_cmd_err = susfs_set_cmdline_or_bootconfig((char __user*)arg3);
        pr_info("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
    if (arg2 == CMD_SUSFS_ADD_OPEN_REDIRECT) {
        susfs_cmd_err = susfs_add_open_redirect((struct st_susfs_open_redirect __user*)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif //#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
#ifdef CONFIG_KSU_SUSFS_SUS_SU
    if (arg2 == CMD_SUSFS_SUS_SU) {
        susfs_cmd_err = susfs_sus_su((struct st_sus_su __user*)arg3);
        pr_info("susfs: CMD_SUSFS_SUS_SU -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_SU
    if (arg2 == CMD_SUSFS_SHOW_VERSION) {
        int len_of_susfs_version = strlen(SUSFS_VERSION);
        char *susfs_version = SUSFS_VERSION;

        susfs_cmd_err = copy_to_user((void __user*)arg3, (void*)susfs_version, len_of_susfs_version+1);
        pr_info("susfs: CMD_SUSFS_SHOW_VERSION -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
        if (arg4 <= 0) {
            pr_err("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> arg4 cannot be <= 0\n");
            return 0;
        }
        susfs_cmd_err = susfs_get_enabled_features((char __user*)arg3, arg4);
        pr_info("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_SHOW_VARIANT) {
        int len_of_variant = strlen(SUSFS_VARIANT);
        char *susfs_variant = SUSFS_VARIANT;

        susfs_cmd_err = copy_to_user((void __user*)arg3, (void*)susfs_variant, len_of_variant+1);
        pr_info("susfs: CMD_SUSFS_SHOW_VARIANT -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#ifdef CONFIG_KSU_SUSFS_SUS_SU
    if (arg2 == CMD_SUSFS_IS_SUS_SU_READY) {
        susfs_cmd_err = copy_to_user((void __user*)arg3, (void*)&susfs_is_sus_su_ready, sizeof(susfs_is_sus_su_ready));
        pr_info("susfs: CMD_SUSFS_IS_SUS_SU_READY -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE) {
        int working_mode = susfs_get_sus_su_working_mode();

        susfs_cmd_err = copy_to_user((void __user*)arg3, (void*)&working_mode, sizeof(working_mode));
        pr_info("susfs: CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_SU
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
    if (arg2 == CMD_SUSFS_ADD_SUS_MAP) {
        susfs_cmd_err = susfs_add_sus_map((struct st_susfs_sus_map __user*)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_SUS_MAP -> ret: %d\n", susfs_cmd_err);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
                pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP
    if (arg2 == CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING) {
        if (arg3 != 0 && arg3 != 1) {
            pr_err("susfs: CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING -> arg3 can only be 0 or 1\n");
            return 0;
        }
        susfs_set_avc_log_spoofing(arg3);
        if (copy_to_user((void __user*)arg5, &susfs_cmd_err, sizeof(susfs_cmd_err)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif //#ifdef CONFIG_KSU_SUSFS

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

#ifdef CONFIG_KSU_SUSFS
    return susfs_is_mnt_devname_ksu(path);
#else
    if (path->mnt && path->mnt->mnt_sb && path->mnt->mnt_sb->s_type) {
        const char *fstype = path->mnt->mnt_sb->s_type->name;
        return strcmp(fstype, "overlay") == 0;
    }
    return false;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) || defined(KSU_HAS_PATH_UMOUNT)
static int ksu_path_umount(struct path *path, int flags)
{
    return path_umount(path, flags);
}
#define ksu_umount_mnt(__unused, path, flags)    (ksu_path_umount(path, flags))
#else
// TODO: Search a way to make this works without set_fs functions
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
    pr_info("%s was called, ret: %d\n", __func__, ret);
    return ret;
}

#define ksu_umount_mnt(mnt, __unused, flags)        \
    ({                        \
        int ret;                \
        path_put(__unused);            \
        ret = ksu_sys_umount(mnt, flags);    \
        ret;                    \
    })

#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
void try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid)
#else
static void try_umount(const char *mnt, bool check_mnt, int flags)
#endif
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

#if defined(CONFIG_KSU_SUSFS_TRY_UMOUNT) && defined(CONFIG_KSU_SUSFS_ENABLE_LOG)
    if (susfs_is_log_enabled) {
        pr_info("susfs: umounting '%s' for uid: %d\n", mnt, uid);
    }
#endif

    ret = ksu_umount_mnt(mnt, &path, flags);
    if (ret) {
#ifdef CONFIG_KSU_DEBUG
        pr_info("%s: path: %s, ret: %d\n", __func__, mnt, ret);
#endif
    }
}

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
void susfs_try_umount_all(uid_t uid) {
    susfs_try_umount(uid);
    /* For Legacy KSU only */
    try_umount("/odm", true, 0, uid);
    try_umount("/system", true, 0, uid);
    try_umount("/vendor", true, 0, uid);
    try_umount("/product", true, 0, uid);
    try_umount("/system_ext", true, 0, uid);
    // - For '/data/adb/modules' we pass 'false' here because it is a loop device that we can't determine whether 
    //   its dev_name is KSU or not, and it is safe to just umount it if it is really a mountpoint
    try_umount("/data/adb/modules", false, MNT_DETACH, uid);
    try_umount("/data/adb/kpm", false, MNT_DETACH, uid);
    /* For both Legacy KSU and Magic Mount KSU */
    try_umount("/debug_ramdisk", true, MNT_DETACH, uid);
    try_umount("/sbin", false, MNT_DETACH, uid);
    
    // try umount hosts file
    try_umount("/system/etc/hosts", false, MNT_DETACH, uid);

    // try umount lsposed dex2oat bins
    try_umount("/apex/com.android.art/bin/dex2oat64", false, MNT_DETACH, uid);
    try_umount("/apex/com.android.art/bin/dex2oat32", false, MNT_DETACH, uid);
}
#endif

struct umount_tw {
    struct callback_head cb;
    const struct cred *old_cred;
};

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
static void umount_tw_func(struct callback_head *cb)
{
    struct umount_tw *tw = container_of(cb, struct umount_tw, cb);
    const struct cred *saved = NULL;
    if (tw->old_cred) {
        saved = override_creds(tw->old_cred);
    }

    uid_t uid = current_uid().val;


    // fixme: use `collect_mounts` and `iterate_mount` to iterate all mountpoint and
    // filter the mountpoint whose target is `/data/adb`
    try_umount("/odm", true, 0, uid);
    try_umount("/system", true, 0, uid);
    try_umount("/vendor", true, 0, uid);
    try_umount("/product", true, 0, uid);
    try_umount("/system_ext", true, 0, uid);
    try_umount("/data/adb/modules", false, MNT_DETACH, uid);
    try_umount("/data/adb/kpm", false, MNT_DETACH, uid);

    // try umount ksu temp path
    try_umount("/debug_ramdisk", false, MNT_DETACH, uid);
    try_umount("/sbin", false, MNT_DETACH, uid);

    // try umount lsposed dex2oat bins
    try_umount("/system/etc/hosts", false, MNT_DETACH, uid);

    // try umount lsposed dex2oat bins
    try_umount("/apex/com.android.art/bin/dex2oat64", false, MNT_DETACH, uid);
    try_umount("/apex/com.android.art/bin/dex2oat32", false, MNT_DETACH, uid);

    if (saved)
        revert_creds(saved);

    if (tw->old_cred)
        put_cred(tw->old_cred);

    kfree(tw);
}
#else
static void umount_tw_func(struct callback_head *cb)
{
    struct umount_tw *tw = container_of(cb, struct umount_tw, cb);
    const struct cred *saved = NULL;
    if (tw->old_cred) {
        saved = override_creds(tw->old_cred);
    }

    // fixme: use `collect_mounts` and `iterate_mount` to iterate all mountpoint and
    // filter the mountpoint whose target is `/data/adb`
    try_umount("/odm", true, 0);
    try_umount("/system", true, 0);
    try_umount("/vendor", true, 0);
    try_umount("/product", true, 0);
    try_umount("/system_ext", true, 0);
    try_umount("/data/adb/modules", false, MNT_DETACH);
    try_umount("/data/adb/kpm", false, MNT_DETACH);
    // try umount ksu temp path
    try_umount("/debug_ramdisk", false, MNT_DETACH);
    try_umount("/sbin", false, MNT_DETACH);

    try_umount("/system/etc/hosts", false, MNT_DETACH);
    // try umount lsposed dex2oat bins
    try_umount("/apex/com.android.art/bin/dex2oat64", false, MNT_DETACH);
    try_umount("/apex/com.android.art/bin/dex2oat32", false, MNT_DETACH);

    if (saved)
        revert_creds(saved);

    if (tw->old_cred)
        put_cred(tw->old_cred);

    kfree(tw);
}
#endif

#ifdef CONFIG_KSU_SUSFS
int ksu_handle_setuid(struct cred *new, const struct cred *old)
{
    __maybe_unused struct umount_tw *tw;
    if (!new || !old) {
        return 0;
    }

    kuid_t new_uid = new->uid;
    kuid_t old_uid = old->uid;

    if (0 != old_uid.val) {
        // old process is not root, ignore it.
        if (ksu_enhanced_security_enabled) {
            // disallow any non-ksu domain escalation from non-root to root!
            if (unlikely(new_uid.val) == 0) {
                if (!is_ksu_domain()) {
                    pr_warn("find suspicious EoP: %d %s, from %d to %d\n", 
                        current->pid, current->comm, old_uid.val, new_uid.val);
                    force_sig(SIGKILL);
                    return 0;
                }
            }
            // disallow appuid decrease to any other uid if it is allowed to su
            if (is_appuid(old_uid)) {
                if (new_uid.val < old_uid.val && !ksu_is_allow_uid_for_current(old_uid.val)) {
                    pr_warn("find suspicious EoP: %d %s, from %d to %d\n", 
                        current->pid, current->comm, old_uid.val, new_uid.val);
                    force_sig(SIGKILL);
                    return 0;
                }
            }
        }
        return 0;
    }

    if (new_uid.val == 2000) {
        if (ksu_su_compat_enabled) {
            ksu_set_task_tracepoint_flag(current);
        }
    }

    // if on private space, see if its possibly the manager
    if (unlikely(new_uid.val > 100000 && new_uid.val % 100000 == ksu_get_manager_uid())) {
        ksu_set_manager_uid(new_uid.val);
    }

    if (unlikely(ksu_get_manager_uid() == new_uid.val)) {
        pr_info("install fd for: %d\n", new_uid.val);

        ksu_install_fd();
        spin_lock_irq(&current->sighand->siglock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 2) // Android backport this feature in 5.10.2
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
#else
        // we dont have those new fancy things upstream has
	    // lets just do original thing where we disable seccomp
        disable_seccomp();
#endif
        if (ksu_su_compat_enabled) {
            ksu_set_task_tracepoint_flag(current);
        }
        spin_unlock_irq(&current->sighand->siglock);
        return 0;
    }

    if (unlikely(ksu_is_allow_uid_for_current(new_uid.val))) {
        if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
            current->seccomp.filter) {
            spin_lock_irq(&current->sighand->siglock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 2) // Android backport this feature in 5.10.2
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
#else
            // we don't have those new fancy things upstream has
            // lets just do original thing where we disable seccomp
            disable_seccomp();
#endif
            spin_unlock_irq(&current->sighand->siglock);
        }
        if (ksu_su_compat_enabled) {
            ksu_set_task_tracepoint_flag(current);
        }
    } else {
        // Disable syscall tracepoint sucompat for non-allowed processes
        if (ksu_su_compat_enabled) {
            ksu_clear_task_tracepoint_flag(current);
        }
    }

    // this hook is used for umounting overlayfs for some uid, if there isn't any module mounted, just ignore it!
    if (!ksu_module_mounted) {
        return 0;
    }

    if (!ksu_kernel_umount_enabled) {
        return 0;
    }

    // We only interest in process spwaned by zygote
    if (!susfs_is_sid_equal(old->security, susfs_zygote_sid)) {
        return 0;
    }

    // Check if spawned process is isolated service first, and force to do umount if so  
    if (is_zygote_isolated_service_uid(new_uid.val) && susfs_is_umount_for_zygote_iso_service_enabled) {
        goto do_umount;
    }

    // - Since ksu maanger app uid is excluded in allow_list_arr, so ksu_uid_should_umount(manager_uid)
    //   will always return true, that's why we need to explicitly check if new_uid.val belongs to
    //   ksu manager
    if (ksu_is_manager_uid_valid() &&
        (new_uid.val % 1000000 == ksu_get_manager_uid())) // % 1000000 in case it is private space uid
    {
        return 0;
    }

    // Check if spawned process is normal user app and needs to be umounted
    if (likely(is_zygote_normal_app_uid(new_uid.val) && ksu_uid_should_umount(new_uid.val))) {
        goto do_umount;
    }

    // Lastly, Check if spawned process is some system process and needs to be umounted
    if (unlikely(is_some_system_uid(new_uid.val) && susfs_is_umount_for_zygote_system_process_enabled)) {
        goto do_umount;
    }
#if __SULOG_GATE
    ksu_sulog_report_syscall(new_uid.val, NULL, "setuid", NULL);
#endif

    return 0;

do_umount:
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
    // susfs come first, and lastly umount by ksu, make sure umount in reversed order
    susfs_try_umount_all(new_uid.val);
#else
    tw = kmalloc(sizeof(*tw), GFP_ATOMIC);
    if (!tw)
        return 0;

    tw->old_cred = get_current_cred();
    tw->cb.func = umount_tw_func;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
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

#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT

    get_task_struct(current);

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    // We can reorder the mnt_id now after all sus mounts are umounted
    susfs_reorder_mnt_id();
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

    susfs_set_current_proc_umounted();

    put_task_struct(current);

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
    susfs_run_sus_path_loop(new_uid.val);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH
    return 0;
}

#else
int ksu_handle_setuid(struct cred *new, const struct cred *old)
{
    __maybe_unused struct umount_tw *tw;
    if (!new || !old) {
        return 0;
    }

    kuid_t new_uid = new->uid;
    kuid_t old_uid = old->uid;

    if (0 != old_uid.val) {
        // old process is not root, ignore it.
        if (ksu_enhanced_security_enabled) {
            // disallow any non-ksu domain escalation from non-root to root!
            if (unlikely(new_uid.val) == 0) {
                if (!is_ksu_domain()) {
                    pr_warn("find suspicious EoP: %d %s, from %d to %d\n", 
                        current->pid, current->comm, old_uid.val, new_uid.val);
                    force_sig(SIGKILL);
                    return 0;
                }
            }
            // disallow appuid decrease to any other uid if it is allowed to su
            if (is_appuid(old_uid)) {
                if (new_uid.val < old_uid.val && !ksu_is_allow_uid_for_current(old_uid.val)) {
                    pr_warn("find suspicious EoP: %d %s, from %d to %d\n", 
                        current->pid, current->comm, old_uid.val, new_uid.val);
                    force_sig(SIGKILL);
                    return 0;
                }
            }
        }
        return 0;
    }

    if (new_uid.val == 2000) {
        if (ksu_su_compat_enabled) {
            ksu_set_task_tracepoint_flag(current);
        }
    }

    if (!is_appuid(new_uid) || is_unsupported_uid(new_uid.val)) {
        // pr_info("handle setuid ignore non application or isolated uid: %d\n", new_uid.val);
        return 0;
    }

    // if on private space, see if its possibly the manager
    if (unlikely(new_uid.val > 100000 && new_uid.val % 100000 == ksu_get_manager_uid())) {
        ksu_set_manager_uid(new_uid.val);
    }

    if (unlikely(ksu_get_manager_uid() == new_uid.val)) {
        pr_info("install fd for: %d\n", new_uid.val);

        ksu_install_fd();
        spin_lock_irq(&current->sighand->siglock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 2) // Android backport this feature in 5.10.2
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
#else
        // we dont have those new fancy things upstream has
	    // lets just do original thing where we disable seccomp
        disable_seccomp();
#endif
        if (ksu_su_compat_enabled) {
            ksu_set_task_tracepoint_flag(current);
        }
        spin_unlock_irq(&current->sighand->siglock);
        return 0;
    }

    if (unlikely(ksu_is_allow_uid_for_current(new_uid.val))) {
        if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
            current->seccomp.filter) {
            spin_lock_irq(&current->sighand->siglock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 2) // Android backport this feature in 5.10.2
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
#else
            // we don't have those new fancy things upstream has
            // lets just do original thing where we disable seccomp
            disable_seccomp();
#endif
            spin_unlock_irq(&current->sighand->siglock);
        }
        if (ksu_su_compat_enabled) {
            ksu_set_task_tracepoint_flag(current);
        }
    } else {
        // Disable syscall tracepoint sucompat for non-allowed processes
        if (ksu_su_compat_enabled) {
            ksu_clear_task_tracepoint_flag(current);
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
    bool is_zygote_child = is_zygote(old);
    if (!is_zygote_child) {
        pr_info("handle umount ignore non zygote child: %d\n",
            current->pid);
        return 0;
    }
#if __SULOG_GATE
    ksu_sulog_report_syscall(new_uid.val, NULL, "setuid", NULL);
#endif
#ifdef CONFIG_KSU_DEBUG
    // umount the target mnt
    pr_info("handle umount for uid: %d, pid: %d\n", new_uid.val,
        current->pid);
#endif

    tw = kmalloc(sizeof(*tw), GFP_ATOMIC);
    if (!tw)
        return 0;

    tw->old_cred = get_current_cred();
    tw->cb.func = umount_tw_func;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
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

    return 0;
}

#endif // #ifdef CONFIG_KSU_SUSFS

// downstream: make sure to pass arg as reference, this can allow us to extend things.
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{

    if (magic1 != KSU_INSTALL_MAGIC1)
        return 0;

#ifdef CONFIG_KSU_DEBUG
    pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1, magic2);
#endif

    // Check if this is a request to install KSU fd
    if (magic2 == KSU_INSTALL_MAGIC2) {
        int fd = ksu_install_fd();
        pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

        // downstream: dereference all arg usage!
        if (copy_to_user((void __user *)*arg, &fd, sizeof(fd))) {
            pr_err("install ksu fd reply err\n");
        }

        return 0;
    }

    // extensions

    return 0;
}

// Init functons - kprobe hooks

// 1. Reboot hook for installing fd
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

static int ksu_task_prctl(int option, unsigned long arg2, unsigned long arg3,
              unsigned long arg4, unsigned long arg5)
{
    ksu_handle_prctl(option, arg2, arg3, arg4, arg5);
    return -ENOSYS;
}
// kernel 4.4 and 4.9
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||    \
    defined(CONFIG_IS_HW_HISI) ||    \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
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

#ifdef CONFIG_KSU_MANUAL_SU
    ksu_try_escalate_for_uid(current_uid().val);
#endif

    return 0;

}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0) && defined(CONFIG_KSU_MANUAL_SU)
static int ksu_task_alloc(struct task_struct *task,
                          unsigned long clone_flags)
{
    ksu_try_escalate_for_uid(task_uid(task).val);
    return 0;
}
#endif

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
                   int flags)
{
    return ksu_handle_setuid(new, old);
}

#ifndef MODULE
static struct security_hook_list ksu_hooks[] = {
    LSM_HOOK_INIT(task_prctl, ksu_task_prctl),
    LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
    LSM_HOOK_INIT(inode_permission, ksu_inode_permission),
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0) && defined(CONFIG_KSU_MANUAL_SU)
    LSM_HOOK_INIT(task_alloc, ksu_task_alloc),
#endif
#ifndef KSU_KPROBES_HOOK
    LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || \
    defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
    LSM_HOOK_INIT(key_permission, ksu_key_permission)
#endif
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
const struct lsm_id ksu_lsmid = {
    .name = "ksu",
    .id = 912,
};
#endif

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
    // https://elixir.bootlin.com/linux/v6.8/source/include/linux/lsm_hooks.h#L120
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), &ksu_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
    // https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
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

    return 0;
}

__maybe_unused int ksu_kprobe_exit(void)
{
    unregister_kprobe(&reboot_kp);
    return 0;
}

void __init ksu_core_init(void)
{
    ksu_lsm_hook_init();
#ifdef KSU_KPROBES_HOOK
    int rc = ksu_kprobe_init();
    if (rc) {
        pr_err("ksu_kprobe_init failed: %d\n", rc);
    }
#endif
    if (ksu_register_feature_handler(&kernel_umount_handler)) {
        pr_err("Failed to register umount feature handler\n");
    }
    if (ksu_register_feature_handler(&enhanced_security_handler)) {
        pr_err("Failed to register enhanced security feature handler\n");
    }
}

void ksu_core_exit(void)
{
    ksu_uid_exit();
    ksu_throne_comm_exit();
#if __SULOG_GATE
    ksu_sulog_exit();
#endif
    
#ifdef KSU_KPROBES_HOOK
    pr_info("ksu_core_kprobe_exit\n");
    ksu_kprobe_exit();
#endif
    ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
    ksu_unregister_feature_handler(KSU_FEATURE_ENHANCED_SECURITY);
}
