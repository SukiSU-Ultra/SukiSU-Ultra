#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/seccomp.h>
#include <linux/thread_info.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include "objsec.h"

#include "allowlist.h"
#include "app_profile.h"
#include "klog.h" // IWYU pragma: keep
#include "selinux/selinux.h"
#ifndef CONFIG_KSU_SUSFS
#include "syscall_hook_manager.h"
#endif
#include "sucompat.h"
#include "sulog.h"

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

void disable_seccomp(void)
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
	atomic_set(&current->seccomp.filter_count, 0);
#else
#endif
}

void escape_with_root_profile(void)
{
    struct cred *cred;
#ifndef CONFIG_KSU_SUSFS
    struct task_struct *p = current;
    struct task_struct *t;
#endif

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

#ifndef CONFIG_KSU_SUSFS
    for_each_thread (p, t) {
        ksu_set_task_tracepoint_flag(t);
    }
#endif
}

#ifdef CONFIG_KSU_MANUAL_SU

#include "ksud.h"

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC    0x1cd1
#endif

static int __manual_su_handle_devpts(struct inode *inode)
{
    if (!current->mm) {
        return 0;
    }

    uid_t uid = current_uid().val;
    if (uid % 100000 < 10000) {
        // not untrusted_app, ignore it
        return 0;
    }

    if (likely(!ksu_is_allow_uid_for_current(uid)))
        return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) || defined(KSU_OPTIONAL_SELINUX_INODE)
        struct inode_security_struct *sec = selinux_inode(inode);
#else
        struct inode_security_struct *sec =
            (struct inode_security_struct *)inode->i_security;
#endif
    if (ksu_file_sid && sec)
        sec->sid = ksu_file_sid;

    return 0;
}

static void disable_seccomp_for_task(struct task_struct *tsk)
{
    assert_spin_locked(&tsk->sighand->siglock);
#ifdef CONFIG_SECCOMP
    if (tsk->seccomp.mode == SECCOMP_MODE_DISABLED && !tsk->seccomp.filter)
        return;
#endif
    clear_tsk_thread_flag(tsk, TIF_SECCOMP);
#ifdef CONFIG_SECCOMP
    tsk->seccomp.mode = SECCOMP_MODE_DISABLED;
    if (tsk->seccomp.filter) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        seccomp_filter_release(tsk);
#else
        put_seccomp_filter(tsk);
        tsk->seccomp.filter = NULL;
#endif
    }
#endif
}

void escape_to_root_for_cmd_su(uid_t target_uid, pid_t target_pid)
{
    struct cred *newcreds;
    struct task_struct *target_task;
#ifndef CONFIG_KSU_SUSFS
    struct task_struct *p = current;
    struct task_struct *t;
#endif

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
        spin_lock_irqsave(&target_task->sighand->siglock, flags);
        disable_seccomp_for_task(target_task);
        spin_unlock_irqrestore(&target_task->sighand->siglock, flags);
    }

    setup_selinux(profile->selinux_domain);
    put_cred(old_creds);
    wake_up_process(target_task);

    if (target_task->signal->tty) {
        struct inode *inode = target_task->signal->tty->driver_data;
        if (inode && inode->i_sb->s_magic == DEVPTS_SUPER_MAGIC) {
            __manual_su_handle_devpts(inode);
        }
    }

    put_task_struct(target_task);
#if __SULOG_GATE
    ksu_sulog_report_su_grant(target_uid, "cmd_su", "manual_escalation");
#endif
#ifndef CONFIG_KSU_SUSFS
    for_each_thread (p, t) {
        ksu_set_task_tracepoint_flag(t);
    }
#endif
    pr_info("cmd_su: privilege escalation completed for UID: %d, PID: %d\n", target_uid, target_pid);
}
#endif
