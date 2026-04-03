#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/binfmts.h>
#include <linux/rcupdate.h>
#include <linux/capability.h>
#include <linux/sched/user.h>
#include <linux/sched/signal.h>
#include <linux/seccomp.h>
#include <linux/thread_info.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/tty.h>

#include "other/manual_su.h"
#include "ksu.h"
#include "policy/allowlist.h"
#include "manager/manager_observer.h"
#include "manager/manager_identity.h"
#include "policy/app_profile.h"
#include "selinux/selinux.h"
#include "infra/su_mount_ns.h"
#include "hook/tp_marker.h"

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC 0x1cd1
#endif

static bool current_verified = false;
static DEFINE_SPINLOCK(verified_lock);

static LIST_HEAD(token_list);
static DEFINE_SPINLOCK(token_lock);
static u32 token_count = 0;

static LIST_HEAD(pending_list);
static DEFINE_SPINLOCK(pending_lock);
static u32 pending_count = 0;

/*
 * Verification state management
 */
bool ksu_check_current_verified(void)
{
    bool result;
    spin_lock(&verified_lock);
    result = current_verified;
    spin_unlock(&verified_lock);
    return result;
}

void ksu_set_current_verified(bool verified)
{
    spin_lock(&verified_lock);
    current_verified = verified;
    spin_unlock(&verified_lock);
}

/*
 * Token Management
 */
static struct ksu_manual_su_token *ksu_alloc_token(void)
{
    struct ksu_manual_su_token *token;

    spin_lock(&token_lock);
    if (token_count >= KSU_MANUAL_SU_MAX_TOKENS) {
        struct ksu_manual_su_token *oldest = list_first_entry(
            &token_list, struct ksu_manual_su_token, list);
        list_del(&oldest->list);
        token_count--;
        kfree(oldest);
    }
    spin_unlock(&token_lock);

    token = kzalloc(sizeof(*token), GFP_KERNEL);
    if (!token)
        return NULL;

    return token;
}

static char *ksu_generate_token_buffer(void)
{
    static char buffer[KSU_MANUAL_SU_TOKEN_LENGTH + 1];
    u8 rand_byte;
    int i;

    for (i = 0; i < KSU_MANUAL_SU_TOKEN_LENGTH; i++) {
        get_random_bytes(&rand_byte, 1);
        int char_type = rand_byte % 3;
        if (char_type == 0) {
            buffer[i] = 'A' + (rand_byte % 26);
        } else if (char_type == 1) {
            buffer[i] = 'a' + (rand_byte % 26);
        } else {
            buffer[i] = '0' + (rand_byte % 10);
        }
    }
    buffer[KSU_MANUAL_SU_TOKEN_LENGTH] = '\0';

    return buffer;
}

static int ksu_generate_auth_token(char *out_buffer, size_t bufsize)
{
    struct ksu_manual_su_token *token;
    char *token_str;

    if (bufsize < KSU_MANUAL_SU_TOKEN_LENGTH + 1)
        return -EINVAL;

    token = ksu_alloc_token();
    if (!token)
        return -ENOMEM;

    token_str = ksu_generate_token_buffer();
    strscpy(token->token, token_str, sizeof(token->token));
    token->expire_jiffies = jiffies + KSU_MANUAL_SU_TOKEN_EXPIRE_SECS * HZ;
    token->used = false;
    token->verified = false;

    spin_lock(&token_lock);
    list_add_tail(&token->list, &token_list);
    token_count++;
    spin_unlock(&token_lock);

    memcpy(out_buffer, token_str, KSU_MANUAL_SU_TOKEN_LENGTH + 1);

    pr_info("manual_su: generated auth token (expires in %d seconds)\n",
            KSU_MANUAL_SU_TOKEN_EXPIRE_SECS);
    return 0;
}

static void ksu_cleanup_expired_tokens(void)
{
    unsigned long now = jiffies;

    spin_lock(&token_lock);
    struct ksu_manual_su_token *token, *tmp;
    list_for_each_entry_safe (token, tmp, &token_list, list) {
        if (time_after(now, token->expire_jiffies) || token->used) {
            list_del(&token->list);
            token_count--;
            kfree(token);
            pr_debug("manual_su: cleaned up token\n");
        }
    }
    spin_unlock(&token_lock);
}

static bool ksu_verify_auth_token(const char *token_str)
{
    unsigned long now = jiffies;
    bool valid = false;

    if (!token_str || strlen(token_str) != KSU_MANUAL_SU_TOKEN_LENGTH)
        return false;

    spin_lock(&token_lock);
    struct ksu_manual_su_token *token;
    list_for_each_entry (token, &token_list, list) {
        if (!token->used &&
            time_before(now, token->expire_jiffies) &&
            strcmp(token->token, token_str) == 0) {
            token->verified = true;
            valid = true;
            pr_info("manual_su: auth token verified\n");
            break;
        }
    }
    spin_unlock(&token_lock);

    if (!valid)
        pr_warn("manual_su: invalid or expired token\n");

    return valid;
}

static char *ksu_get_token_from_envp(void)
{
    struct mm_struct *mm;
    char *envp_start, *envp_end;
    char *env_ptr, *token = NULL;
    unsigned long env_len;
    char *env_copy = NULL;

    if (!current->mm)
        return NULL;

    mm = current->mm;

    down_read(&mm->mmap_lock);
    envp_start = (char *)mm->env_start;
    envp_end = (char *)mm->env_end;
    env_len = envp_end - envp_start;

    if (env_len <= 0 || env_len > PAGE_SIZE * 32) {
        up_read(&mm->mmap_lock);
        return NULL;
    }

    env_copy = kzalloc(env_len + 1, GFP_KERNEL);
    if (!env_copy) {
        up_read(&mm->mmap_lock);
        return NULL;
    }

    if (copy_from_user(env_copy, envp_start, env_len)) {
        kfree(env_copy);
        up_read(&mm->mmap_lock);
        return NULL;
    }
    up_read(&mm->mmap_lock);

    env_copy[env_len] = '\0';
    env_ptr = env_copy;

    while (env_ptr < env_copy + env_len) {
        if (strncmp(env_ptr, KSU_MANUAL_SU_TOKEN_ENV_NAME "=",
                    strlen(KSU_MANUAL_SU_TOKEN_ENV_NAME) + 1) == 0) {
            char *token_start = env_ptr + strlen(KSU_MANUAL_SU_TOKEN_ENV_NAME) + 1;
            char *token_end = strchr(token_start, '\0');

            if (token_end && (token_end - token_start) == KSU_MANUAL_SU_TOKEN_LENGTH) {
                token = kstrndup(token_start, KSU_MANUAL_SU_TOKEN_LENGTH, GFP_KERNEL);
                if (token)
                    pr_info("manual_su: found auth token in environment\n");
            }
            break;
        }
        env_ptr += strlen(env_ptr) + 1;
    }

    kfree(env_copy);
    return token;
}

/*
 * Pending UID Management
 */
static struct ksu_manual_su_pending_uid *ksu_find_pending_uid(uid_t uid)
{
    struct ksu_manual_su_pending_uid *entry;
    list_for_each_entry (entry, &pending_list, list) {
        if (entry->uid == uid)
            return entry;
    }
    return NULL;
}

static int ksu_add_pending_uid(uid_t uid)
{
    struct ksu_manual_su_pending_uid *entry;
    unsigned long flags;

    spin_lock(&pending_lock);

    if (pending_count >= KSU_MANUAL_SU_MAX_PENDING_UIDS) {
        pr_warn("manual_su: pending list full\n");
        spin_unlock(&pending_lock);
        return -ENOSPC;
    }

    entry = ksu_find_pending_uid(uid);
    if (entry) {
        atomic_set(&entry->use_count, 0);
        atomic_set(&entry->remove_calls, 0);
        spin_unlock(&pending_lock);
        return 0;
    }

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock(&pending_lock);
        return -ENOMEM;
    }

    entry->uid = uid;
    entry->magic = KSU_MANUAL_SU_VERIFIED_MAGIC;
    atomic_set(&entry->use_count, 0);
    atomic_set(&entry->remove_calls, 0);
    entry->add_time = jiffies;

    list_add_tail(&entry->list, &pending_list);
    pending_count++;

    spin_unlock(&pending_lock);

    ksu_temp_grant_root_once(uid);
    pr_info("manual_su: pending UID %d added\n", uid);
    return 0;
}

static void ksu_cleanup_expired_pending_uids(void)
{
    unsigned long now = jiffies;
    unsigned long max_age = KSU_MANUAL_SU_TOKEN_EXPIRE_SECS * 2 * HZ;
    unsigned long flags;

    spin_lock_irqsave(&pending_lock, flags);
    struct ksu_manual_su_pending_uid *entry, *tmp;
    list_for_each_entry_safe (entry, tmp, &pending_list, list) {
        if (time_after(now, entry->add_time + max_age)) {
            list_del(&entry->list);
            pending_count--;
            ksu_temp_revoke_root_once(entry->uid);
            kfree(entry);
            pr_info("manual_su: cleaned up expired pending UID\n");
        }
    }
    spin_unlock_irqrestore(&pending_lock, flags);
}

/*
 * Public API for pending root
 */
bool ksu_is_pending_root(uid_t uid)
{
    bool found;
    unsigned long flags;

    spin_lock_irqsave(&pending_lock, flags);
    struct ksu_manual_su_pending_uid *entry = ksu_find_pending_uid(uid);
    if (entry) {
        atomic_inc(&entry->use_count);
        found = true;
    } else {
        found = false;
    }
    spin_unlock_irqrestore(&pending_lock, flags);

    return found;
}

void ksu_remove_pending_root(uid_t uid)
{
    unsigned long flags;

    spin_lock_irqsave(&pending_lock, flags);
    struct ksu_manual_su_pending_uid *entry = ksu_find_pending_uid(uid);
    if (!entry) {
        spin_unlock_irqrestore(&pending_lock, flags);
        return;
    }

    int calls = atomic_inc_return(&entry->remove_calls);
    pr_info("manual_su: pending UID %d remove_call=%d\n", uid, calls);

    if (calls >= KSU_MANUAL_SU_REMOVE_DELAY_CALLS) {
        list_del(&entry->list);
        pending_count--;
        ksu_temp_revoke_root_once(uid);
        kfree(entry);
        pr_info("manual_su: pending UID %d removed after %d calls\n",
                uid, KSU_MANUAL_SU_REMOVE_DELAY_CALLS);
    }
    spin_unlock_irqrestore(&pending_lock, flags);
}

void ksu_try_escalate_for_uid(uid_t uid)
{
    if (!ksu_is_pending_root(uid))
        return;

    pr_info("manual_su: UID=%d temporarily allowed\n", uid);
    ksu_remove_pending_root(uid);
}

/*
 * Seccomp disabling for target task
 */
static void disable_seccomp_for_task(struct task_struct *tsk)
{
    struct task_struct *fake;

    fake = kmalloc(sizeof(*fake), GFP_ATOMIC);
    if (!fake) {
        pr_warn("manual_su: failed to alloc fake task_struct\n");
        return;
    }

    spin_lock_irq(&tsk->sighand->siglock);
#if defined(CONFIG_GENERIC_ENTRY) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    clear_tsk_thread_flag(tsk, TIF_SECCOMP);
#else
    clear_thread_flag(TIF_SECCOMP);
#endif

    memcpy(fake, tsk, sizeof(*fake));
    tsk->seccomp.mode = SECCOMP_MODE_DISABLED;
    tsk->seccomp.filter = NULL;
    atomic_set(&tsk->seccomp.filter_count, 0);
    spin_unlock_irq(&tsk->sighand->siglock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
    fake->flags |= PF_EXITING;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    fake->sighand = NULL;
#endif

    seccomp_filter_release(fake);
    kfree(fake);
}

/*
 * Devpts SELinux handling
 */
static int ksu_handle_devpts_inode(struct inode *inode)
{
    if (!current->mm)
        return 0;

    uid_t uid = current_uid().val;
    if (uid % 100000 < 10000)
        return 0;

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

/*
 * Escape to root with profile for cmd_su target process
 */
void escape_to_root_for_cmd_su(uid_t target_uid, pid_t target_pid)
{
    struct cred *newcreds;
    struct task_struct *target_task;
    struct task_struct *p = current;
    struct task_struct *t;
    struct root_profile profile;

    pr_info("manual_su: escape_to_root_for_cmd_su UID=%d PID=%d\n",
            target_uid, target_pid);

    rcu_read_lock();
    target_task = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (!target_task) {
        rcu_read_unlock();
        pr_err("manual_su: target task not found PID=%d\n", target_pid);
        return;
    }
    get_task_struct(target_task);
    rcu_read_unlock();

    if (task_uid(target_task).val == 0) {
        pr_warn("manual_su: target task is already root PID=%d\n", target_pid);
        put_task_struct(target_task);
        return;
    }

    newcreds = prepare_kernel_cred(target_task);
    if (!newcreds) {
        pr_err("manual_su: failed to allocate new cred PID=%d\n", target_pid);
        put_task_struct(target_task);
        return;
    }

    ksu_get_root_profile(newcreds->uid.val, &profile);

    newcreds->uid.val = profile.uid;
    newcreds->suid.val = profile.uid;
    newcreds->euid.val = profile.uid;
    newcreds->fsuid.val = profile.uid;

    newcreds->gid.val = profile.gid;
    newcreds->fsgid.val = profile.gid;
    newcreds->sgid.val = profile.gid;
    newcreds->egid.val = profile.gid;
    newcreds->securebits = 0;

    u64 cap_for_cmd_su = profile.capabilities.effective |
                         CAP_DAC_READ_SEARCH | CAP_SETUID | CAP_SETGID;
    memcpy(&newcreds->cap_effective, &cap_for_cmd_su,
           sizeof(newcreds->cap_effective));
    memcpy(&newcreds->cap_permitted, &profile.capabilities.effective,
           sizeof(newcreds->cap_permitted));
    memcpy(&newcreds->cap_bset, &profile.capabilities.effective,
           sizeof(newcreds->cap_bset));

    setup_groups(&profile, newcreds);
    setup_selinux(profile.selinux_domain, newcreds);

    task_lock(target_task);
    const struct cred *old_creds = get_task_cred(target_task);
    rcu_assign_pointer(target_task->real_cred, newcreds);
    rcu_assign_pointer(target_task->cred, get_cred(newcreds));
    task_unlock(target_task);

    if (target_task->sighand)
        disable_seccomp_for_task(target_task);

    put_cred(old_creds);
    wake_up_process(target_task);

    if (target_task->signal->tty) {
        struct inode *inode = target_task->signal->tty->driver_data;
        if (inode && inode->i_sb->s_magic == DEVPTS_SUPER_MAGIC)
            ksu_handle_devpts_inode(inode);
    }

    put_task_struct(target_task);

    for_each_thread (p, t)
        ksu_set_task_tracepoint_flag(t);

    setup_mount_ns(profile.namespaces);

    pr_info("manual_su: privilege escalation completed UID=%d PID=%d\n",
            target_uid, target_pid);
}

/*
 * Permission check: is current process allowed to escalate?
 */
static bool ksu_check_escalation_permission(void)
{
    uid_t uid = current_uid().val;

    if (uid == 0)
        return true;

    if (is_manager())
        return true;

    if (ksu_is_allow_uid_for_current(uid))
        return true;

    return false;
}

/*
 * Operation handlers
 */
static int ksu_handle_token_generation(struct ksu_manual_su_request *request)
{
    if (current_uid().val > 2000) {
        pr_warn("manual_su: token generation denied for app UID %d\n",
                current_uid().val);
        return -EPERM;
    }

    ksu_cleanup_expired_tokens();
    int ret = ksu_generate_auth_token(request->token_buffer,
                                       sizeof(request->token_buffer));
    if (ret)
        pr_err("manual_su: failed to generate token: %d\n", ret);
    else
        pr_info("manual_su: token generated successfully\n");

    return ret;
}

static int ksu_handle_escalation_request(struct ksu_manual_su_request *request)
{
    uid_t target_uid = request->target_uid;
    pid_t target_pid = request->target_pid;
    struct task_struct *tsk;

    rcu_read_lock();
    tsk = pid_task(find_vpid(target_pid), PIDTYPE_PID);
    if (!tsk || ksu_task_is_dead(tsk)) {
        rcu_read_unlock();
        pr_err("manual_su: PID %d is invalid or dead\n", target_pid);
        return -ESRCH;
    }
    rcu_read_unlock();

    if (ksu_check_escalation_permission()) {
        ksu_set_current_verified(true);
        goto allowed;
    }

    char *env_token = ksu_get_token_from_envp();
    if (!env_token) {
        pr_warn("manual_su: no auth token found in environment\n");
        return -EACCES;
    }

    if (!ksu_verify_auth_token(env_token)) {
        kfree(env_token);
        return -EACCES;
    }
    kfree(env_token);

    ksu_set_current_verified(true);

allowed:
    escape_to_root_for_cmd_su(target_uid, target_pid);
    return 0;
}

static int ksu_handle_add_pending_request(struct ksu_manual_su_request *request)
{
    uid_t target_uid = request->target_uid;

    if (!ksu_check_current_verified()) {
        pr_warn("manual_su: add_pending denied, not verified\n");
        return -EPERM;
    }

    int ret = ksu_add_pending_uid(target_uid);
    ksu_set_current_verified(false);

    if (ret == 0)
        pr_info("manual_su: pending root added for UID %d\n", target_uid);
    else
        pr_err("manual_su: failed to add pending UID %d: %d\n", target_uid, ret);

    return ret;
}

/*
 * Main request handler
 */
int ksu_handle_manual_su_request(int option, struct ksu_manual_su_request *request)
{
    if (!request) {
        pr_err("manual_su: invalid request pointer\n");
        return -EINVAL;
    }

    switch (option) {
    case MANUAL_SU_OP_GENERATE_TOKEN:
        pr_info("manual_su: handling token generation request\n");
        return ksu_handle_token_generation(request);

    case MANUAL_SU_OP_ESCALATE:
        pr_info("manual_su: handling escalation request UID=%d PID=%d\n",
                request->target_uid, request->target_pid);
        return ksu_handle_escalation_request(request);

    case MANUAL_SU_OP_ADD_PENDING:
        pr_info("manual_su: handling add pending request UID=%d\n",
                request->target_uid);
        return ksu_handle_add_pending_request(request);

    default:
        pr_err("manual_su: unknown option %d\n", option);
        return -EINVAL;
    }
}

/*
 * Module initialization
 */
void __init ksu_manual_su_init(void)
{
    INIT_LIST_HEAD(&token_list);
    INIT_LIST_HEAD(&pending_list);
    pr_info("manual_su: module initialized\n");
}

/*
 * Module cleanup
 */
void ksu_manual_su_exit(void)
{
    unsigned long flags;

    spin_lock_irqsave(&token_lock, flags);
    struct ksu_manual_su_token *token, *tmp;
    list_for_each_entry_safe (token, tmp, &token_list, list) {
        list_del(&token->list);
        kfree(token);
    }
    token_count = 0;
    spin_unlock_irqrestore(&token_lock, flags);

    spin_lock_irqsave(&pending_lock, flags);
    struct ksu_manual_su_pending_uid *entry, *pent;
    list_for_each_entry_safe (entry, pent, &pending_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    pending_count = 0;
    spin_unlock_irqrestore(&pending_lock, flags);

    pr_info("manual_su: module exited\n");
}
