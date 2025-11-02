#include <linux/version.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif
#include <linux/uaccess.h>
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h" // Add check Huawei Device

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||    \
    defined(CONFIG_IS_HW_HISI) ||    \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
#include <linux/key.h>
#include <linux/errno.h>
#include <linux/cred.h>
struct key *init_session_keyring = NULL;

static inline int install_session_keyring(struct key *keyring)
{
    struct cred *new;
    int ret;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    ret = install_session_keyring_to_cred(new, keyring);
    if (ret < 0) {
        abort_creds(new);
        return ret;
    }

    return commit_creds(new);
}
#endif

extern struct task_struct init_task;

// mnt_ns context switch for environment that android_init->nsproxy->mnt_ns != init_task.nsproxy->mnt_ns, such as WSA
struct ksu_ns_fs_saved {
    struct nsproxy *ns;
    struct fs_struct *fs;
};

static void ksu_save_ns_fs(struct ksu_ns_fs_saved *ns_fs_saved)
{
    ns_fs_saved->ns = current->nsproxy;
    ns_fs_saved->fs = current->fs;
}

static void ksu_load_ns_fs(struct ksu_ns_fs_saved *ns_fs_saved)
{
    current->nsproxy = ns_fs_saved->ns;
    current->fs = ns_fs_saved->fs;
}

static bool android_context_saved_checked = false;
static bool android_context_saved_enabled = false;
static struct ksu_ns_fs_saved android_context_saved;

void ksu_android_ns_fs_check(void)
{
    if (android_context_saved_checked)
        return;
    android_context_saved_checked = true;
    task_lock(current);
    if (current->nsproxy && current->fs &&
        current->nsproxy->mnt_ns != init_task.nsproxy->mnt_ns) {
        android_context_saved_enabled = true;
#ifdef CONFIG_KSU_DEBUG
        pr_info("android context saved enabled due to init mnt_ns(%p) != android mnt_ns(%p)\n",
            current->nsproxy->mnt_ns, init_task.nsproxy->mnt_ns);
#endif
        ksu_save_ns_fs(&android_context_saved);
    } else {
        pr_info("android context saved disabled\n");
    }
    task_unlock(current);
}

struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||    \
    defined(CONFIG_IS_HW_HISI) ||    \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
    if (init_session_keyring != NULL && !current_cred()->session_keyring &&
        (current->flags & PF_WQ_WORKER)) {
        pr_info("installing init session keyring for older kernel\n");
        install_session_keyring(init_session_keyring);
    }
#endif
    // switch mnt_ns even if current is not wq_worker, to ensure what we open is the correct file in android mnt_ns, rather than user created mnt_ns
    struct ksu_ns_fs_saved saved;
    if (android_context_saved_enabled) {
#ifdef CONFIG_KSU_DEBUG
        pr_info("start switch current nsproxy and fs to android context\n");
#endif
        task_lock(current);
        ksu_save_ns_fs(&saved);
        ksu_load_ns_fs(&android_context_saved);
        task_unlock(current);
    }
    struct file *fp = filp_open(filename, flags, mode);
    if (android_context_saved_enabled) {
        task_lock(current);
        ksu_load_ns_fs(&saved);
        task_unlock(current);
#ifdef CONFIG_KSU_DEBUG
        pr_info("switch current nsproxy and fs back to saved successfully\n");
#endif
    }
    return fp;
}

ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
                   loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) || defined(KSU_OPTIONAL_KERNEL_READ)
    return kernel_read(p, buf, count, pos);
#else
    loff_t offset = pos ? *pos : 0;
    ssize_t result = kernel_read(p, offset, (char *)buf, count);
    if (pos && result > 0) {
        *pos = offset + result;
    }
    return result;
#endif
}

ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count,
                loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) || defined(KSU_OPTIONAL_KERNEL_WRITE)
    return kernel_write(p, buf, count, pos);
#else
    loff_t offset = pos ? *pos : 0;
    ssize_t result = kernel_write(p, buf, count, offset);
    if (pos && result > 0) {
        *pos = offset + result;
    }
    return result;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(KSU_OPTIONAL_STRNCPY)
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
                   long count)
{
    return strncpy_from_user_nofault(dst, unsafe_addr, count);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
                   long count)
{
    return strncpy_from_unsafe_user(dst, unsafe_addr, count);
}
#else
// Copied from: https://elixir.bootlin.com/linux/v4.9.337/source/mm/maccess.c#L201
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
                   long count)
{
    mm_segment_t old_fs = get_fs();
    long ret;

    if (unlikely(count <= 0))
        return 0;

    set_fs(USER_DS);
    pagefault_disable();
    ret = strncpy_from_user(dst, unsafe_addr, count);
    pagefault_enable();
    set_fs(old_fs);

    if (ret >= count) {
        ret = count;
        dst[ret - 1] = '\0';
    } else if (ret > 0) {
        ret++;
    }

    return ret;
}
#endif

long ksu_strncpy_from_user_retry(char *dst, const void __user *unsafe_addr,
                   long count)
{
    long ret;

    ret = ksu_strncpy_from_user_nofault(dst, unsafe_addr, count);
    if (likely(ret >= 0))
        return ret;

    // we faulted! fallback to slow path
    if (unlikely(!ksu_access_ok(unsafe_addr, count))) {
#ifdef CONFIG_KSU_DEBUG
        pr_err("%s: faulted!\n", __func__);
#endif
        return -EFAULT;
    }

    // why we don't do like how strncpy_from_user_nofault?
    ret = strncpy_from_user(dst, unsafe_addr, count);

    if (ret >= count) {
        ret = count;
        dst[ret - 1] = '\0';
    } else if (likely(ret >= 0)) {
        ret++;
    }

    return ret;
}

long ksu_copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    return copy_from_user_nofault(dst, src, size);
#else
    // https://elixir.bootlin.com/linux/v5.8/source/mm/maccess.c#L205
    long ret = -EFAULT;
    mm_segment_t old_fs = get_fs();

    set_fs(USER_DS);
    // tweaked to use ksu_access_ok
    if (ksu_access_ok(src, size)) {
        pagefault_disable();
        ret = __copy_from_user_inatomic(dst, src, size);
        pagefault_enable();
    }
    set_fs(old_fs);

    if (ret)
        return -EFAULT;
    return 0;
#endif
}

struct action_cache {
    DECLARE_BITMAP(allow_native, NR_syscalls);
#ifdef SECCOMP_ARCH_COMPAT
    DECLARE_BITMAP(allow_compat, SECCOMP_ARCH_COMPAT_NR);
#endif
};

struct seccomp_filter {
    refcount_t refs;
    refcount_t users;
    bool log;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    bool wait_killable_recv;
#endif
    struct action_cache cache;
    struct seccomp_filter *prev;
    struct bpf_prog *prog;
    struct notification *notif;
    struct mutex notify_lock;
    wait_queue_head_t wqh;
};

void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
    if (!filter) {
        return;
    }

    if (nr >= 0 && nr < NR_syscalls) {
        clear_bit(nr, filter->cache.allow_native);
    }

#ifdef SECCOMP_ARCH_COMPAT
    if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR) {
        clear_bit(nr, filter->cache.allow_compat);
    }
#endif
}

void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
    if (!filter) {
        return;
    }

    if (nr >= 0 && nr < NR_syscalls) {
        set_bit(nr, filter->cache.allow_native);
    }

#ifdef SECCOMP_ARCH_COMPAT
    if (nr >= 0 && nr < SECCOMP_ARCH_COMPAT_NR) {
        set_bit(nr, filter->cache.allow_compat);
    }
#endif
}