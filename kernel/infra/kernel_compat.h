#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)) ||              \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0))
#ifdef HISI_SELINUX_EBITMAP_RO
#define CONFIG_IS_HW_HISI
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_IS_HW_HISI) ||                                     \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)

extern int install_session_keyring_to_cred(struct cred *cred, struct key *keyring);
static struct key *init_session_keyring = NULL;

static int install_session_keyring(struct key *keyring)
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

struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
    if (init_session_keyring != NULL && !current_cred()->session_keyring && (current->flags & PF_WQ_WORKER)) {
        pr_info("installing init session keyring for older kernel\n");
        install_session_keyring(init_session_keyring);
    }

    return filp_open(filename, flags, mode);
}
#define filp_open ksu_filp_open_compat
#endif

#ifndef VERIFY_READ
#define ksu_access_ok(addr, size) access_ok(addr, size)
#else
#define ksu_access_ok(addr, size) access_ok(VERIFY_READ, addr, size)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) // caller is reponsible for sanity!
static inline void ksu_zeroed_strncpy(char *dest, const char *src, size_t count)
{
	// this is actually faster due to dead store elimination
	// count - 1 as implicit null termination
	__builtin_memset(dest, 0, count);
	__builtin_strncpy(dest, src, count - 1);
}
#define strscpy ksu_zeroed_strncpy
#define strscpy_pad ksu_zeroed_strncpy
#endif

static inline long __strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(KSU_HAS_STRNCPY_FROM_USER_NOFAULT)
    return strncpy_from_user_nofault(dst, unsafe_addr, count);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
    return strncpy_from_unsafe_user(dst, unsafe_addr, count);
#else
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
#endif
}

long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
    long ret = __strncpy_from_user_nofault(dst, unsafe_addr, count);

    if (likely(ret >= 0))
        return ret;
    if (unlikely(!ksu_access_ok(unsafe_addr, count)))
        return -EFAULT;

    ret = strncpy_from_user(dst, unsafe_addr, count);
    if (ret >= count) {
        ret = count;
        dst[ret - 1] = '\0';
    } else if (ret >= 0) {
        ret++;
    }

    return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
// https://elixir.bootlin.com/linux/v4.14.336/source/fs/read_write.c#L418
ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count, loff_t *pos)
{
    mm_segment_t old_fs;
    old_fs = get_fs();
    set_fs(get_ds());
    ssize_t result = vfs_read(p, (void __user *)buf, count, pos);
    set_fs(old_fs);
    return result;
}
// https://elixir.bootlin.com/linux/v4.14.336/source/fs/read_write.c#L512
ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count, loff_t *pos)
{
    mm_segment_t old_fs;
    old_fs = get_fs();
    set_fs(get_ds());
    ssize_t res = vfs_write(p, (__force const char __user *)buf, count, pos);
    set_fs(old_fs);
    return res;
}
#define kernel_read ksu_kernel_read_compat
#define kernel_write ksu_kernel_write_compat
#endif // < 4.14

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static inline void *ksu_kvmalloc(size_t size, gfp_t flags)
{
    void *buf = kmalloc(size, flags);
    if (!buf)
        buf = vmalloc(size);

    return buf;
}

static inline void ksu_kvfree(void *buf)
{
    if (is_vmalloc_addr(buf))
        vfree(buf);
    else
        kfree(buf);
}
#define kvmalloc ksu_kvmalloc
#define kvfree ksu_kvfree
#endif

// for supercalls.c fd install tw
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef TWA_RESUME
#define TWA_RESUME 1
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
#define close_fd sys_close
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#include <linux/fdtable.h>
__weak int close_fd(unsigned fd)
{
    // this is ksys_close, but that shit is inline
    // its problematic to cascade a weak symbol for it
    return __close_fd(current->files, fd);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) && !defined(KSU_HAS_SELINUX_INODE)
static inline struct inode_security_struct *selinux_inode(const struct inode *inode)
{
    return inode->i_security;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) && !defined(KSU_HAS_SELINUX_CRED)
static inline struct task_security_struct *selinux_cred(const struct cred *cred)
{
    return cred->security;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
__weak void groups_sort(struct group_info *group_info)
{
} // no-op
#endif

#ifndef U16_MAX
#define	U16_MAX	((u16)(~0U))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 12, 0) && !defined(EPOLLIN)
#define EPOLLIN		0x00000001
#define EPOLLPRI	0x00000002
#define EPOLLOUT	0x00000004
#define EPOLLERR	0x00000008
#define EPOLLHUP	0x00000010
#define EPOLLRDNORM	0x00000040
#define EPOLLRDBAND	0x00000080
#define EPOLLWRNORM	0x00000100
#define EPOLLWRBAND	0x00000200
#define EPOLLMSG	0x00000400
#define EPOLLRDHUP	0x00002000
#endif // < 4.12 && !EPOLLIN

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 15, 0)
#define task_ppid_nr(a) (pid_t)sys_getppid()
#endif

// WARNING: no overflow safety!
#ifndef struct_size
#define struct_size(p, member, n) (sizeof(*(p)) + (n) * sizeof(*(p)->member))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 12, 0)
#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, a) __ALIGN_KERNEL((x) - ((a) - 1), (a))
#endif
#endif

#ifndef untagged_addr
#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 9, 0)
static inline __s64 ksu_sign_extend64(__u64 value, int index)
{
	__u8 shift = 63 - index;
	return (__s64)(value << shift) >> shift;
}
#define untagged_addr(addr) ksu_sign_extend64(addr, 55)
#endif
#endif

#ifndef check_add_overflow
#define check_add_overflow(a, b, d) ({      \
    typeof(a) _a = (a);                     \
    typeof(b) _b = (b);                     \
    *(d) = _a + _b;                         \
    *(d) < _a;                              \
})
#endif

#ifndef in_compat_syscall
#define in_compat_syscall() is_compat_task()
#endif

#endif
