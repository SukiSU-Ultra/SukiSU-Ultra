#include <linux/version.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include <linux/string.h>
#include <linux/security.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif

#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
#include <linux/key.h>
#include <linux/errno.h>
#include <linux/cred.h>

extern int install_session_keyring_to_cred(struct cred *, struct key *);
struct key *init_session_keyring = NULL;

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
#endif

struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||                           \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	if (init_session_keyring != NULL && !current_cred()->session_keyring &&
	    (current->flags & PF_WQ_WORKER)) {
		pr_info("installing init session keyring for older kernel\n");
		install_session_keyring(init_session_keyring);
	}
#endif
	return filp_open(filename, flags, mode);
}

ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
			       loff_t *pos)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) ||                          \
	defined(KSU_OPTIONAL_KERNEL_READ)
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0) ||                          \
	defined(KSU_OPTIONAL_KERNEL_WRITE)
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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0) && !defined(KSU_HAS_PATH_MOUNT))
extern long do_mount(const char *dev_name, const char __user *dir_name,
		     const char *type_page, unsigned long flags,
		     void *data_page);

int path_mount(const char *dev_name, struct path *path, const char *type_page,
	       unsigned long flags, void *data_page)
{
	mm_segment_t old_fs;
	long ret = 0;
	char buf[384];

	char *realpath = d_path(path, buf, 384);
	if (IS_ERR(realpath)) {
		pr_err("ksu_mount: d_path failed, err: %lu\n",
		       PTR_ERR(realpath));
		return PTR_ERR(realpath);
	}

	// https://github.com/backslashxx/KernelSU/blob/e02c2771b106c68f0b8a17234b5b1846664852f0/kernel/kernel_compat.c#L123
	// This check is handy.
	if (!(realpath && realpath != buf))
		return -ENOENT;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = do_mount(dev_name, (const char __user *)realpath, type_page,
		       flags, data_page);
	set_fs(old_fs);
	return ret;
}
#endif

static inline long
do_strncpy_user_nofault(char *dst, const void __user *unsafe_addr, long count)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) ||                           \
	defined(KSU_OPTIONAL_STRNCPY)
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

long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
				   long count)
{
#ifdef CONFIG_KSU_MANUAL_HOOK
	long ret;

	ret = do_strncpy_user_nofault(dst, unsafe_addr, count);
	if (likely(ret >= 0))
		return ret;

	// we faulted! fallback to slow path
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
#else
	return do_strncpy_user_nofault(dst, unsafe_addr, count);
#endif
}

int do_close_fd(unsigned int fd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	return close_fd(fd);
#else
	return __close_fd(current->files, fd);
#endif
}
