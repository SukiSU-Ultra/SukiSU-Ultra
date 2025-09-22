#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>
#include "ss/policydb.h"
#include "linux/key.h"

/**
 * list_count_nodes - count the number of nodes in a list
 * @head: the head of the list
 *
 * This function iterates over the list starting from @head and counts
 * the number of nodes in the list. It does not modify the list.
 *
 * Context: Any context. The function is safe to call in any context,
 *          including interrupt context, as it does not sleep or allocate
 *          memory.
 *
 * Return: the number of nodes in the list (excluding the head)
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
static inline __maybe_unused size_t list_count_nodes(const struct list_head *head)
{
    const struct list_head *pos;
    size_t count = 0;

    if (!head)
        return 0;

    list_for_each(pos, head)
        count++;

	return count;
}
#endif

/*
 * Adapt to Huawei HISI kernel without affecting other kernels ,
 * Huawei Hisi Kernel EBITMAP Enable or Disable Flag ,
 * From ss/ebitmap.h
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)) &&                           \
		(LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)) ||               \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) &&                      \
		(LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0))
#ifdef HISI_SELINUX_EBITMAP_RO
#define CONFIG_IS_HW_HISI
#endif
#endif

extern long ksu_strncpy_from_user_nofault(char *dst,
					  const void __user *unsafe_addr,
					  long count);

extern void ksu_android_ns_fs_check();
extern struct file *ksu_filp_open_compat(const char *filename, int flags,
					 umode_t mode);
extern ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
				      loff_t *pos);
extern ssize_t ksu_kernel_write_compat(struct file *p, const void *buf,
				       size_t count, loff_t *pos);
/*
 * ksu_copy_from_user_retry
 * try nofault copy first, if it fails, try with plain
 * paramters are the same as copy_from_user
 * 0 = success
 */
static long ksu_copy_from_user_retry(void *to, 
		const void __user *from, unsigned long count)
{
	long ret = copy_from_user_nofault(to, from, count);
	if (likely(!ret))
		return ret;

	// we faulted! fallback to slow path
	return copy_from_user(to, from, count);
}

#endif
