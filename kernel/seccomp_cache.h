#ifndef __KSU_H_SECCOMP_CACHE
#define __KSU_H_SECCOMP_CACHE

#include <linux/fs.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
extern void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr);
extern void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr);
#endif

#endif
