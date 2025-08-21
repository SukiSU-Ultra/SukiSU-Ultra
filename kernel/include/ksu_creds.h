/*
 * KernelSU creds wrapper
 *
 * Provide a wrapper for a few credentials use (e.g current_uid().val),
 * so it would be easier to maintain
 * some older linux versions.
 */

#ifndef __KSU_H_CREDS
#define __KSU_H_CREDS

#include <linux/cred.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) && \
     defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS)) ||    \
	LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
#define ksu_cred_uid(x) ((x)->uid.val)
#define ksu_cred_suid(x) ((x)->suid.val)
#define ksu_cred_euid(x) ((x)->euid.val)
#define ksu_cred_fsuid(x) ((x)->fsuid.val)
#define ksu_cred_gid(x) ((x)->gid.val)
#define ksu_cred_fsgid(x) ((x)->fsgid.val)
#define ksu_cred_sgid(x) ((x)->sgid.val)
#define ksu_cred_egid(x) ((x)->egid.val)
#define ksu_current_uid() (current_uid().val)
#else
#define ksu_cred_uid(x) ((x)->uid)
#define ksu_cred_suid(x) ((x)->suid)
#define ksu_cred_euid(x) ((x)->euid)
#define ksu_cred_fsuid(x) ((x)->fsuid)
#define ksu_cred_gid(x) ((x)->gid)
#define ksu_cred_fsgid(x) ((x)->fsgid)
#define ksu_cred_sgid(x) ((x)->sgid)
#define ksu_cred_egid(x) ((x)->egid)
#define ksu_current_uid() (current_uid())
#endif

#endif
