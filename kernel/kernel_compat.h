#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/cred.h>

// Checks for UH, KDP and RKP
#ifdef SAMSUNG_UH_DRIVER_EXIST
#if defined(CONFIG_UH) || defined(CONFIG_KDP) || defined(CONFIG_RKP)
#error "CONFIG_UH, CONFIG_KDP and CONFIG_RKP is enabled! Please disable or remove it before compile a kernel with KernelSU!"
#endif
#endif

extern long ksu_strncpy_from_user_nofault(char *dst,
                      const void __user *unsafe_addr,
                      long count);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||    \
    defined(CONFIG_IS_HW_HISI) ||    \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
extern struct key *init_session_keyring;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define ksu_access_ok(addr, size)    access_ok(addr, size)
#else
#define ksu_access_ok(addr, size)    access_ok(VERIFY_READ, addr, size)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define TWA_RESUME true
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define ksu_force_sig(sig)      force_sig(sig);
#else
#define ksu_force_sig(sig)      force_sig(sig, current);
#endif

#endif
