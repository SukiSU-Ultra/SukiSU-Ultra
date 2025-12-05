#ifndef __KSU_H_SELINUX_DEFS
#define __KSU_H_SELINUX_DEFS

#include "selinux.h"
#include "objsec.h"
#ifdef SAMSUNG_SELINUX_PORTING
#include "security.h" // Samsung SELinux Porting
#endif
#ifndef KSU_COMPAT_USE_SELINUX_STATE
#include "avc.h"
#endif

#ifdef CONFIG_SECURITY_SELINUX_DISABLE
#ifdef KSU_COMPAT_USE_SELINUX_STATE
#define is_selinux_disabled() (selinux_state.disabled)
#else
#define is_selinux_disabled() (selinux_disabled)
#endif
#else
#define is_selinux_disabled() (0)
#endif

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
#ifdef KSU_COMPAT_USE_SELINUX_STATE
#define __is_selinux_enforcing() (selinux_state.enforcing)
#define __setenforce(val) selinux_state.enforcing = val
#elif defined(SAMSUNG_SELINUX_PORTING) || !defined(KSU_COMPAT_USE_SELINUX_STATE)
#define __is_selinux_enforcing() (selinux_enforcing)
#define __setenforce(val) selinux_enforcing = val
#endif
#else
#define __is_selinux_enforcing() (1)
#define __setenforce(val)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
typedef struct task_security_struct selinux_security_struct;
#else
typedef struct cred_security_struct selinux_security_struct;
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) &&                           \
     !defined(KSU_OPTIONAL_SELINUX_CRED))
static inline selinux_security_struct *selinux_cred(const struct cred *cred)
{
	return (selinux_security_struct *)cred->security;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
struct lsm_context {
	char *context;
	u32 len;
};

static inline int __security_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
	return security_secid_to_secctx(secid, &cp->context, &cp->len);
}
static inline void __security_release_secctx(struct lsm_context *cp)
{
	security_release_secctx(cp->context, cp->len);
}
#else
#define __security_secid_to_secctx security_secid_to_secctx
#define __security_release_secctx security_release_secctx
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) &&                         \
	!defined(KSU_COMPAT_HAS_CURRENT_SID)
/*
 * get the subjective security ID of the current task
 */
static inline u32 current_sid(void)
{
	const selinux_security_struct *sec = current_security();

	return sec->sid;
}
#endif

#endif
