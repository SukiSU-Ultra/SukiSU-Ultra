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

#endif
