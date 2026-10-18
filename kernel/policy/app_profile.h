#ifndef __KSU_H_APP_PROFILE
#define __KSU_H_APP_PROFILE

#if defined(CONFIG_64BIT)
#define TIF_KSU_DISABLE_ESCAPE_WITH_ROOT 63
#define TIF_KSU_RESERVED_62 62
#define TIF_KSU_UNMOUNTABLE 61
#define TIF_KSU_MANAGED	60
#else
#define TIF_KSU_DISABLE_ESCAPE_WITH_ROOT 31
#define TIF_KSU_RESERVED_30 30
#define TIF_KSU_UNMOUNTABLE 29
#define TIF_KSU_MANAGED	28
#endif

// Escalate current process to root with the appropriate profile
int escape_with_root_profile(void);

void escape_to_root_forced(void);

void __init ksu_app_profile_init(void);

#endif
