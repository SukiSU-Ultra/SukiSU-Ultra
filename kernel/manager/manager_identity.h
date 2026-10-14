#ifndef __KSU_H_MANAGER_IDENTITY
#define __KSU_H_MANAGER_IDENTITY

#include <linux/cred.h>
#include <linux/types.h>

#define KSU_INVALID_APPID -1
#define KSU_PER_USER_RANGE 100000

#ifndef CONFIG_KSU_DISABLE_MANAGER
bool ksu_manager_enabled(void);
bool ksu_manager_uid_authorized(uid_t uid);
bool ksu_manager_package_authorized(const char *package, uid_t uid);
#endif

#ifdef CONFIG_KSU_DISABLE_MANAGER
static inline bool ksu_is_manager_appid_valid()
{
    return true;
}

static inline bool ksu_manager_enabled()
{
    return true;
}

static inline bool ksu_manager_uid_authorized(uid_t uid)
{
    return uid == 0;
}

static inline bool ksu_manager_package_authorized(const char *package, uid_t uid)
{
    (void)package;
    return uid == 0;
}

static inline bool is_manager()
{
    return current_uid().val == 0;
}

static inline bool is_uid_manager(uid_t uid)
{
    return uid == 0;
}

static inline uid_t ksu_get_manager_appid()
{
    return 0;
}

static inline void ksu_set_manager_appid(uid_t appid)
{
    (void)appid;
}

static inline void ksu_invalidate_manager_uid()
{
}
#else
extern uid_t ksu_manager_appid; // DO NOT DIRECT USE

static inline bool ksu_is_manager_appid_valid()
{
    return ksu_manager_appid != KSU_INVALID_APPID;
}

static inline bool is_manager()
{
    return ksu_manager_uid_authorized(current_uid().val);
}

static inline bool is_uid_manager(uid_t uid)
{
    return ksu_manager_uid_authorized(uid);
}

static inline uid_t ksu_get_manager_appid()
{
    return ksu_manager_appid;
}

static inline void ksu_set_manager_appid(uid_t appid)
{
    ksu_manager_appid = appid;
}

static inline void ksu_invalidate_manager_uid()
{
    ksu_manager_appid = KSU_INVALID_APPID;
}
#endif

#endif // __KSU_H_MANAGER_IDENTITY
