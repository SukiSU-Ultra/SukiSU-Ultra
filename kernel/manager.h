#ifndef __KSU_H_KSU_MANAGER
#define __KSU_H_KSU_MANAGER

#include <linux/cred.h>
#include <linux/types.h>
#include "allowlist.h"

#define KSU_INVALID_APPID -1

extern uid_t ksu_manager_appid; // DO NOT DIRECT USE

extern bool ksu_is_any_manager(uid_t uid);
extern void ksu_add_manager(uid_t uid, int signature_index);
extern void ksu_remove_manager(uid_t uid);
extern int ksu_get_manager_signature_index(uid_t uid);

static inline bool ksu_is_manager_appid_valid(void)
{
	return ksu_manager_appid != KSU_INVALID_APPID;
}

static inline bool is_manager(void)
{
	return unlikely(ksu_is_any_manager(current_uid().val) || 
			(ksu_manager_appid != KSU_INVALID_APPID && ksu_manager_appid == current_uid().val % PER_USER_RANGE));
}

static inline uid_t ksu_get_manager_appid(void)
{
	return ksu_manager_appid;
}

static inline void ksu_set_manager_appid(uid_t appid)
{
	ksu_manager_appid = appid;
}

static inline void ksu_invalidate_manager_uid(void)
{
	ksu_manager_appid = KSU_INVALID_APPID;
}
#endif
