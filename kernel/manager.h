#ifndef __KSU_H_KSU_MANAGER
#define __KSU_H_KSU_MANAGER

#include <linux/cred.h>
#include <linux/types.h>
#include "include/ksu_creds.h"

#define KSU_INVALID_UID -1

extern uid_t ksu_manager_uid; // DO NOT DIRECT USE

extern bool ksu_is_any_manager(uid_t uid);
extern void ksu_add_manager(uid_t uid, int signature_index);
extern void ksu_remove_manager(uid_t uid);
extern int ksu_get_manager_signature_index(uid_t uid);

static inline bool ksu_is_manager_uid_valid()
{
	return ksu_manager_uid != KSU_INVALID_UID;
}

static inline bool is_manager()
{
	return unlikely(ksu_is_any_manager(ksu_current_uid()) ||
			ksu_manager_uid == ksu_current_uid());
}

static inline uid_t ksu_get_manager_uid()
{
	return ksu_manager_uid;
}

static inline void ksu_set_manager_uid(uid_t uid)
{
	ksu_manager_uid = uid;
}

static inline void ksu_invalidate_manager_uid()
{
	ksu_manager_uid = KSU_INVALID_UID;
}

#endif