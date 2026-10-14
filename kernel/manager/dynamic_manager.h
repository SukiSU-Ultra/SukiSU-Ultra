// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_DYNAMIC_MANAGER_H
#define __KSU_DYNAMIC_MANAGER_H

#include <linux/errno.h>
#include <linux/types.h>
#include "uapi/supercall.h"

#ifdef CONFIG_KSU_DISABLE_MANAGER
static inline bool ksu_dynamic_manager_match(const char *package, unsigned int size, const char *hash)
{
    (void)package;
    (void)size;
    (void)hash;
    return false;
}
static inline bool ksu_dynamic_manager_check_apk(char *path, const char *package, uid_t uid)
{
    (void)path;
    (void)package;
    (void)uid;
    return false;
}
static inline bool ksu_dynamic_manager_package_registered(const char *package)
{
    (void)package;
    return false;
}
static inline bool ksu_dynamic_manager_verify_apk(char *path, const char *package, uid_t uid)
{
    (void)path;
    (void)package;
    (void)uid;
    return false;
}
static inline int ksu_dynamic_manager_uid_for_package(const char *package, uid_t *uid)
{
    (void)package;
    (void)uid;
    return -ENOENT;
}
static inline void ksu_dynamic_manager_reset_verification(void) {}
static inline void ksu_dynamic_manager_load(void) {}
static inline int ksu_dynamic_manager_set(struct ksu_manager_cmd *cmd)
{
    (void)cmd;
    return -EOPNOTSUPP;
}
static inline int ksu_dynamic_manager_get(struct ksu_manager_cmd *cmd)
{
    (void)cmd;
    return -EOPNOTSUPP;
}
#else
bool ksu_dynamic_manager_match(const char *package, unsigned int size, const char *hash);
bool ksu_dynamic_manager_check_apk(char *path, const char *package, uid_t uid);
bool ksu_dynamic_manager_package_registered(const char *package);
bool ksu_dynamic_manager_verify_apk(char *path, const char *package, uid_t uid);
int ksu_dynamic_manager_uid_for_package(const char *package, uid_t *uid);
void ksu_dynamic_manager_reset_verification(void);
void ksu_dynamic_manager_load(void);
int ksu_dynamic_manager_set(struct ksu_manager_cmd *cmd);
int ksu_dynamic_manager_get(struct ksu_manager_cmd *cmd);
#endif

#endif
