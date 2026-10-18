// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_EXTENSION_DYNAMIC_MANAGER
#define __KSU_H_EXTENSION_DYNAMIC_MANAGER

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include "extension.h"
#include "uapi/manager.h"
#include "uapi/supercall.h"

/*
 * Dynamic manager extension.
 *
 * Sticky state (u64 bit 0): whether dynamic-manager feature is currently
 * enabled (mirrors dynamic_manager_enabled).
 *
 * The actual list-modify / list-fetch is done by
 * ksu_dynamic_manager_{get,set} via the io op, accepting a
 * struct ksu_manager_cmd.
 */

/* Backwards-compat: dynamic_manager.{c,h} from kernel/manager/, hoisted here. */
bool ksu_dynamic_manager_match(const char *package, unsigned int size,
                               const char *hash);
bool ksu_dynamic_manager_package_registered(const char *package);
bool ksu_dynamic_manager_verify_apk(char *path, const char *package,
                                    uid_t uid);
int ksu_dynamic_manager_uid_for_package(const char *package, uid_t *uid);
void ksu_dynamic_manager_reset_verification(void);
void ksu_dynamic_manager_load(void);
int ksu_dynamic_manager_set(struct ksu_manager_cmd *cmd);
int ksu_dynamic_manager_get(struct ksu_manager_cmd *cmd);
bool ksu_manager_enabled(void);

int ksu_extension_dynamic_manager_get(u32 id, u64 *value);
int ksu_extension_dynamic_manager_set(u32 id, u64 value);
int ksu_extension_dynamic_manager_io(u32 id, void __user *raw);

extern const struct ksu_extension_handler_ops ksu_extension_dynamic_manager_ops;

#endif /* __KSU_H_EXTENSION_DYNAMIC_MANAGER */
