/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION_APP_CONTEXT
#define __KSU_H_EXTENSION_APP_CONTEXT

#include <linux/types.h>
#include "uapi/extension.h"

/* Sleepable kernel API. Returned entries are independent snapshots; no pointers
 * into the internal list escape the lock. These symbols are not a module ABI.
 */
int ksu_app_context_query(uid_t uid, struct ksu_app_context_entry *entry);
int ksu_app_context_set_foreground(uid_t uid, bool foreground);
int ksu_app_context_set_profile(uid_t uid, u32 profile_id);
int ksu_app_context_set_tag(uid_t uid, u64 tag_mask);
int ksu_app_context_clear_tag(uid_t uid, u64 tag_mask);
int ksu_app_context_list(struct ksu_app_context_entry *buf, u32 max_count,
                         u32 *out_count);
int ksu_app_context_remove(uid_t uid);
int ksu_app_context_clear_all(u32 id);
void ksu_app_context_init(void);
void ksu_app_context_exit(void);
int ksu_extension_app_context_io(u32 id, void __user *raw);

#endif /* __KSU_H_EXTENSION_APP_CONTEXT */
