/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION_VERSION_SPOOF
#define __KSU_H_EXTENSION_VERSION_SPOOF

#include <linux/types.h>

#include "uapi/extension.h"
#include "uapi/supercall.h"

int ksu_extension_version_spoof_io(u32 id, void __user *raw);
int ksu_extension_version_spoof_wipe(u32 id);
void ksu_version_spoof_apply_info(struct ksu_get_info_cmd *cmd);
void ksu_version_spoof_apply_info_legacy(struct ksu_get_info_legacy_cmd *cmd);
void ksu_version_spoof_apply_full_version(char *buf, size_t size);

#endif /* __KSU_H_EXTENSION_VERSION_SPOOF */
