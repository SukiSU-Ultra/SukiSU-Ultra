/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION_KPM_GLUE
#define __KSU_H_EXTENSION_KPM_GLUE

#include <linux/types.h>

#include "extension.h"

/* KPM extension glue (extension/kpm.c). Sticky state + io passthrough
 * to the actual KPM control surface (extension/kpm/kpm.c). Built
 * unconditionally so extension/extension.c can reference the symbols
 * regardless of CONFIG_KPM. */
int ksu_extension_kpm_get(u32 id, u64 *value);
int ksu_extension_kpm_set(u32 id, u64 value);
int ksu_extension_kpm_io(u32 id, void __user *raw);

extern const struct ksu_extension_handler_ops ksu_extension_kpm_ops;

#endif /* __KSU_H_EXTENSION_KPM_GLUE */
