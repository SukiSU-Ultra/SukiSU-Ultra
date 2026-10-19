// SPDX-License-Identifier: GPL-2.0
/*
 * Hot-patch infrastructure for signature-fallback support.
 *
 * When a third-party manager is registered through dynamic_manager and the
 * APK's package name does NOT match the compiled KSU_PACKAGE_NAME, we need
 * to allow non-matching packages to reach is_manager_apk() so they can be
 * authenticated via (cert_size, hash) lookup.
 *
 * Two target functions are patched via inline-assembly trampolines:
 *   1. maybe_manager_apk_dir  — bypass the KSU_PACKAGE_NAME filter.
 *   2. is_manager_apk        — try compiled EXPECTED_SIZE/HASH first, then
 *                              fall back to the dynamic_manager table.
 *
 * Architecture trampoline sizes (see hot_patch.c for rationale):
 *   ARM64   : 64 bytes
 *   x86_64  : 48 bytes
 *   others  : unsupported, install refused at runtime
 */

#ifndef __KSU_H_HOT_PATCH
#define __KSU_H_HOT_PATCH

#include <linux/types.h>

int install_signature_fallback_hot_patch(void);
void remove_signature_fallback_hot_patch(void);

#endif /* __KSU_H_HOT_PATCH */
