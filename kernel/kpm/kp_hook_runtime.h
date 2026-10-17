/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported from KernelPatch to SukiSU-Ultra: 2025 Liankong.
 *
 * Runtime backends required by kp_hook.c (the inline-hook engine
 * ported from kernel/base/hook.c). Provides:
 *
 *   - hook_mem_zalloc / hook_get_mem_from_origin / hook_mem_free
 *     used to allocate executable memory for the trampolines and
 *     the per-hooked-function `hook_t` / `hook_chain_t` records.
 *   - hotpatch() which calls SukiSU's ksu_patch_text() under the
 *     appropriate flags (KP_PATCH_TEXT_FLUSH_DCACHE / _ICACHE).
 *
 * Differences from the upstream KP LKM hook_runtime.c:
 *   - The KP-specific kp_resolve_symbol helper is replaced with a
 *     direct kallsyms_lookup_name() (SukiSU has no custom symbol
 *     table at runtime; modules resolve their own ksymtab entries
 *     the same way the rest of the kernel does).
 *   - The KP_PATCH_TEXT_FLUSH_DCACHE / KP_PATCH_TEXT_FLUSH_ICACHE
 *     flag bits are mapped to SukiSU's KSU_PATCH_TEXT_* bits.
 */

#ifndef _SUKISU_KP_HOOK_RUNTIME_H_
#define _SUKISU_KP_HOOK_RUNTIME_H_

#include <linux/types.h>
#include <hook.h>

#define KP_PATCH_TEXT_FLUSH_DCACHE 1
#define KP_PATCH_TEXT_FLUSH_ICACHE 2

void *hook_mem_zalloc(uintptr_t origin, enum hook_type type);
void *hook_get_mem_from_origin(uint64_t origin);
void hook_mem_free(void *payload);

int hotpatch(void *addrs[], uint32_t values[], int count);

int kp_hook_runtime_init(void);

#endif /* _SUKISU_KP_HOOK_RUNTIME_H_ */
