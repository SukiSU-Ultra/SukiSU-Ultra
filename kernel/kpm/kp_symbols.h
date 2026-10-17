/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Liankong. All Rights Reserved.
 * Ported from KernelPatch to SukiSU-Ultra: 2025 Liankong.
 *
 * KPM-ABI symbol compatibility layer for SukiSU-Ultra. Header
 * counterpart of kp_symbols.c, which is the verbatim port of
 * KernelPatch's lkm/kpm/symbols.c.
 *
 * Symbol groups exposed through the table:
 *
 *  1. Kernel base symbols (printk, compat_copy_to_user, ...)
 *     - printk is a statement-expression macro on every supported
 *       GKI tree, so the table publishes the address of a function
 *       pointer variable slot. KPM code declares `extern int
 *       (*printk)(...)` and calls through the slot, which is exactly
 *       the indirection KernelPatch uses.
 *
 *  2. KP internal offset structs (task_struct_offset, mm_struct_offset)
 *     and scalar constants (thread_size, sp_el0_is_current,
 *     stack_in_task_offset, cred_offset, ...) - published as addresses
 *     of storage cells that the KPM ABI dereferences.
 *
 *  3. KP helper functions (kf_memcpy, kf_memset, kf_snprintf, ...)
 *     - thin wrappers around the kernel's own implementations.
 *
 *  4. KP hooking API (hook_wrap, hook_chain_add, hook_prepare, ...)
 *     - the actual implementation lives in kp_hook.c (ported from
 *       kernel/base/hook.c). The public declarations are in
 *       <hook.h>.
 */

#ifndef _SUKISU_KP_COMPAT_H_
#define _SUKISU_KP_COMPAT_H_

#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/compiler.h>

/*
 * KP version macros - some modules check these at load time.
 * We claim KP 0.13.3 (LKM v0.13.3) compatibility, matching the
 * upstream KernelPatch release line so KPMs compiled against either
 * runtime see the same kpver value.
 */
#define KP_VERSION_MAJOR 0
#define KP_VERSION_MINOR 13
#define KP_VERSION_PATCH 3
#define KP_VERSION ((KP_VERSION_MAJOR << 16) | (KP_VERSION_MINOR << 8) | KP_VERSION_PATCH)

/* Init function (called by module.c::kpm_module_init). */
extern int kp_compat_init(void);

/* Centralized KPM symbol lookup.
 * Called by module.c::simplify_symbols as the first-tier resolver
 * for KPM-ABI symbols. Returns the address the KPM loader should
 * patch into the SHN_UNDEF slot, or 0 if the name is not handled
 * by the compat layer (the loader then falls back to kallsyms). */
extern unsigned long sukisu_kpm_symbol_lookup(const char *name);

#endif /* _SUKISU_KP_COMPAT_H_ */
