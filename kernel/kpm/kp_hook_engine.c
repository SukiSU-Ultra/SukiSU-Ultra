// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported from KernelPatch to SukiSU-Ultra: 2025 Liankong.
 *
 * Companion to kp_hook.c. The hook engine was written assuming
 * a kpimg-style linker script that defines _transit0_end etc. to
 * bound each transit function's code; SukiSU uses the Linux
 * kbuild which has no such markers, so the static
 * `hook_chain_prepare` body in kp_hook.c (selected when
 * KP_HOOK_EXTERNAL_CHAIN_PREPARE is not defined) is compiled out
 * and this file provides the override that absolute-branches the
 * trampoline into the resident LKM copy of _transit0/4/8/12.
 */
#include <linux/types.h>
#include <linux/compiler.h>
#include <asm/cacheflush.h>
#include <linux/string.h>

#include <hook.h>

#ifndef __noinline
#define __noinline noinline
#endif

/* Declared in kp_hook.c, weak so this file can override them. */
__attribute__((weak)) uint64_t _transit0(void);
__attribute__((weak)) uint64_t _transit4(uint64_t, uint64_t, uint64_t, uint64_t);
__attribute__((weak)) uint64_t _transit8(uint64_t, uint64_t, uint64_t, uint64_t,
					 uint64_t, uint64_t, uint64_t, uint64_t);
__attribute__((weak)) uint64_t _transit12(uint64_t, uint64_t, uint64_t, uint64_t,
					  uint64_t, uint64_t, uint64_t, uint64_t,
					  uint64_t, uint64_t, uint64_t, uint64_t);

extern int32_t branch_absolute(uint32_t *buf, uint64_t addr);

static hook_err_t _unused_static_hook_chain_prepare(uint32_t *transit, int32_t argno)
{
	uint64_t target;
	hook_chain_t *chain = local_container_of(transit, hook_chain_t, transit);

	if (argno < 0 || argno > 12)
		return -HOOK_BAD_ADDRESS;
	if (argno == 0)
		target = (uint64_t)_transit0;
	else if (argno <= 4)
		target = (uint64_t)_transit4;
	else if (argno <= 8)
		target = (uint64_t)_transit8;
	else
		target = (uint64_t)_transit12;

	transit[0] = ARM64_BTI_JC;
	transit[1] = 0x58000070; /* LDR X16, #12 */
	transit[2] = 0x14000004; /* B #16 */
	transit[3] = ARM64_NOP;
	transit[4] = (uint64_t)chain;
	transit[5] = (uint64_t)chain >> 32;
	return branch_absolute(&transit[6], target) ? HOOK_NO_ERR : -HOOK_TRANSIT_NO_MEM;
}

/* kp_hook.c declares `extern hook_err_t hook_chain_prepare(...)`; we
 * provide the real (non-static) implementation here. The original
 * static version above was preserved as a code-clarity reference
 * but renamed with a leading underscore so it is intentionally
 * unused and the compiler will not warn about an unreachable
 * function. */
hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno)
{
	uint64_t target;
	hook_chain_t *chain = local_container_of(transit, hook_chain_t, transit);

	if (argno < 0 || argno > 12)
		return -HOOK_BAD_ADDRESS;
	if (argno == 0)
		target = (uint64_t)_transit0;
	else if (argno <= 4)
		target = (uint64_t)_transit4;
	else if (argno <= 8)
		target = (uint64_t)_transit8;
	else
		target = (uint64_t)_transit12;

	transit[0] = ARM64_BTI_JC;
	transit[1] = 0x58000070; /* LDR X16, #12 */
	transit[2] = 0x14000004; /* B #16 */
	transit[3] = ARM64_NOP;
	transit[4] = (uint64_t)chain;
	transit[5] = (uint64_t)chain >> 32;
	return branch_absolute(&transit[6], target) ? HOOK_NO_ERR : -HOOK_TRANSIT_NO_MEM;
}
EXPORT_SYMBOL(hook_chain_prepare);
