// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __KSU_H_ARM64_BL_PATCH
#define __KSU_H_ARM64_BL_PATCH

#include <linux/version.h>
#include <linux/uaccess.h>
#include <asm/insn.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
#include <asm/text-patching.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#include <asm/patching.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
__weak s32 aarch64_get_branch_offset(u32 insn)
{
	// 26-bit signed relative jump offset
	// FC, D, E, F, so 3
	s32 imm26 = insn & 0x03FFFFFF;

	// in case of backward jumps
	if (imm26 & 0x02000000)
		imm26 |= 0xFC000000;

	// 4-byte word count to byte delta
	return imm26 * 4;
}
#endif

/**
 * arm64_branch_patch(): hunt and patch first b or bl insn found with target
 *
 * @target_callsite: callsite on where to start scanning for (ptr / fn_ptr)
 * @target_width: how far to scan for (bytes / ptrdiff)
 * @symbol_addr: symbol being called to look for at the site (fn_ptr)
 * @hook_addr: symbol to redirect "b symbol_addr" to (fn_ptr)
 * @type: branch type to look for. 1: b, 2: bl, 3: b or bl
 *
 * CONTEXT:
 * - do NOT call inside atomic context! (aarch64_insn_patch_text calls stop_machine)
 * - safe to run early or within kernel threads.
 *
 * NOTES:
 * - do NOT use directly! use helpers below!
 * - both symbol_addr and hook_addr must be inside +/-128MB ptrdiff to callsite! else ret -ERANGE
 * - if target bl not found within target_width, ret -ENOENT
 * - returns 0 on success.
 * - preserves instruction type (e.g., 'BL' becomes a 'BL' to the hook, and 'B' becomes a 'B' to the hook).
 * 
 */
#define BRANCH_TYPE_B		1
#define BRANCH_TYPE_BL		2
#define BRANCH_TYPE_B_OR_BL	3
static noinline int arm64_branch_patch(uintptr_t target_callsite, ptrdiff_t target_width, uintptr_t symbol_addr, uintptr_t hook_addr, uint8_t type)
{
	if (!target_callsite || !symbol_addr) {
		pr_info("%s: no callsite or symbol addr specified!\n", __func__);
		return -EINVAL;
	}

	might_sleep();

	uintptr_t start_addr = (uintptr_t)target_callsite;
	uintptr_t end_addr = start_addr + target_width;
	uintptr_t curr_addr = start_addr;
	uint32_t raw_instruction; // arm64 wordsize
	constexpr ptrdiff_t bl_max_delta = (1L << 25) * sizeof(uint32_t); // 26 bits signed * insn size

start_scan:
	if (curr_addr >= end_addr)
		goto bail;

	if (!!copy_from_kernel_nofault(&raw_instruction, (void *)curr_addr, sizeof(uint32_t)))
		goto step_up;

	// aarch64_insn_is_##abbr, arch/arm64/include/asm/insn.h
	switch (type) {
	case BRANCH_TYPE_BL:
		if (!aarch64_insn_is_bl(raw_instruction))
			goto step_up;
		break;
	case BRANCH_TYPE_B:
		if (!aarch64_insn_is_b(raw_instruction))
			goto step_up;
		break;
	case BRANCH_TYPE_B_OR_BL:
		if (!aarch64_insn_is_bl(raw_instruction) && !aarch64_insn_is_b(raw_instruction))
			goto step_up;
		break;
	default:
		return -EINVAL;
	}

	// signed
	long offset = aarch64_get_branch_offset(raw_instruction);
	uintptr_t calculated_destination = curr_addr + offset;

	if (calculated_destination != symbol_addr)
		goto step_up;

	pr_info("%s: found call site at 0x%lx\n", __func__, curr_addr);

	ptrdiff_t delta = 0;
	if (hook_addr > curr_addr)
		delta = hook_addr - curr_addr;
	else
		delta = curr_addr - hook_addr;
		
	if (delta >= bl_max_delta) {
		pr_info("%s: callsite 0x%lx to hook 0x%lx out of range! (delta: %ld bytes)\n",  __func__, curr_addr, hook_addr, delta);
		return -ERANGE;
	}

	pr_info("%s: callsite 0x%lx to hook 0x%lx inside range! (delta: %ld bytes)\n",  __func__, curr_addr, hook_addr, delta);

	uint32_t insn;
	if (aarch64_insn_is_bl(raw_instruction))
		insn = aarch64_insn_gen_branch_imm(curr_addr, hook_addr, AARCH64_INSN_BRANCH_LINK);
	else
		insn = aarch64_insn_gen_branch_imm(curr_addr, hook_addr, AARCH64_INSN_BRANCH_NOLINK);

	void *arr_addr[] = { (void*)curr_addr };
	uint32_t arr_insn[] = { insn };

	int res = aarch64_insn_patch_text(arr_addr, arr_insn, 1);
	pr_info("%s: patched callsite: 0x%lx ret: %d\n", __func__, curr_addr, res);

	return res;

step_up:
	curr_addr = curr_addr + sizeof(uint32_t);
	goto start_scan;

bail:
	pr_info("%s: callsite instruction not found!\n", __func__);
	return -ENOENT;
}

/**
 * arm64_b_patch() - hunt and patch the first b insn targeting @symbol_addr.
 * @target_callsite: callsite on where to start scanning for (ptr / fn_ptr)
 * @target_width: how far to scan for (bytes / ptrdiff)
 * @symbol_addr: symbol being called to look for at the site (fn_ptr)
 * @hook_addr: symbol to redirect "b symbol_addr" to (fn_ptr)
 */
static inline int arm64_b_patch(uintptr_t target_callsite, ptrdiff_t target_width, uintptr_t symbol_addr, uintptr_t hook_addr)
{
	return arm64_branch_patch(target_callsite, target_width, symbol_addr, hook_addr, BRANCH_TYPE_B);
}

/**
 * arm64_bl_patch() - hunt and patch the first bl insn targeting @symbol_addr.
 * @target_callsite: callsite on where to start scanning for (ptr / fn_ptr)
 * @target_width: how far to scan for (bytes / ptrdiff)
 * @symbol_addr: symbol being called to look for at the site (fn_ptr)
 * @hook_addr: symbol to redirect "b symbol_addr" to (fn_ptr)
 */
static inline int arm64_bl_patch(uintptr_t target_callsite, ptrdiff_t target_width, uintptr_t symbol_addr, uintptr_t hook_addr)
{
	return arm64_branch_patch(target_callsite, target_width, symbol_addr, hook_addr, BRANCH_TYPE_BL);
}

/**
 * arm64_b_or_bl_patch() - hunt and patch the first 'b' or 'bl' insn targeting @symbol_addr.
 * @target_callsite: callsite on where to start scanning for (ptr / fn_ptr)
 * @target_width: how far to scan for (bytes / ptrdiff)
 * @symbol_addr: symbol being called to look for at the site (fn_ptr)
 * @hook_addr: symbol to redirect "b symbol_addr" to (fn_ptr)
 */
static inline int arm64_b_or_bl_patch(uintptr_t target_callsite, ptrdiff_t target_width, uintptr_t symbol_addr, uintptr_t hook_addr)
{
	return arm64_branch_patch(target_callsite, target_width, symbol_addr, hook_addr, BRANCH_TYPE_B_OR_BL);
}

#undef BRANCH_TYPE_B
#undef BRANCH_TYPE_BL
#undef BRANCH_TYPE_B_OR_BL

#endif // __KSU_H_ARM64_BL_PATCH
