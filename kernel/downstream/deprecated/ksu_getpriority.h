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

#ifndef __KSU_H_GETPRIORITY_FILTER
#define __KSU_H_GETPRIORITY_FILTER

// an array of 8 bits
static uint8_t *gp_package_bitmap __read_mostly = nullptr;

// we want 10000 bits
// app uid = 10000, means bit 0
// app uid = 10001, means bit 1
#define gp_bitmap_bits	10000
#define gp_alloc_size	((gp_bitmap_bits + 7) / 8)

static_assert(sizeof(*gp_package_bitmap) == 1);

static __always_inline bool gp_test_package_bit(int uid)
{
	assume_dereferenceable(gp_package_bitmap, gp_alloc_size);
	if (uid > 20000 || uid < 10000)
		return false;

	int uid_offset = uid - 10000;

	int byte_idx = uid_offset / 8;
	int bit_idx = uid_offset % 8;

	// see if bit is set, go to index, & mask to teh array
	return !!(gp_package_bitmap[byte_idx] & (1 << bit_idx));
}

void gp_set_package_bit(int uid)
{
	assume_dereferenceable(gp_package_bitmap, gp_alloc_size);
	if (uid > 20000)
		return;

	if (uid < 10000)
		return;

	int uid_offset = uid - 10000;

	int byte_idx = uid_offset / 8;
	int bit_idx  = uid_offset % 8;
	gp_package_bitmap[byte_idx] |= (1U << bit_idx);

	pr_info("ksu_getpriority: %s: %d is set! \n", __func__, uid);
	kick_all_cpus_sync();
}

void gp_reset_bitmap(void)
{
	assume_dereferenceable(gp_package_bitmap, gp_alloc_size);
	memzero_explicit(gp_package_bitmap, gp_alloc_size);
	pr_info("ksu_getpriority: %s: bitmap reser \n", __func__);
	kick_all_cpus_sync();
}

static __always_inline bool ksu_getpriority_should_swap(int which, int who)
{
	// return if not unmountable
	if (!test_thread_flag(TIF_KSU_UNMOUNTABLE))
		return false;

	// only filter appuid calls
	int cuid = current_uid().val;
	if (unlikely(cuid < 10000))
		return false;

	// try to equalize memory load to all
	__builtin_prefetch(gp_package_bitmap);
	barrier();

	if (which != 2)
		return false;

	if (cuid == who)
		return false;

	if (who < 10000)
		return false;

	if (who >= 20000)
		return false;

//	pr_info("ksu_getpriority: caller: %d paramms: %d / %d comm: %s \n", current_uid().val, which, who, current->comm);

	if (!gp_test_package_bit(who))
		return false;
		
	pr_info("ksu_getpriority: uid: %d is set! \n", who);
	return true;
}

#define __AARCH64_getpriority 141
#define __ARMEABI_getpriority 96

#ifdef CONFIG_ARM64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static syscall_fn_t aarch64_getpriority __read_mostly = nullptr;
asmlinkage long hook_aarch64_getpriority(const struct pt_regs *regs)
{
	extern typeof(hook_aarch64_getpriority) __arm64_sys_getpriority;

	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!ksu_getpriority_should_swap(which, *p_who))
		*p_who = 99999;

	return __arm64_sys_getpriority(regs);
}
#ifdef CONFIG_COMPAT
static syscall_fn_t armeabi_getpriority __read_mostly = nullptr;
asmlinkage long hook_armeabi_getpriority(const struct pt_regs *regs)
{
	extern typeof(hook_armeabi_getpriority) __arm64_sys_getpriority;

	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!ksu_getpriority_should_swap(which, *p_who))
		*p_who = 99999;

	return __arm64_sys_getpriority(regs);
}
#endif	// compat
#else	/* < 4.19 */
static void *aarch64_getpriority __read_mostly = nullptr;
asmlinkage long hook_aarch64_getpriority(int which, int who)
{
	int new_who = who;
	
	if (!!ksu_getpriority_should_swap(which, who))
		new_who = 99999;

	return sys_getpriority(which, new_who);
}
#ifdef CONFIG_COMPAT
static void *armeabi_getpriority __read_mostly = nullptr;
asmlinkage long hook_armeabi_getpriority(int which, int who)
{
	int new_who = who;
	
	if (!!ksu_getpriority_should_swap(which, who))
		new_who = 99999;

	return sys_getpriority(which, new_who);
}
#endif	// compat
#endif	/* < 4.19 */

#else	/* ! CONFIG_ARM64 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static syscall_fn_t armeabi_getpriority __read_mostly = nullptr;
asmlinkage long hook_armeabi_getpriority(const struct pt_regs *regs)
{
	extern typeof(hook_armeabi_getpriority) sys_getpriority;

	int which = regs->regs[0];
	int *p_who = (int *)&regs->regs[1];

	if (!!ksu_getpriority_should_swap(which, *p_who))
		*p_who = 99999;

	return sys_getpriority(regs);
}
#else	/* < 4.19 */
static void *armeabi_getpriority __read_mostly = nullptr;
asmlinkage long hook_armeabi_getpriority(int which, int who)
{
	int new_who = who;
	
	if (!!ksu_getpriority_should_swap(which, who))
		new_who = 99999;

	return sys_getpriority(which, new_who);
}
#endif	/* < 4.19 */
#endif	/* ! CONFIG_ARM64 */

static void ksu_getpriority_init()
{
	static_assert(PAGE_SIZE > gp_alloc_size);

	gp_package_bitmap = get_zeroed_page(GFP_KERNEL | __GFP_NOFAIL);
	pr_info("ksu_getpriority: page allocated at: 0x%lx, %u / %u bytes\n", (uintptr_t)gp_package_bitmap, gp_alloc_size, PAGE_SIZE);

#ifdef CONFIG_ARM64
	read_and_replace_syscall((void *)&aarch64_getpriority, __AARCH64_getpriority, (void *)hook_aarch64_getpriority, (void *)sys_call_table);
#ifdef CONFIG_COMPAT
	read_and_replace_syscall((void *)&armeabi_getpriority, __ARMEABI_getpriority, (void *)hook_armeabi_getpriority, (void *)compat_sys_call_table);
#endif
#else
	read_and_replace_syscall((void *)&armeabi_getpriority, __ARMEABI_getpriority, (void *)hook_armeabi_getpriority, (void *)sys_call_table);
#endif

	return;
}

#endif // __KSU_H_GETPRIORITY_FILTER
