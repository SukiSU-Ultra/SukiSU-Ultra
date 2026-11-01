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

#ifndef __KSU_H_MODULE_BLACKLIST
#define __KSU_H_MODULE_BLACKLIST

// split with ,
#define MODULES_TO_BLOCK "ksu,kernelsu"

static int ksu_prepare_new_blacklist(uintptr_t blacklist_pptr)
{
	static_assert(sizeof(MODULES_TO_BLOCK) > 0);
	const char *modules = MODULES_TO_BLOCK;
	size_t old_len;
	if (!*(char **)blacklist_pptr)
		old_len = 0;
	else
		old_len = strlen(*(char **)blacklist_pptr);

	// + 2 for extra , and \0
	size_t new_len = old_len + strlen(modules) + 2;
	char *new_blacklist = kzalloc(new_len, GFP_KERNEL); // yeah, unfreed, not a big deal tho
	if (!new_blacklist)
		return -ENOMEM;

	if (!old_len)
		goto write_fresh;

	memcpy(new_blacklist, *(char **)blacklist_pptr, old_len);
	new_blacklist[old_len] = ',';
	memcpy(new_blacklist + old_len + 1, modules, strlen(modules));
	goto write_to_slot;

write_fresh:
	memcpy(new_blacklist, modules, strlen(modules));

write_to_slot:
	ksu_write_to_readonly_slot((uintptr_t)blacklist_pptr, (uintptr_t)new_blacklist);

	return 0;
}
#undef MODULES_TO_BLOCK

static uintptr_t ksu_read_module_blacklist()
{
	char **module_blacklist_pptr = kallsyms_lookup_name("module_blacklist");
	if (!module_blacklist_pptr)
		return 0x0;

	char *module_blacklist = *module_blacklist_pptr;
	pr_info("module_blackist: 0x%lx with %s\n", (uintptr_t)module_blacklist, module_blacklist);
	
	return module_blacklist_pptr;
}

#define __AARCH64_init_module 105
static syscall_fn_t aarch64_init_module __read_mostly = nullptr;
asmlinkage long hook_aarch64_init_module_ret(const struct pt_regs *regs)
{
	extern long __arm64_sys_init_module(const struct pt_regs *regs);
	long ret = __arm64_sys_init_module(regs);
	if (ret == -EPERM)
		return 0;
	return ret;
}

#define __AARCH64_finit_module 273
static syscall_fn_t aarch64_finit_module __read_mostly = nullptr;
asmlinkage long hook_aarch64_finit_module_ret(const struct pt_regs *regs)
{
	extern long __arm64_sys_finit_module(const struct pt_regs *regs);
	long ret = __arm64_sys_finit_module(regs);
	if (ret == -EPERM)
		return 0;
	return ret;
}

static int ksu_unhook_syscall_init_module(void *unused)
{
	set_user_nice(current, 19); // low prio
	pr_info("%s: kthread init!\n", __func__);

start:
	// watchdog will flip this anyway, we can loop forever
	if (!!*(volatile bool *)&ksu_boot_completed)
		goto cleanup;

	msleep(10000);
	goto start;

cleanup:

	restore_syscall((void *)&aarch64_init_module, __AARCH64_init_module, (void *)hook_aarch64_init_module_ret, (void *)sys_call_table);
	restore_syscall((void *)&aarch64_finit_module, __AARCH64_finit_module, (void *)hook_aarch64_finit_module_ret, (void *)sys_call_table);

	pr_info("%s: kthread exit!\n", __func__);
	return 0;
}

static inline void ksu_hook_syscall_init_module(void)
{
	read_and_replace_syscall((void *)&aarch64_init_module, __AARCH64_init_module, (void *)hook_aarch64_init_module_ret, (void *)sys_call_table);
	read_and_replace_syscall((void *)&aarch64_finit_module, __AARCH64_finit_module, (void *)hook_aarch64_finit_module_ret, (void *)sys_call_table);

	kthread_run(ksu_unhook_syscall_init_module, NULL, "kthread");
}

static noinline void ksu_extend_module_blacklist()
{
	uintptr_t blacklist_pptr = ksu_read_module_blacklist();
	if (!blacklist_pptr)
		return;

	int ret = ksu_prepare_new_blacklist(blacklist_pptr);
	if (!ret)
		pr_info("module_blackist: 0x%lx extended with %s\n", (uintptr_t)*(void **)blacklist_pptr, *(char **)blacklist_pptr);
	else
		pr_info("module_blackist: operation failed! ret: %d \n", ret);

	ksu_hook_syscall_init_module();

	return;
}

#endif // __KSU_H_MODULE_BLACKLIST
