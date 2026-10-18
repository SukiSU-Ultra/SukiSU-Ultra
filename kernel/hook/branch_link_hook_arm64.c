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

#ifndef CONFIG_ARM64
#error "only meant for ARM64!"
#endif

/**
 *  branch_link_hook_arm64.c - inline callsite hooking for ARM64
 *
 *  tested to work on:
 *	- 3.10 ~ 4.14 (partially, no do_faccessat)
 *	- 4.19 ~ 6.12 GKI
 *	- mainline (as of 7.1.3)
 *
 *  Changelog:
 *	- init, 260524
 *	- partial/probably-broken 4.19/5.4 compat, 260525
 *	- fixups for 4.19 ~ 6.6 CFI, resolve symbols via kprobe. (260630)
 *	- optimize ksu_vfs_statx (260630)
 *	- wire up basic pre-4.17 support, however do_faccessat is still needed (260722)
 *	- also patch our hooksite, removes blr overhead compared to function pointers (260725)
 *	- smaller stub code (260728)
 *	- smaller stub code p.2, gcc fix, thx to lh_mouse @ #gcc (260728)
 *	- limit insn scan to symbol size or 32 insn (260809)
 *	- recurse. have the hook call itself and patch that branch it makes to itself. (261017)
 *
 * NOTES:
 *	- not everyone is expected to understand how this works.
 *	- we do NOT modify fn entry, we modify the caller's jump. CFI won't panic if it cannot see.
 *	- we also went crazy to the point we patch ourselves.
 *	- we hook syscall table, if patching is successful, we unhook our syscall table hook like nothing happened.
 *
 * ---
 * Dear Clang kCFI,
 * 	This is NOT an indirect call, it's just a very normal branch. ;)
 *
 */

#if defined(__GNUC__) && !defined(__clang__)
#define KEEP_SYMBOL_NO_TAIL __attribute__((used)) noinline __attribute__((optimize("no-optimize-sibling-calls")))
#else
#define KEEP_SYMBOL_NO_TAIL __attribute__((used)) noinline __attribute__((disable_tail_calls))
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Winfinite-recursion"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || defined(KSU_HAS_FACCESSAT2)
KEEP_SYMBOL_NO_TAIL long ksu_do_faccessat(int dfd, const char __user *filename, int mode, int flags)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return ksu_do_faccessat(dfd, filename, mode, flags);
}
#else
KEEP_SYMBOL_NO_TAIL long ksu_do_faccessat(int dfd, const char __user *filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return ksu_do_faccessat(dfd, filename, mode);
}
#endif // 5.7+ || faccessat2

// vfs_statx, vfs_fstatat
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0) || defined(KSU_HAS_VFS_STATX2)
/**
 * on 6.1 kernels vfs_fstatat calls can get inlined, so we have to also look for vfs_statx
 * actually overloading on do_statx is possible instead of this ifdef, see torvalds/linux 1b6fe6e0dfe
 * but we already scan for something like faccessat2 so nbd for now.
 */
KEEP_SYMBOL_NO_TAIL int ksu_vfs_statx(int dfd, struct filename *restrict filename, int flags, struct kstat *restrict stat, u32 request_mask)
{
	if (likely(IS_ERR(filename)))
		goto orig_fn;

	char *filename_ptr = (char *)filename->name;
	if (likely(!is_su_allowed((const void **)&filename_ptr)))
		goto orig_fn;

	// see sucompat.c
	constexpr char su[16] = SU_PATH;
	uint64_t *su_p = (uint64_t *)su;
	uint64_t *fn_p = (uint64_t *)filename_ptr;

	// getname_flags pads this so nothing to worry about
	assume_restricted((void *)su_p, (void *)fn_p);
	assume_dereferenceable((void *)fn_p, 16);

	// https://godbolt.org/z/j8Yovv6bE
	if (likely((fn_p[1] & 0x00FFFFFFFFFFFFFFULL) != (su_p[1] & 0x00FFFFFFFFFFFFFFULL)))
		goto orig_fn;

	if (unlikely(fn_p[0] != su_p[0]))
		goto orig_fn;

	write_sulog('s');
	pr_info("su_compat: vfs_statx su->sh!%s\n", (is_compat_task()) ? " [compat]" : "" );
	constexpr char sh[16] = SH_PATH;
	memcpy_inline(filename_ptr, sh, sizeof(sh));

orig_fn:
	return ksu_vfs_statx(dfd, filename, flags, stat, request_mask);
}
#else
KEEP_SYMBOL_NO_TAIL int ksu_vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return ksu_vfs_statx(dfd, filename, flags, stat, request_mask);
}
#endif // >= 5.18

KEEP_SYMBOL_NO_TAIL int ksu_vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
{
	ksu_handle_stat(&dfd, &filename, &flags);
	return ksu_vfs_fstatat(dfd, filename, stat, flags);
}

// execve
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
KEEP_SYMBOL_NO_TAIL int ksu_do_execveat_common(int fd, struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags)
{
	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return ksu_do_execveat_common(fd, filename, argv, envp, flags);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
KEEP_SYMBOL_NO_TAIL int ksu_do_execve_file(int fd, struct filename *restrict filename, struct user_arg_ptr argv, struct user_arg_ptr envp, int flags, struct file *restrict file)
{
	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return ksu_do_execve_file(fd, filename, argv, envp, flags, file);
}
#endif // < 5.9

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
KEEP_SYMBOL_NO_TAIL int ksu_do_execve_common(struct filename *filename, struct user_arg_ptr argv, struct user_arg_ptr envp)
{
	ksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);
	return ksu_do_execve_common(filename, argv, envp);
}
#endif // < 3.19

#else /* < 3.14 */

KEEP_SYMBOL_NO_TAIL int ksu_do_execve_common(const char *filename, struct user_arg_ptr argv, struct user_arg_ptr envp)
{
	ksu_legacy_execve_sucompat(&filename, &argv, &envp);
	return ksu_do_execve_common(filename, argv, envp);
}
#endif

#pragma GCC diagnostic pop
#undef KEEP_SYMBOL_NO_TAIL

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define syscall_lookup(name) kallsyms_lookup_retry("__arm64_" name)
#else
#define syscall_lookup(name) kallsyms_lookup_retry(name)
#endif

#ifdef CONFIG_MODULES
#define kernel_function_lookup(name) kallsyms_lookup_retry(#name)
#else
#define kernel_function_lookup(name) ({ 						\
	pr_info("kernel_function_lookup: %s addr: 0x%lx\n", #name, (uintptr_t)&name);	\
	(uintptr_t)&name; 								\
})
#endif

#define ksu_get_ksym_size32(addr)	ksu_get_ksym_size(addr, (32 * sizeof(uint32_t)))

// patch the first call of the hook to itself
#define ksu_self_patch_hook(hook_fn, tgt) ({							\
	uintptr_t hook_p = kernel_function_lookup(hook_fn);					\
	int ret = arm64_b_or_bl_patch(hook_p, ksu_get_ksym_size32(hook_p), hook_p, tgt);	\
	pr_info("patch_hook: %s ret: %d \n", #hook_fn, ret);					\
	ret;											\
})

static int bl_hook_faccessat(void *data)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

	target_callsite = syscall_lookup("sys_faccessat");
	symbol_addr = kallsyms_lookup_retry("do_faccessat");
	if (!symbol_addr)
		return -ENOENT;

	// patch our hook handler first
	ret = ksu_self_patch_hook(ksu_do_faccessat, symbol_addr);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_do_faccessat);
	pr_info("hook_site: sys_faccessat->do_faccessat ret: %d \n", ret);
	if (!ret)
		goto unhook_sct;

	return ret;

unhook_sct:
	restore_syscall((void *)&aarch64_faccessat, __AARCH64_faccessat, (void *)hook_aarch64_faccessat, (void *)sys_call_table);
#if defined(CONFIG_COMPAT)
	restore_syscall((void *)&armeabi_faccessat, __ARMEABI_faccessat, (void *)hook_armeabi_faccessat, (void *)compat_sys_call_table);
#endif
	return ret;
}

static int bl_hook_newfstatat(void *data)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

	target_callsite = syscall_lookup("sys_newfstatat");
	symbol_addr = kallsyms_lookup_retry("vfs_statx");
	if (!symbol_addr)
		goto hook2;

	// patch our hook handler first
	ret = ksu_self_patch_hook(ksu_vfs_statx, symbol_addr);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_vfs_statx);
	pr_info("hook_site: sys_newfstatat->vfs_statx ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;

hook2:
	symbol_addr = kallsyms_lookup_retry("vfs_fstatat");
	if (!symbol_addr)
		return -ENOENT;

	// patch our hook handler first
	ret = ksu_self_patch_hook(ksu_vfs_fstatat, symbol_addr);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_vfs_fstatat);
	pr_info("hook_site: sys_newfstatat->vfs_fstatat ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;

	return ret;

unhook_sct_native:
	restore_syscall((void *)&aarch64_newfstatat, __AARCH64_newfstatat, (void *)hook_aarch64_newfstatat, (void *)sys_call_table);

#ifdef CONFIG_COMPAT
	target_callsite = syscall_lookup("sys_fstatat64");
	symbol_addr = kallsyms_lookup_retry("vfs_statx");
	if (!symbol_addr)
		goto hook2c;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_vfs_statx);
	pr_info("hook_site: sys_fstatat64->vfs_statx ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;

hook2c:
	symbol_addr = kallsyms_lookup_retry("vfs_fstatat");
	if (!symbol_addr)
		return -ENOENT;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_vfs_fstatat);
	pr_info("hook_site: sys_fstatat64->vfs_fstatat ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;

	return ret;

unhook_sct_compat:
	restore_syscall((void *)&armeabi_fstatat64, __ARMEABI_fstatat64, (void *)hook_armeabi_fstatat64, (void *)compat_sys_call_table);
#endif // CONFIG_COMPAT

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
static int bl_hook_execve(void *data)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t target_callsite2;
	uintptr_t symbol_addr;

	target_callsite = syscall_lookup("sys_execve");
	target_callsite2 = syscall_lookup("sys_execveat");

	symbol_addr = kallsyms_lookup_retry("do_execveat_common");
	if (!symbol_addr)
		goto hook2;

	// patch our hook handler first
	ret = ksu_self_patch_hook(ksu_do_execveat_common, symbol_addr);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_do_execveat_common);
	pr_info("hook_site: sys_execve->do_execveat_common ret: %d \n", ret);
	if (!ret && !!target_callsite2) {
		ret = arm64_b_or_bl_patch(target_callsite2, ksu_get_ksym_size32(target_callsite2), symbol_addr, (uintptr_t)&ksu_do_execveat_common);
		pr_info("hook_site: sys_execveat->do_execveat_common ret: %d \n", ret);
	}
	if (!ret)
		goto unhook_sct_native;

hook2:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
	symbol_addr = kallsyms_lookup_retry("__do_execve_file");
	if (!symbol_addr)
		goto hook3;

	// patch our hook handler first
	ret = ksu_self_patch_hook(ksu_do_execve_file, symbol_addr);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_do_execve_file);
	pr_info("hook_site: sys_execve->__do_execve_file ret: %d \n", ret);
	if (!ret && !!target_callsite2) {
		ret = arm64_b_or_bl_patch(target_callsite2, ksu_get_ksym_size32(target_callsite2), symbol_addr, (uintptr_t)&ksu_do_execve_file);
		pr_info("hook_site: sys_execveat->__do_execve_file ret: %d \n", ret);
	}
	if (!ret)
		goto unhook_sct_native;
#endif // < 5.9
hook3:
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	symbol_addr = kallsyms_lookup_retry("do_execve_common"); // this symbol doesn't handle execveat
	if (!symbol_addr)
		return -ENOENT;

	// patch our hook handler first
	ret = ksu_self_patch_hook(ksu_do_execve_common, symbol_addr);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_do_execve_common);
	pr_info("hook_site: sys_execve->do_execve_common ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;
#endif // < 3.19

unhook_sct_native:
	restore_syscall((void *)&aarch64_execve, __AARCH64_execve, (void *)hook_aarch64_execve, (void *)sys_call_table);
	restore_syscall((void *)&aarch64_execveat, __AARCH64_execveat, (void *)hook_aarch64_execveat, (void *)sys_call_table);

#ifdef CONFIG_COMPAT
	target_callsite = syscall_lookup("compat_sys_execve");
	target_callsite2 = syscall_lookup("compat_sys_execveat");

	symbol_addr = kallsyms_lookup_retry("do_execveat_common");
	if (!symbol_addr)
		goto hook2c;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_do_execveat_common);
	pr_info("hook_site: compat_sys_execve->do_execveat_common ret: %d \n", ret);
	if (!ret && !!target_callsite2) {
		ret = arm64_b_or_bl_patch(target_callsite2, ksu_get_ksym_size32(target_callsite2), symbol_addr, (uintptr_t)&ksu_do_execveat_common);
		pr_info("hook_site: compat_sys_execveat->do_execveat_common ret: %d \n", ret);
	}
	if (!ret)
		goto unhook_sct_compat;

hook2c:
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
	symbol_addr = kallsyms_lookup_retry("__do_execve_file");
	if (!symbol_addr)
		goto hook3c;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_do_execve_file);
	pr_info("hook_site: compat_sys_execve->__do_execve_file ret: %d \n", ret);
	if (!ret && !!target_callsite2) {
		ret = arm64_b_or_bl_patch(target_callsite2, ksu_get_ksym_size32(target_callsite2), symbol_addr, (uintptr_t)&ksu_do_execve_file);
		pr_info("hook_site: compat_sys_execveat->__do_execve_file ret: %d \n", ret);
	}
	if (!ret)
		goto unhook_sct_compat;
#endif // < 5.9
hook3c:
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	symbol_addr = kallsyms_lookup_retry("do_execve_common");
	if (!symbol_addr)
		return -ENOENT;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_do_execve_common);
	pr_info("hook_site: compat_sys_execve->do_execve_common ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;
#endif // < 3.19

unhook_sct_compat:
	restore_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)compat_sys_call_table);
	restore_syscall((void *)&armeabi_execveat, __ARMEABI_execveat, (void *)hook_armeabi_execveat, (void *)compat_sys_call_table);
#endif // COMPAT
	return ret;
}
#else /* < 3.14 */
static int bl_hook_execve(void *data)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

	target_callsite = syscall_lookup("sys_execve");
	symbol_addr = kallsyms_lookup_retry("do_execve_common");
	if (!symbol_addr)
		return -ENOENT;

	// patch our hook handler first
	ret = ksu_self_patch_hook(ksu_do_execve_common, symbol_addr);
	if (ret)
		return ret;

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_do_execve_common);
	pr_info("hook_site: sys_execve->do_execve_common ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_native;

	return ret;

unhook_sct_native:
	restore_syscall((void *)&aarch64_execve, __AARCH64_execve, (void *)hook_aarch64_execve, (void *)sys_call_table);

#ifdef CONFIG_COMPAT
	target_callsite = syscall_lookup("compat_sys_execve");

	ret = arm64_b_or_bl_patch(target_callsite, ksu_get_ksym_size32(target_callsite), symbol_addr, (uintptr_t)&ksu_do_execve_common);
	pr_info("hook_site: compat_sys_execve->do_execve_common ret: %d \n", ret);
	if (!ret)
		goto unhook_sct_compat;

	return ret;

unhook_sct_compat:
	restore_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)compat_sys_call_table);
#endif

	return ret;
}
#endif

#undef ksu_self_patch_hook
#undef kernel_function_lookup
#undef syscall_lookup
#undef ksu_get_ksym_size32

static int bl_hack_init_thread(void *data)
{
	set_user_nice(current, 19); // low prio

	bool faccessat = !!!bl_hook_faccessat(data);
	bool newfstatat = !!!bl_hook_newfstatat(data);
	bool execve = !!!bl_hook_execve(data);

	pr_info("branch_link: done! faccessat: %s newfstatat: %s execve: %s\n", (faccessat) ? "ok" : "fail", (newfstatat) ? "ok" : "fail", (execve) ? "ok" : "fail");

	dotted_kallsyms_destroy_hash_array();

	return 0;
}

static int ksu_branch_link_patch_init()
{
	// enable sct first, if branch link succeeds, it will be restored
	syscall_table_ksud_hook_init();
	syscall_table_sucompat_enable();

	/**
	 *  we move sucompat hook initialization to a kthread
	 *  due to it falling back to a bruteforce ksym lookup if !kprobes
	 *  it somewhat takes 0.5 ~ 1s to scan whole kernel _stext to _etext
	 *  so this better be offloaded
	 */
	kthread_run(bl_hack_init_thread, NULL, "kthread");

	return 0;
}
