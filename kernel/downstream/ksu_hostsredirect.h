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

#ifndef __KSU_H_HOSTSREDIRECT
#define __KSU_H_HOSTSREDIRECT

static bool ksu_kernel_umount_enabled __read_mostly;

static __always_inline void ksu_hosts_file_redirect(const char __user *filename, int flags, int *fd_ptr)
{
	if (likely(test_thread_flag(TIF_KSU_UNMOUNTABLE)))
		return;

	if (likely(!ksu_module_mounted))
		return;

	if (likely(!ksu_kernel_umount_enabled))
		return;

	constexpr char hf[] = "/system/etc/hosts";

	uint64_t *hf_p = (uint64_t *)hf;
	uint64_t __user *fn_p = (uint64_t __user *)untagged_addr((void *)filename);
	__builtin_prefetch(fn_p);

	uint16_t *last_p = (uint16_t *)((char *)hf + 16);
	uint16_t buf16;
	if (likely(get_user(buf16, (uint16_t __user *)((char __user *)fn_p + 16))))
		return;

	if (likely((buf16 != *last_p)))
		return;

#ifdef CONFIG_64BIT
	uint64_t buf64;
	if (get_user(buf64, &fn_p[1]))
		return;

	if (buf64 != hf_p[1])
		return;

	if (get_user(buf64, &fn_p[0]))
		return;

	if (buf64 != hf_p[0])
		return;
#else
	char cbuf[16];
	if (copy_from_user_retry(cbuf, (void __user *)fn_p, 16))
		return;

	if (!!memcmp_inline(cbuf, hf, 16))
		return;
#endif
	//pr_info("%s: intercepting %s for comm: %s pid: %d\n", __func__, hf, current->comm, current->pid);

	const struct cred *saved = override_creds(ksu_cred);
	struct file *filp = filp_open("/data/adb/hosts", O_RDONLY, 0);
	revert_creds(saved);

	if (IS_ERR(filp))
		return;

	if (!is_compat_task() && force_o_largefile())
		flags |= O_LARGEFILE;

	int fd = get_unused_fd_flags(flags);
	if (fd < 0) {
		fput(filp);
		return;
	}

	fd_install(fd, filp);
	*fd_ptr = fd;

	return;
}

#define __AARCH64_openat 56
#define __ARMEABI_openat 322

#ifdef CONFIG_ARM64
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static syscall_fn_t aarch64_openat __read_mostly = nullptr;
extern long __arm64_sys_openat(const struct pt_regs *regs);
asmlinkage long hook_aarch64_openat(const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[1];
	int flags = (int)regs->regs[2];

	int fd = -1;
	ksu_hosts_file_redirect(filename, flags, &fd);
	if (fd != -1)
		return fd;
orig_fn:
	return __arm64_sys_openat(regs);
}

#ifdef CONFIG_COMPAT
static syscall_fn_t armeabi_openat __read_mostly = nullptr;
extern long __arm64_compat_sys_openat(const struct pt_regs *regs);
asmlinkage long hook_armeabi_openat(const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[1];
	int flags = (int)regs->regs[2];

	int fd = -1;
	ksu_hosts_file_redirect(filename, flags, &fd);
	if (fd != -1)
		return fd;
orig_fn:
	return __arm64_compat_sys_openat(regs);
}
#endif // CONFIG_COMPAT
#else /* < 4.19 */
static void *aarch64_openat __read_mostly = nullptr;
asmlinkage long hook_aarch64_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
	int fd = -1;
	ksu_hosts_file_redirect(filename, flags, &fd);
	if (fd != -1)
		return fd;
orig_fn:
	return sys_openat(dfd, filename, flags, mode);
}

#ifdef CONFIG_COMPAT
extern const void *compat_sys_call_table[];
static void *armeabi_openat __read_mostly = nullptr;
asmlinkage long hook_armeabi_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
	int fd = -1;
	ksu_hosts_file_redirect(filename, flags, &fd);
	if (fd != -1)
		return fd;
orig_fn:
	return compat_sys_openat(dfd, filename, flags, mode);
}
#endif // CONFIG_COMPAT
#endif  /* < 4.19 */

#else /* ARM */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
static syscall_fn_t armeabi_openat __read_mostly = nullptr;
extern long sys_openat(const struct pt_regs *regs);
asmlinkage long hook_armeabi_openat(const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[1];
	int flags = (int)regs->regs[2];

	int fd = -1;
	ksu_hosts_file_redirect(filename, flags, &fd);
	if (fd != -1)
		return fd;
orig_fn:
	return sys_openat(regs);
}
#else /* < 4.19 */
static void *armeabi_openat __read_mostly = nullptr;
asmlinkage long hook_armeabi_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
	int fd = -1;
	ksu_hosts_file_redirect(filename, flags, &fd);
	if (fd != -1)
		return fd;
orig_fn:
	return sys_openat(dfd, filename, flags, mode);
}
#endif /* < 4.19 */
#endif /* ARM */


static void ksu_hostsredirect_init()
{
	// we unhook at boot complete if /data/adb/hosts does not exist
	struct path kpath;
	if (!!kern_path("/data/adb/hosts", 0, &kpath))
		return;

	path_put(&kpath);
	pr_info("ksu_hostsredirect: /data/adb/hosts found! hooking sys_openat \n");
#ifdef CONFIG_ARM64
	read_and_replace_syscall((void *)&aarch64_openat, __AARCH64_openat, (void *)hook_aarch64_openat, (void *)sys_call_table);
# ifdef CONFIG_COMPAT
	read_and_replace_syscall((void *)&armeabi_openat, __ARMEABI_openat, (void *)hook_armeabi_openat, (void *)compat_sys_call_table);
# endif
#else
	read_and_replace_syscall((void *)&armeabi_openat, __AARCH64_openat, (void *)hook_armeabi_openat, (void *)sys_call_table);
#endif
	return;
}

#endif // __KSU_H_HOSTSREDIRECT
