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
#error "only meant for ARM64"
#endif

// ref: https://elixir.bootlin.com/linux/v4.14.1/source/include/uapi/asm-generic/unistd.h
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/arch/arm64/include/asm/unistd32.h
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/arch/arm64/include/asm/unistd.h

#define __AARCH64_reboot	142
#define __AARCH64_execve	221
#define __AARCH64_execveat	281
#define __AARCH64_faccessat	48
#define __AARCH64_newfstatat	79
#define __AARCH64_newfstat	80
#define __AARCH64_read		63

// NOTE: CONFIG_COMPAT implies __ARCH_WANT_COMPAT_STAT64 (fstatat64, fstat64)
#define __ARMEABI_reboot	88
#define __ARMEABI_execve	11
#define __ARMEABI_execveat	387
#define __ARMEABI_faccessat	334
#define __ARMEABI_fstatat64	327
#define __ARMEABI_fstat64	197
#define __ARMEABI_read		3

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

// on 4.19+ its is no longer just a void *sys_call_table[]
// it becomes syscall_fn_t sys_call_table[];

extern long __arm64_sys_reboot(const struct pt_regs *regs);
static syscall_fn_t aarch64_reboot __read_mostly = nullptr; 
asmlinkage long hook_aarch64_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user **arg = (void __user **)&regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
	return __arm64_sys_reboot(regs);
}

extern long __arm64_sys_execve(const struct pt_regs *regs);
static syscall_fn_t aarch64_execve __read_mostly = nullptr;
asmlinkage long hook_aarch64_execve(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[0];
	void ***argv = (void ***)&regs->regs[1];
	void ***envp = (void ***)&regs->regs[2];

	ksu_handle_sys_execve(filename, argv, envp);
	return __arm64_sys_execve(regs);
}

extern long __arm64_sys_execveat(const struct pt_regs *regs);
static syscall_fn_t aarch64_execveat __read_mostly = nullptr;
asmlinkage long hook_aarch64_execveat(const struct pt_regs *regs)
{
	int *fd = (int *)&regs->regs[0];
	const char __user **filename = (const char __user **)&regs->regs[1];
	void ***argv = (void ***)&regs->regs[2];
	void ***envp = (void ***)&regs->regs[3];
	int *flags = (int *)&regs->regs[4];

	ksu_handle_sys_execveat(fd, filename, argv, envp, flags);
	return __arm64_sys_execveat(regs);
}

extern long __arm64_sys_faccessat(const struct pt_regs *regs);
static syscall_fn_t aarch64_faccessat __read_mostly = nullptr;
asmlinkage long hook_aarch64_faccessat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_faccessat(NULL, filename, NULL, NULL);
	return __arm64_sys_faccessat(regs);
}

extern long __arm64_sys_newfstatat(const struct pt_regs *regs);
static syscall_fn_t aarch64_newfstatat __read_mostly = nullptr;
asmlinkage long hook_aarch64_newfstatat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_stat(NULL, filename, NULL);
	return __arm64_sys_newfstatat(regs);
}

extern long __arm64_sys_newfstat(const struct pt_regs *regs);
static syscall_fn_t aarch64_newfstat __read_mostly = nullptr;
asmlinkage long hook_aarch64_newfstat_ret(const struct pt_regs *regs)
{
	// we handle it like rp
	unsigned int *fd = (unsigned int *)&regs->regs[0];
	struct stat __user **statbuf = (struct stat __user **)&regs->regs[1];

	long ret = __arm64_sys_newfstat(regs);
	ksu_handle_newfstat_ret(fd, statbuf);
	return ret;
}

extern long __arm64_sys_read(const struct pt_regs *regs);
static syscall_fn_t aarch64_read __read_mostly = nullptr;
asmlinkage long hook_aarch64_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];

	ksu_handle_sys_read_fd(fd);

	return __arm64_sys_read(regs);
}

#ifdef CONFIG_COMPAT
extern long __arm64_sys_reboot(const struct pt_regs *regs);
static syscall_fn_t armeabi_reboot __read_mostly = nullptr;
asmlinkage long hook_armeabi_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user **arg = (void __user **)&regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
	return __arm64_sys_reboot(regs);
}

extern long __arm64_compat_sys_execve(const struct pt_regs *regs);
static syscall_fn_t armeabi_execve __read_mostly = nullptr;
asmlinkage long hook_armeabi_execve(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[0];
	void ***argv = (void ***)&regs->regs[1];
	void ***envp = (void ***)&regs->regs[2];

	ksu_handle_sys_execve(filename, argv, envp);
	return __arm64_compat_sys_execve(regs);
}

extern long __arm64_compat_sys_execveat(const struct pt_regs *regs);
static syscall_fn_t armeabi_execveat __read_mostly = nullptr;
asmlinkage long hook_armeabi_execveat(const struct pt_regs *regs)
{
	int *fd = (int *)&regs->regs[0];
	const char __user **filename = (const char __user **)&regs->regs[1];
	void ***argv = (void ***)&regs->regs[2];
	void ***envp = (void ***)&regs->regs[3];
	int *flags = (int *)&regs->regs[4];

	ksu_handle_sys_execveat(fd, filename, argv, envp, flags);
	return __arm64_compat_sys_execveat(regs);
}

extern long __arm64_sys_faccessat(const struct pt_regs *regs);
static syscall_fn_t armeabi_faccessat __read_mostly = nullptr;
asmlinkage long hook_armeabi_faccessat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_faccessat(NULL, filename, NULL, NULL);
	return __arm64_sys_faccessat(regs);
}

extern long __arm64_sys_fstatat64(const struct pt_regs *regs);
static syscall_fn_t armeabi_fstatat64 __read_mostly = nullptr;
asmlinkage long hook_armeabi_fstatat64(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_stat(NULL, filename, NULL);
	return __arm64_sys_fstatat64(regs);
}

extern long __arm64_sys_fstat64(const struct pt_regs *regs);
static syscall_fn_t armeabi_fstat64 __read_mostly = nullptr;
asmlinkage long hook_armeabi_fstat64_ret(const struct pt_regs *regs)
{
	// we handle it like rp
	unsigned long *fd = (unsigned long *)&regs->regs[0];
	struct stat64 __user **statbuf = (struct stat64 __user **)&regs->regs[1];

	long ret = __arm64_sys_fstat64(regs);
	ksu_handle_fstat64_ret(fd, statbuf);
	return ret;
}

extern long __arm64_sys_read(const struct pt_regs *regs);
static syscall_fn_t armeabi_read __read_mostly = nullptr;
asmlinkage long hook_armeabi_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];	

	ksu_handle_sys_read_fd(fd);
	return __arm64_sys_read(regs);
}

#endif // CONFIG_COMPAT

#else // END OF 4.19+ SYSCALL HANDLERS

static void *aarch64_reboot __read_mostly = nullptr;
asmlinkage long hook_aarch64_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return sys_reboot(magic1, magic2, cmd, arg);
}

static void *aarch64_execve __read_mostly = nullptr;
asmlinkage long hook_aarch64_execve(const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp)
{
	ksu_handle_sys_execve(&filename, (void ***)&argv, (void ***)&envp);
	return sys_execve(filename, argv, envp);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
__weak long sys_execveat(int fd, const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp, int flags) { return -ENOSYS; }
#endif
static void *aarch64_execveat __read_mostly = nullptr;
asmlinkage long hook_aarch64_execveat(int fd, const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp, int flags)
{
	ksu_handle_sys_execveat(&fd, &filename, (void ***)&argv, (void ***)&envp, &flags);
	return sys_execveat(fd, filename, argv, envp, flags);
}

static void *aarch64_faccessat __read_mostly = nullptr;
asmlinkage long hook_aarch64_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return sys_faccessat(dfd, filename, mode);
}

static void *aarch64_newfstatat __read_mostly = nullptr;
asmlinkage long hook_aarch64_newfstatat(int dfd, const char __user * filename, struct stat __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return sys_newfstatat(dfd, filename, statbuf, flag);
}

static void *aarch64_newfstat __read_mostly = nullptr;
asmlinkage long hook_aarch64_newfstat_ret(unsigned int fd, struct stat __user * statbuf)
{
	// we handle it like rp
	long ret = sys_newfstat(fd, statbuf);
	ksu_handle_newfstat_ret(&fd, &statbuf);
	return ret;
}

static void *aarch64_read __read_mostly = nullptr;
asmlinkage long hook_aarch64_read(unsigned int fd, char __user *buf, size_t count)
{
	ksu_handle_sys_read_fd(fd);
	return sys_read(fd, buf, count);
}

#ifdef CONFIG_COMPAT
extern const void *compat_sys_call_table[];

static void *armeabi_reboot __read_mostly = nullptr;
asmlinkage long hook_armeabi_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return sys_reboot(magic1, magic2, cmd, arg);
}

static void *armeabi_execve __read_mostly = nullptr;
asmlinkage long hook_armeabi_execve(const char __user * filename,
				const compat_uptr_t __user * argv,
				const compat_uptr_t __user * envp)
{
	ksu_handle_sys_execve(&filename, (void ***)&argv, (void ***)&envp);
	return compat_sys_execve(filename, argv, envp);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
__weak long compat_sys_execveat(int fd, const char __user * filename, const compat_uptr_t __user * argv, const compat_uptr_t __user * envp, int flags) { return -ENOSYS; }
#endif
static void *armeabi_execveat __read_mostly = nullptr;
asmlinkage long hook_armeabi_execveat(int fd, const char __user * filename, const compat_uptr_t __user * argv, const compat_uptr_t __user * envp, int flags)
{
	ksu_handle_sys_execveat(&fd, &filename, (void ***)&argv, (void ***)&envp, &flags);
	return compat_sys_execveat(fd, filename, argv, envp, flags);
}

static void *armeabi_faccessat __read_mostly = nullptr;
asmlinkage long hook_armeabi_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return sys_faccessat(dfd, filename, mode);
}

static void *armeabi_fstatat64 __read_mostly = nullptr;
asmlinkage long hook_armeabi_fstatat64(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return sys_fstatat64(dfd, filename, statbuf, flag);
}

static void *armeabi_fstat64 __read_mostly = nullptr;
asmlinkage long hook_armeabi_fstat64_ret(unsigned long fd, struct stat64 __user * statbuf)
{
	// workaround for pre- torvalds/linux 54e45c169dbce43cf46d00eb1521b655b6e4f9e9
	extern typeof(hook_armeabi_fstat64_ret) sys_fstat64;

	// we handle it like rp
	long ret = sys_fstat64(fd, statbuf);
	ksu_handle_fstat64_ret(&fd, &statbuf);
	return ret;
}

static void *armeabi_read __read_mostly = nullptr;
asmlinkage long hook_armeabi_read(unsigned int fd, char __user *buf, size_t count)
{
	ksu_handle_sys_read_fd(fd);
	return sys_read(fd, buf, count);
}

#endif // CONFIG_COMPAT

#endif // SYSCALL HANDLERS

static int ksu_syscall_table_restore(void *data)
{
	set_user_nice(current, 19); // low prio

loop_start:

	msleep(1000);

	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

	restore_syscall((void *)&aarch64_newfstat, __AARCH64_newfstat, (void *)hook_aarch64_newfstat_ret, (void *)sys_call_table);
	restore_syscall((void *)&aarch64_read, __AARCH64_read, (void *)hook_aarch64_read, (void *)sys_call_table);

#if defined(CONFIG_COMPAT)
	restore_syscall((void *)&armeabi_fstat64, __ARMEABI_fstat64, (void *)hook_armeabi_fstat64_ret, (void *)compat_sys_call_table);
	restore_syscall((void *)&armeabi_read, __ARMEABI_read, (void *)hook_armeabi_read, (void *)compat_sys_call_table);
#endif
	
	return 0;
}

static DEFINE_MUTEX(sucompat_toggle_mutex);

static void syscall_table_sucompat_enable()
{
	guarded_mutex_lock(&sucompat_toggle_mutex);

	read_and_replace_syscall((void *)&aarch64_execve, __AARCH64_execve, (void *)hook_aarch64_execve, (void *)sys_call_table);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0) || defined(__NR_execveat)
	read_and_replace_syscall((void *)&aarch64_execveat, __AARCH64_execveat, (void *)hook_aarch64_execveat, (void *)sys_call_table);
#endif
	read_and_replace_syscall((void *)&aarch64_faccessat, __AARCH64_faccessat, (void *)hook_aarch64_faccessat, (void *)sys_call_table);
	read_and_replace_syscall((void *)&aarch64_newfstatat, __AARCH64_newfstatat, (void *)hook_aarch64_newfstatat, (void *)sys_call_table);

#if defined(CONFIG_COMPAT)
	read_and_replace_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)compat_sys_call_table);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0) || defined(__NR_execveat)
	read_and_replace_syscall((void *)&armeabi_execveat, __ARMEABI_execveat, (void *)hook_armeabi_execveat, (void *)compat_sys_call_table);
#endif
	read_and_replace_syscall((void *)&armeabi_faccessat, __ARMEABI_faccessat, (void *)hook_armeabi_faccessat, (void *)compat_sys_call_table);
	read_and_replace_syscall((void *)&armeabi_fstatat64, __ARMEABI_fstatat64, (void *)hook_armeabi_fstatat64, (void *)compat_sys_call_table);
#endif

}

static void syscall_table_sucompat_disable()
{
	guarded_mutex_lock(&sucompat_toggle_mutex);

	restore_syscall((void *)&aarch64_execve, __AARCH64_execve, (void *)hook_aarch64_execve, (void *)sys_call_table);
	restore_syscall((void *)&aarch64_execveat, __AARCH64_execveat, (void *)hook_aarch64_execveat, (void *)sys_call_table);
	restore_syscall((void *)&aarch64_faccessat, __AARCH64_faccessat, (void *)hook_aarch64_faccessat, (void *)sys_call_table);
	restore_syscall((void *)&aarch64_newfstatat, __AARCH64_newfstatat, (void *)hook_aarch64_newfstatat, (void *)sys_call_table);

#if defined(CONFIG_COMPAT)
	restore_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)compat_sys_call_table);
	restore_syscall((void *)&armeabi_execveat, __ARMEABI_execveat, (void *)hook_armeabi_execveat, (void *)compat_sys_call_table);
	restore_syscall((void *)&armeabi_faccessat, __ARMEABI_faccessat, (void *)hook_armeabi_faccessat, (void *)compat_sys_call_table);
	restore_syscall((void *)&armeabi_fstatat64, __ARMEABI_fstatat64, (void *)hook_armeabi_fstatat64, (void *)compat_sys_call_table);
#endif
}

static void syscall_table_ksud_hook_init()
{
	read_and_replace_syscall((void *)&aarch64_reboot, __AARCH64_reboot, (void *)hook_aarch64_reboot, (void *)sys_call_table);
	read_and_replace_syscall((void *)&aarch64_newfstat, __AARCH64_newfstat, (void *)hook_aarch64_newfstat_ret, (void *)sys_call_table);
	read_and_replace_syscall((void *)&aarch64_read, __AARCH64_read, (void *)hook_aarch64_read, (void *)sys_call_table);

#if defined(CONFIG_COMPAT)
	read_and_replace_syscall((void *)&armeabi_reboot, __ARMEABI_reboot, (void *)hook_armeabi_reboot, (void *)compat_sys_call_table);
	read_and_replace_syscall((void *)&armeabi_fstat64, __ARMEABI_fstat64, (void *)hook_armeabi_fstat64_ret, (void *)compat_sys_call_table);
	read_and_replace_syscall((void *)&armeabi_read, __ARMEABI_read, (void *)hook_armeabi_read, (void *)compat_sys_call_table);
#endif // COMPAT

	// start unreg kthread
	kthread_run(ksu_syscall_table_restore, NULL, "unhook");
}

static __init int ksu_syscall_table_hook_init()
{
	// enable on init!
	syscall_table_sucompat_enable();
	syscall_table_ksud_hook_init();

	return 0;
}

// EOF
