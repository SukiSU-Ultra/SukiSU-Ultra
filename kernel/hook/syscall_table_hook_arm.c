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

#ifndef CONFIG_ARM
#error "only meant for ARM"
#endif

// ref: https://elixir.bootlin.com/linux/v4.14.1/source/include/uapi/asm-generic/unistd.h
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/arch/arm64/include/asm/unistd32.h
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/arch/arm64/include/asm/unistd.h

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

static syscall_fn_t armeabi_reboot __read_mostly = nullptr;
asmlinkage long hook_armeabi_reboot(const struct pt_regs *regs)
{
	int magic1 = (int)regs->regs[0];
	int magic2 = (int)regs->regs[1];
	unsigned int cmd = (unsigned int)regs->regs[2];
	void __user **arg = (void __user **)&regs->regs[3];

	ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
	return sys_reboot(regs);
}

static syscall_fn_t armeabi_execve __read_mostly = nullptr;
asmlinkage long hook_armeabi_execve(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[0];
	void ***argv = (void ***)&regs->regs[1];
	void ***envp = (void ***)&regs->regs[2];

	ksu_handle_sys_execve(filename, argv, envp);
	return sys_execve(regs);
}

static syscall_fn_t armeabi_execveat __read_mostly = nullptr;
asmlinkage long hook_armeabi_execveat(const struct pt_regs *regs)
{
	int *fd = (int *)&regs->regs[0];
	const char __user **filename = (const char __user **)&regs->regs[1];
	void ***argv = (void ***)&regs->regs[2];
	void ***envp = (void ***)&regs->regs[3];
	int *flags = (int *)&regs->regs[4];

	ksu_handle_sys_execveat(fd, filename, argv, envp, flags);
	return sys_execveat(regs);
}

static syscall_fn_t armeabi_faccessat __read_mostly = nullptr;
asmlinkage long hook_armeabi_faccessat(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_faccessat(NULL, filename, NULL, NULL);
	return sys_faccessat(regs);
}

static syscall_fn_t armeabi_fstatat64 __read_mostly = nullptr;
asmlinkage long hook_armeabi_fstatat64(const struct pt_regs *regs)
{
	const char __user **filename = (const char __user **)&regs->regs[1];

	ksu_handle_stat(NULL, filename, NULL);
	return sys_fstatat64(regs);
}

static syscall_fn_t armeabi_fstat64 __read_mostly = nullptr;
asmlinkage long hook_armeabi_fstat64_ret(const struct pt_regs *regs)
{
	// we handle it like rp
	unsigned long *fd = (unsigned long *)&regs->regs[0];
	struct stat64 __user **statbuf = (struct stat64 __user **)&regs->regs[1];

	long ret = sys_fstat64(regs);
	ksu_handle_fstat64_ret(fd, statbuf);
	return ret;
}

static syscall_fn_t armeabi_read __read_mostly = nullptr;
asmlinkage long hook_armeabi_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];	

	ksu_handle_sys_read_fd(fd);
	return sys_read(regs);
}

#else // END OF 4.19+ SYSCALL HANDLERS

// arch/arm/include/asm/syscall.h
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
extern const unsigned long sys_call_table[];
#else
extern void *sys_call_table[];
#endif

static void *armeabi_reboot __read_mostly = nullptr;
asmlinkage long hook_armeabi_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return sys_reboot(magic1, magic2, cmd, arg);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
static void *armeabi_execve __read_mostly = nullptr;
asmlinkage long hook_armeabi_execve(const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp)
{
	ksu_handle_sys_execve(&filename, (void ***)&argv, (void ***)&envp);
	return sys_execve(filename, argv, envp);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
__weak long sys_execveat(int fd, const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp, int flags) { return -ENOSYS; }
#endif
static void *armeabi_execveat __read_mostly = nullptr;
asmlinkage long hook_armeabi_execveat(int fd, const char __user * filename, const char __user *const __user * argv, const char __user *const __user * envp, int flags)
{
	ksu_handle_sys_execveat(&fd, &filename, (void ***)&argv, (void ***)&envp, &flags);
	return sys_execveat(fd, filename, argv, envp, flags);
}

#else /* sys_execve_oabi */ /* NOTE: execveat is not on this unless someone makes one !! */

/**
 *  on 3.0 / 3.4 ARM, sys_execve sc entry accepts 3 args (r0, r1, r2)
 *  however, sys_execve on that version, needs 4. the kernel does this small wrapper
 *  where it puts sp + 8 on r3. without it, hook won't work.
 *
 * // arch/arm/kernel/entry-common.S
 *
 * sys_execve_wrapper:
 *		add	r3, sp, #S_OFF
 *		b	sys_execve
 * ENDPROC(sys_execve_wrapper)
 *
 */
#include <asm/ptrace.h>
static void *armeabi_execve __read_mostly = nullptr;
__attribute__((used))
asmlinkage long hook_sys_execve(const char __user *filenamei, const char __user *const __user *argv, const char __user *const __user *envp, struct pt_regs *regs)
{
	ksu_handle_sys_execve(&filenamei, (void ***)&argv, (void ***)&envp);
	return sys_execve(filenamei, argv, envp, regs);
}

#define S_OFF "8"
__attribute__((naked))
asmlinkage void hook_armeabi_execve()
{
	asm volatile(
		"add r3, sp, #" S_OFF "\n"
		"b   hook_sys_execve\n"
	);
}

#endif /* sys_execve_oabi */


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

#endif // SYSCALL HANDLERS

static int ksu_syscall_table_restore(void *data)
{
	set_user_nice(current, 19); // low prio

loop_start:

	msleep(1000);

	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

	restore_syscall((void *)&armeabi_fstat64, __ARMEABI_fstat64, (void *)hook_armeabi_fstat64_ret, (void *)sys_call_table);
	restore_syscall((void *)&armeabi_read, __ARMEABI_read, (void *)hook_armeabi_read, (void *)sys_call_table);
	
	return 0;
}

static DEFINE_MUTEX(sucompat_toggle_mutex);

static void syscall_table_sucompat_enable()
{
	guarded_mutex_lock(&sucompat_toggle_mutex);

	read_and_replace_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)sys_call_table);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
	read_and_replace_syscall((void *)&armeabi_execveat, __ARMEABI_execveat, (void *)hook_armeabi_execveat, (void *)sys_call_table);
#endif
	read_and_replace_syscall((void *)&armeabi_faccessat, __ARMEABI_faccessat, (void *)hook_armeabi_faccessat, (void *)sys_call_table);
	read_and_replace_syscall((void *)&armeabi_fstatat64, __ARMEABI_fstatat64, (void *)hook_armeabi_fstatat64, (void *)sys_call_table);
}

static void syscall_table_sucompat_disable()
{
	guarded_mutex_lock(&sucompat_toggle_mutex);

	restore_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)sys_call_table);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
	restore_syscall((void *)&armeabi_execveat, __ARMEABI_execveat, (void *)hook_armeabi_execveat, (void *)sys_call_table);
#endif
	restore_syscall((void *)&armeabi_faccessat, __ARMEABI_faccessat, (void *)hook_armeabi_faccessat, (void *)sys_call_table);
	restore_syscall((void *)&armeabi_fstatat64, __ARMEABI_fstatat64, (void *)hook_armeabi_fstatat64, (void *)sys_call_table);
}

static void syscall_table_ksud_hook_init()
{
	read_and_replace_syscall((void *)&armeabi_reboot, __ARMEABI_reboot, (void *)hook_armeabi_reboot, (void *)sys_call_table);
	read_and_replace_syscall((void *)&armeabi_fstat64, __ARMEABI_fstat64, (void *)hook_armeabi_fstat64_ret, (void *)sys_call_table);
	read_and_replace_syscall((void *)&armeabi_read, __ARMEABI_read, (void *)hook_armeabi_read, (void *)sys_call_table);

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
