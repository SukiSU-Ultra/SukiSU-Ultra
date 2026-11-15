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

#if !defined(CONFIG_ARM64)
#error "automated LSM hooking on 6.8+ is only for ARM64!"
#endif

#if !defined(CONFIG_KALLSYMS)
#error "automated LSM hooking on 6.8+ requires kallsyms!"
#endif

// security.c hijack for 6.8+

extern int vfs_rename(struct renamedata *rd);
static int ksu_vfs_rename(struct renamedata *rd)
{
	int ret = vfs_rename(rd);
	if (!ret)
		ksu_rename_observer(rd->old_dentry, rd->new_dentry);

	return ret;
}

extern int security_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags);
static int ksu_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return security_inode_rename(old_dir, old_dentry, new_dir, new_dentry, flags);
}

#if 0 // setuid
extern int security_task_fix_setuid(struct cred *new, const struct cred *old, int flags);
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return security_task_fix_setuid(new, old, flags);
}
#endif

#define __AARCH64_setresuid 147
static void *aarch64_setresuid __read_mostly = nullptr;
asmlinkage long hook_aarch64_setresuid(const struct pt_regs *regs)
{
	extern long __arm64_sys_setresuid(const struct pt_regs *regs);
	const struct cred old = *current_cred();

	long ret = __arm64_sys_setresuid(regs);
	if (!ret)
		ksu_handle_setresuid_cred(current_cred(), &old);
	return ret;
}

#ifdef CONFIG_COMPAT
#define __ARMEABI_setresuid 208
static void *armeabi_setresuid __read_mostly = nullptr;
asmlinkage long hook_armeabi_setresuid(const struct pt_regs *regs)
{
	extern long __arm64_sys_setresuid(const struct pt_regs *regs);
	const struct cred old = *current_cred();

	long ret = __arm64_sys_setresuid(regs);
	if (!ret)
		ksu_handle_setresuid_cred(current_cred(), &old);
	return ret;
}
#endif

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK) && !defined(CONFIG_KSU_SUSFS)
#ifdef CONFIG_COMPAT
#define __ARMEABI_read		3
extern long __arm64_sys_read(const struct pt_regs *regs);
static syscall_fn_t armeabi_read __read_mostly = nullptr;
asmlinkage long hook_armeabi_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];	

	ksu_handle_sys_read_fd(fd);
	return __arm64_sys_read(regs);
}
#endif // CONFIG_COMPAT
#define __AARCH64_read		63
extern long __arm64_sys_read(const struct pt_regs *regs);
static syscall_fn_t aarch64_read __read_mostly = nullptr;
asmlinkage long hook_aarch64_read(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];

	ksu_handle_sys_read_fd(fd);
	return __arm64_sys_read(regs);
}
static int ksu_syscall_table_restore(void *data)
{
	set_user_nice(current, 19); // low prio
loop_start:
	msleep(1000);
	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

#if defined(CONFIG_COMPAT)
	restore_syscall((void *)&armeabi_read, __ARMEABI_read, (void *)hook_armeabi_read, compat_sct);
#endif
	restore_syscall((void *)&aarch64_read, __AARCH64_read, (void *)hook_aarch64_read, native_sct);
	return 0;
}
#endif // !CONFIG_KSU_TAMPER_SYSCALL_TABLE && !CONFIG_KSU_HACK_ARM64_BRANCH_LINK

extern int security_setprocattr(int lsmid, const char *name, void *value, size_t size);
static int ksu_setprocattr(int lsmid, const char *name, void *value, size_t size)
{
	ksu_hide_setprocattr_inline(name, value, size);
	return security_setprocattr(lsmid, name, value, size);
}

extern int security_inode_setxattr(struct mnt_idmap *idmap, struct dentry *dentry,
			const char *name, const void *value, size_t size, int flags);
static int ksu_inode_setxattr(struct mnt_idmap *idmap, struct dentry *dentry,
			const char *name, const void *value, size_t size, int flags)
{
	ksu_hide_setxattr_inline(name, value, size);
	return security_inode_setxattr(idmap, dentry, name, value, size, flags);
}

static void __init ksu_lsm_hook_init(void)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;
	uintptr_t trampoline;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0) 
	target_callsite = kallsyms_lookup_retry("filename_renameat2");
#else
	target_callsite = kallsyms_lookup_retry("do_renameat2");
#endif
	symbol_addr = kallsyms_lookup_retry("vfs_rename");
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_vfs_rename);
	pr_info("LSM: vfs_rename: ret %d \n", ret);
	if (ret == -ERANGE) {
		trampoline = create_landing_pad((uintptr_t)&ksu_vfs_rename);
		if (!!trampoline)
			ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, trampoline);
	}
	if (!ret)
		goto rename_hook_done;

	target_callsite = kallsyms_lookup_retry("vfs_rename");
	symbol_addr = kallsyms_lookup_retry("security_inode_rename");
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_inode_rename);
	if (ret == -ERANGE) {
		trampoline = create_landing_pad((uintptr_t)&ksu_inode_rename);
		if (!!trampoline)
			ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, trampoline);
	}
	pr_info("LSM: security_inode_rename: ret %d \n", ret);

rename_hook_done:

#if 0
	target_callsite = kallsyms_lookup_retry("__sys_setresuid");
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("__arm64_sys_setresuid");
	symbol_addr = kallsyms_lookup_retry("security_task_fix_setuid");
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_task_fix_setuid);
	pr_info("lsm_hijack: security_task_fix_setuid: ret %d \n", ret);
#endif
#ifndef CONFIG_KSU_SUSFS
	replace_syscall((void *)&aarch64_setresuid, __AARCH64_setresuid, (void *)hook_aarch64_setresuid, native_sct);
#ifdef CONFIG_COMPAT
	replace_syscall((void *)&armeabi_setresuid, __ARMEABI_setresuid, (void *)hook_armeabi_setresuid, compat_sct);
#endif
#endif // CONFIG_KSU_SUSFS

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK) && !defined(CONFIG_KSU_SUSFS)
#ifdef CONFIG_COMPAT
	replace_syscall((void *)&armeabi_read, __ARMEABI_read, (void *)hook_armeabi_read, compat_sct);
#endif
	replace_syscall((void *)&aarch64_read, __AARCH64_read, (void *)hook_aarch64_read, native_sct);
	kthread_run(ksu_syscall_table_restore, NULL, "unhook");
#endif // !CONFIG_KSU_TAMPER_SYSCALL_TABLE && !CONFIG_KSU_HACK_ARM64_BRANCH_LINK

	target_callsite = kallsyms_lookup_retry("proc_pid_attr_write"); // fn ptr on dispatch table
	symbol_addr = kallsyms_lookup_retry("security_setprocattr");
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 128 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_setprocattr);
	if (ret == -ERANGE) {
		trampoline = create_landing_pad((uintptr_t)&ksu_setprocattr);
		if (!!trampoline)
			ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 128 * sizeof(uint32_t)), symbol_addr, trampoline);
	}
	pr_info("LSM: security_setprocattr: ret %d \n", ret);

	target_callsite = kallsyms_lookup_retry("__vfs_setxattr_locked"); // exported symbol
	symbol_addr = kallsyms_lookup_retry("security_inode_setxattr");
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 128 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_inode_setxattr);
	if (ret == -ERANGE) {
		trampoline = create_landing_pad((uintptr_t)&ksu_inode_setxattr);
		if (!!trampoline)
			ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 128 * sizeof(uint32_t)), symbol_addr, trampoline);
	}
	pr_info("LSM: security_inode_setxattr: ret %d \n", ret);

}
