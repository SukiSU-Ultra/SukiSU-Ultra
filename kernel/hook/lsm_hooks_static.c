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

// setuid
extern int security_task_fix_setuid(struct cred *new, const struct cred *old, int flags);
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return security_task_fix_setuid(new, old, flags);
}

// bprm
extern int security_bprm_check(struct linux_binprm *bprm);
static int ksu_bprm_check(struct linux_binprm *bprm)
{
#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit_bprm((const char *)bprm->filename);
#endif
	return security_bprm_check(bprm);
}

// vfs_read, as security_file_permission is a bit spotty to hook!
extern ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos);
static ssize_t ksu_vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	if (static_branch_likely(&ksud_vfs_read_key))
		ksu_install_rc_hook(file);

	return vfs_read(file, buf, count, pos);
}

extern int security_file_permission(struct file *file, int mask);
static int ksu_security_file_permission(struct file *file, int mask)
{
	if (static_branch_likely(&ksud_vfs_read_key))
		ksu_install_rc_hook(file);

	return security_file_permission(file, mask);
}

extern int security_setprocattr(int lsmid, const char *name, void *value, size_t size);
static int ksu_setprocattr(int lsmid, const char *name, void *value, size_t size)
{
	ksu_hide_setprocattr_inline(name, value, size);
	return security_setprocattr(lsmid, name, value, size);
}

static void __init ksu_core_init(void)
{
	int ret;
	uintptr_t target_callsite;
	uintptr_t symbol_addr;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0) 
	target_callsite = kallsyms_lookup_retry("filename_renameat2");
#else
	target_callsite = kallsyms_lookup_retry("do_renameat2");
#endif
	symbol_addr = kallsyms_lookup_retry("vfs_rename");
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_vfs_rename);
	pr_info("lsm_hijack: vfs_rename: ret %d \n", ret);
	if (!ret)
		goto rename_hook_done;

	target_callsite = kallsyms_lookup_retry("vfs_rename");
	symbol_addr = kallsyms_lookup_retry("security_inode_rename");
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_inode_rename);
	pr_info("lsm_hijack: security_inode_rename: ret %d \n", ret);

rename_hook_done:

	target_callsite = kallsyms_lookup_retry("__sys_setresuid");
	if (!target_callsite)
		target_callsite = kallsyms_lookup_retry("__arm64_sys_setresuid");
	symbol_addr = kallsyms_lookup_retry("security_task_fix_setuid");
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_task_fix_setuid);
	pr_info("lsm_hijack: security_task_fix_setuid: ret %d \n", ret);

#ifdef CONFIG_KSU_FEATURE_SULOG
	symbol_addr = kallsyms_lookup_retry("security_bprm_check");
	target_callsite = kallsyms_lookup_retry("bprm_execve");
	if (!target_callsite)
		goto skip_bprm1;
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_bprm_check);
	if (!ret)
		goto bprm_done;
skip_bprm1:
	target_callsite = kallsyms_lookup_retry("search_binary_handler");
	if (!target_callsite)
		goto skip_bprm2;
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_bprm_check);
	if (!ret)
		goto bprm_done;
skip_bprm2:
	ret = -ENXIO;
	target_callsite = kallsyms_lookup_retry("exec_binprm");
	if (!target_callsite)
		goto bprm_done;
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 256 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_bprm_check);
bprm_done:
	pr_info("lsm_hijack: security_bprm_check: ret %d \n", ret);
#endif

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
	symbol_addr = kallsyms_lookup_retry("vfs_read");
	if (!symbol_addr)
		goto skip_read2;
	target_callsite = kallsyms_lookup_retry("__arm64_sys_read");
	if (!target_callsite)
		goto skip_read1;
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 128 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_vfs_read);
	if (!ret)
		goto read_hook_done;
skip_read1:
	target_callsite = kallsyms_lookup_retry("ksys_read");
	if (!target_callsite)
		goto skip_read2;
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 128 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_vfs_read);
	if (!ret)
		goto read_hook_done;
skip_read2:
	ret = -ENXIO;
	symbol_addr = kallsyms_lookup_retry("security_file_permission");
	if (!symbol_addr)
		goto read_hook_done;
	target_callsite = kallsyms_lookup_retry("rw_verify_area");
	if (!target_callsite)
		goto read_hook_done;
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 128 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_security_file_permission);

read_hook_done:
	pr_info("lsm_hijack: security_file_permission: ret %d \n", ret);
#endif

	target_callsite = kallsyms_lookup_retry("proc_pid_attr_write");
	symbol_addr = kallsyms_lookup_retry("security_setprocattr");
	ret = arm64_bl_patch(target_callsite, ksu_get_ksym_size(target_callsite, 128 * sizeof(uint32_t)), symbol_addr, (uintptr_t)&ksu_setprocattr);
	pr_info("lsm_hijack: security_setprocattr: ret %d \n", ret);

}
