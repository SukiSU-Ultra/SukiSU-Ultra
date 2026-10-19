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

// selinux_ops (LSM), security_operations struct tampering for ultra legacy

static uintptr_t selinux_ops_addr = 0x0;

static int (*orig_setprocattr) (struct task_struct *p, char *name, void *value, size_t size) __read_mostly = nullptr;
static int hook_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
	ksu_hide_setprocattr_inline(name, value, size);
	return orig_setprocattr(p, name, value, size);
}

static int (*orig_inode_rename) (struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry) __read_mostly = nullptr;
static int hook_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return orig_inode_rename(old_inode, old_dentry, new_inode, new_dentry);
}

static int (*orig_bprm_check_security)(struct linux_binprm *bprm) __read_mostly = nullptr;
static int hook_bprm_check_security(struct linux_binprm *bprm)
{
#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit_bprm((const char *)bprm->filename);
#endif
	return orig_bprm_check_security(bprm);
}

static int (*orig_task_fix_setuid) (struct cred *new, const struct cred *old, int flags) __read_mostly = nullptr;
static int hook_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return orig_task_fix_setuid(new, old, flags);
}

static int (*orig_file_permission) (struct file *file, int mask) __read_mostly = nullptr;
static int hook_file_permission(struct file *file, int mask)
{
	if (unlikely(ksu_vfs_read_hook))
		ksu_install_rc_hook(file);

	return orig_file_permission(file, mask);
}

static int (*orig_bprm_set_creds)(struct linux_binprm *bprm) __read_mostly = nullptr;
static int ksu_unregister_bprm_set_creds(void *data)
{
	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;
	if (!orig_bprm_set_creds)
		return 0;

	pr_info("%s: restoring: bprm_set_creds 0x%lx -> 0x%lx\n", __func__, (long)ops->bprm_set_creds, (long)orig_bprm_set_creds);
	ops->bprm_set_creds = orig_bprm_set_creds;

	return 0;
}

static int hook_bprm_set_creds(struct linux_binprm *bprm)
{
	if (ksu_boot_completed)
		goto unreg_bprm_set_creds;

	if (!is_init(current_cred()))
		goto bprm_set_creds;

	if (!bprm->filename)
		goto bprm_set_creds;

	if (!!strcmp(bprm->filename, "/data/adb/ksud"))
		goto bprm_set_creds;

	pr_info("bprm_set_creds: escape init executing %s with pid: %d\n", bprm->filename, current->pid);
	escape_to_root_forced(); // give this context all permissions

	goto bprm_set_creds;

unreg_bprm_set_creds:
	stop_machine(ksu_unregister_bprm_set_creds, NULL, NULL);

bprm_set_creds:
	return orig_bprm_set_creds(bprm);
}

static inline bool verify_selinux_cred_free(void *fn_ptr)
{
	bool success = false;

	if (!fn_ptr)
		return false;

	// ref: https://elixir.bootlin.com/linux/v3.18.140/source/security/selinux/hooks.c#L3474
	void (*selinux_cred_free_fn)(struct cred *) = fn_ptr;

	struct cred dummy_cred;

	// explicitly set it to NULL
	// make sure this happens!
	// #1. it wont trigger BUG_ON
	// #2. this way it will kfree(NULL), which does nothing
	*(void **)&dummy_cred.security = nullptr;
	barrier();

	selinux_cred_free_fn(&dummy_cred);

	// check if selinux_cred_free is successful
	if ((unsigned long)*(void **)&dummy_cred.security == 0x7UL)
		success = true;

	pr_info("selinux_cred_free: 0x%lx cred->security: 0x%lx success: %d\n", (unsigned long)fn_ptr, (unsigned long)dummy_cred.security, success);

	return success;
}

// we should see a lot of pointers that is inside stext && etext
// basically we check for "pointer density"
static inline bool is_selinux_ops_valid(uintptr_t addr)
{
	extern char _stext[], _etext[];
	int total_slots = sizeof(struct security_operations) / sizeof(void *); 
	int valid_ptr = 0;
	int i = 0;

	uintptr_t member_ptr = 0;
	uintptr_t current_slot_addr;

	// we will be off by two or three due to sizeof(security_operations.name)
	// thats 11 bytes, on 32 bit, this is three pointers worth, not a big deal

density_verify_start:
	current_slot_addr = addr + (i * sizeof(void *));

	member_ptr = 0;
	if (copy_from_kernel_nofault(&member_ptr, (void *)current_slot_addr, sizeof(uintptr_t) ))
		goto next_iter; // if it fails, just try next slot

	// give up early
	if (!valid_ptr && i >= 20)
		return false;

	// pr_info("%s: member_ptr: 0x%lx \n", __func__, (long)member_ptr);
	if (member_ptr >= (uintptr_t)_stext && member_ptr <= (uintptr_t)_etext)
		valid_ptr++;

next_iter:
	i++;	
	if (i < total_slots)
		goto density_verify_start;

	pr_info("%s: density: valid: %lu slots: %lu \n", __func__, valid_ptr, total_slots);

	// maybe increase to 75% or something?
	return (valid_ptr > (total_slots / 2));
}

static inline bool check_candidate(uintptr_t addr)
{
	struct security_operations *candidate = (struct security_operations *)addr;

	char char_buf[sizeof("selinux")];
	if (copy_from_kernel_nofault(char_buf, (void *)addr, sizeof("selinux") ))
		return false;

	if (!!memcmp_inline(char_buf, "selinux", sizeof("selinux")))
		return false;

	// candidate found!
	pr_info("%s: candidate selinux_ops at 0x%lx\n", __func__, (long)addr);

	// check ptr density	
	if (!is_selinux_ops_valid(addr))
		return false;

	if (!candidate->cred_free)
		return false;

#if 0 //def CONFIG_KALLSYMS // not always available, can also fail, but it wont hurt to try.
	uintptr_t ksym_ptr = (uintptr_t)kallsyms_lookup_name("selinux_cred_free");
	if (unlikely(ksym_ptr != (uintptr_t)candidate->cred_free))
		goto test_fn;

	pr_info("%s: selinux_cred_free found via ksym_lookup: 0x%lx probe_result: 0x%lx \n", __func__, (long)ksym_ptr, (long)candidate->cred_free);
	return true;
test_fn:
#endif
	// oh yeah I am so confident that this is it
	pr_info("%s: candidate selinux_cred_free at 0x%lx\n", __func__, (long)candidate->cred_free);
	return verify_selinux_cred_free((void *)candidate->cred_free);
}

/** 
 * we do this in blocks of sequential 10k pointers.
 * 10k pointers up, 10k pointers down
 * this is predictable, more cache friendly, no trashing.
 *
 * one up, one down oscillating scan isn't as friendly to teh cahce.
 * once ptrdiff of up vs down is larger than L1, it will be trashy.
 *
 */
static noinline void *hunt_for_selinux_ops(void *heuristic_ptr)
{
	uintptr_t anchor = (uintptr_t)heuristic_ptr;
	uintptr_t curr;
	unsigned long iter_count = 0;
	unsigned long max_index = 10000; // max number of pointers to test, one way
	unsigned long i = 0;

	uintptr_t start = anchor - max_index * sizeof(void *);
	uintptr_t end = anchor + max_index * sizeof(void *);
	pr_info("%s: scan range: 0x%lx - 0x%lx anchor: 0x%lx\n", __func__, (long)start, (long)end, (long)anchor);

scan_up:
	if (i >= max_index) {
		i = 1;
		goto scan_down;
	}

	curr = anchor + (i * sizeof(void *));
	i++;
	iter_count++;

	if (check_candidate(curr))
		goto found;

	goto scan_up;

scan_down:
	if (i >= max_index)
		goto not_found;

	curr = anchor - (i * sizeof(void *));
	i++;
	iter_count++;

	if (check_candidate(curr))
		goto found;

	goto scan_down;

found:
	pr_info("%s: found selinux_ops at 0x%lx iter_count: %lu \n", __func__, curr, iter_count);
	return (void *)curr;

not_found:
	pr_info("%s: selinux_ops not found in range! iter_count: %lu \n", __func__, iter_count);
	return nullptr;
}

static inline void set_selinux_ops()
{
	extern int selinux_enabled;
	extern struct security_class_mapping secclass_map[];
	extern struct list_head crypto_alg_list;
	extern unsigned int avc_cache_threshold;
	
	struct security_operations *ops = nullptr;

// if user exports selinux_ops, we just go for it!
#ifdef KSU_HAS_EXPORTED_SELINUX_OPS
	extern struct security_operations selinux_ops;
	if (!ops)
		ops = (struct security_operations *)&selinux_ops;
#endif

#ifdef CONFIG_KEYS
	extern struct key_user root_key_user;
	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops((void *)&root_key_user);
#endif

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops((void *)&avc_cache_threshold);

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops((void *)&crypto_alg_list);

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops((void *)&selinux_enabled);

	if (!ops)
		ops = (struct security_operations *)hunt_for_selinux_ops((void *)&secclass_map);

	if (!ops)
		return;

	selinux_ops_addr = (uintptr_t)ops;	
}

// stop_machine
static int ksu_restore_file_permission_stop_machine(void *data)
{
	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;
	if (!orig_file_permission)
		return 0;

	pr_info("%s: restoring file_permission 0x%lx -> 0x%lx\n", __func__, (long)ops->file_permission, (long)orig_file_permission);
	ops->file_permission = orig_file_permission;	
	return 0;
}

static int ksu_restore_file_permission(void *data)
{
loop_start:

	msleep(1000);

	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

	stop_machine(ksu_restore_file_permission_stop_machine, NULL, NULL);

	return 0;
}

// stop_machine
static int ksu_register_lsm_hook(void *data)
{
	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;

	orig_bprm_set_creds = ops->bprm_set_creds;
	ops->bprm_set_creds = hook_bprm_set_creds;

	orig_inode_rename = ops->inode_rename;
	ops->inode_rename = hook_inode_rename;

	orig_setprocattr = ops->setprocattr;
	ops->setprocattr = hook_setprocattr;

	orig_task_fix_setuid = ops->task_fix_setuid;
	ops->task_fix_setuid = hook_task_fix_setuid;

#ifdef CONFIG_KSU_FEATURE_SULOG
	orig_bprm_check_security = ops->bprm_check_security;
	ops->bprm_check_security = hook_bprm_check_security;
#endif

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
	orig_file_permission = ops->file_permission;
	ops->file_permission = hook_file_permission;
#endif

	return 0;
}

static void ksu_lsm_hook_init(void)
{
	set_selinux_ops();

	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;
	if (!ops)
		return;

	if (!!memcmp_inline(ops, "selinux", sizeof("selinux")))
		return;

	pr_info("%s: selinux_ops: 0x%lx .name = %s\n", __func__, (long)ops, (const char *)ops );

	stop_machine(ksu_register_lsm_hook, NULL, NULL);
	
	kthread_run(ksu_restore_file_permission, NULL, "kthread");
	return;
}

static void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
