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
// k4.2 ~ 6.7, LSM Hijacking, pure function pointer edition.
extern struct security_hook_heads security_hook_heads;

static int (*task_fix_setuid_fn)(struct cred *new, const struct cred *old, int flags) __read_mostly = nullptr;
static __nocfi int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	// see sys_setresuid
	if (flags == LSM_SETID_RES)
		ksu_handle_setresuid_cred(new, old);

	return task_fix_setuid_fn(new, old, flags);
}

static int (*inode_rename_fn)(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry) __read_mostly = nullptr;
static __nocfi int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry)
{
	ksu_rename_observer(old_dentry, new_dentry);
	return inode_rename_fn(old_inode, old_dentry, new_inode, new_dentry);
}

static void (*bprm_committing_creds_fn)(struct linux_binprm *bprm) __read_mostly = nullptr;
static __nocfi void ksu_bprm_committing_creds(struct linux_binprm *bprm)
{
#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit_bprm((const char *)bprm->filename);
#endif
	bprm_committing_creds_fn(bprm); // NOTE: void LSM hook
}

static int (*file_permission_fn)(struct file *file, int mask) __read_mostly = nullptr;
static __nocfi int ksu_file_permission(struct file *file, int mask)
{
	if (unlikely(ksu_vfs_read_hook))
		ksu_install_rc_hook(file);

	return file_permission_fn(file, mask);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static int (*bprm_set_creds_fn)(struct linux_binprm *bprm) __read_mostly = nullptr;
static __nocfi int ksu_bprm_set_creds(struct linux_binprm *bprm)
{
	if (likely(ksu_boot_completed))
		goto capability_fn;

	if (likely(!is_init(current_cred())))
		goto capability_fn;

	if (!bprm->filename)
		goto capability_fn;

	if (!!strcmp(bprm->filename, "/data/adb/ksud"))
		goto capability_fn;

	pr_info("bprm_set_creds: escape init executing %s with pid: %d\n", bprm->filename, current->pid);
	escape_to_root_forced(); // give this context all permissions

capability_fn:
	return bprm_set_creds_fn(bprm);
}
#endif

static void *setprocattr_fn __read_mostly = nullptr;
static __nocfi int ksu_setprocattr_new(const char *name, void *value, size_t size)
{
	ksu_hide_setprocattr_inline(name, value, size);
	return ((typeof(ksu_setprocattr_new) *)setprocattr_fn)(name, value, size);
}

static __nocfi int ksu_setprocattr_old(struct task_struct *p, char *name, void *value, size_t size)
{
	ksu_hide_setprocattr_inline(name, value, size);
	return ((typeof(ksu_setprocattr_old) *)setprocattr_fn)(p, name, value, size);
}

#define SETPROCATTR_TYPE_old	struct task_struct *, char *, void *, size_t
#define SETPROCATTR_TYPE_new1	const char *, void *, size_t
#define SETPROCATTR_TYPE_new2	const char *lsm, const char *, void *, size_t

/**
 * the pragma is to workaround GCC 4.9's broken designated initializer.
 * - avoid initializing it casted.
 * e.g. (void *)ksu_setprocattr_old, (void *)ksu_setprocattr_new
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"

#if 0 // small demo of __builtin_choose_expr vs C11 _Generic
#define OVERLOAD_SETPROCATTR(fn) __builtin_choose_expr(					\
        __builtin_types_compatible_p(typeof(fn), int (*)(SETPROCATTR_TYPE_old)),	\
        ksu_setprocattr_old,								\
        ksu_setprocattr_new								\
)
#else
#define OVERLOAD_SETPROCATTR(fn) _Generic(			\
(fn),								\
	int (*)(SETPROCATTR_TYPE_old)	:ksu_setprocattr_old,	\
	int (*)(SETPROCATTR_TYPE_new1)	:ksu_setprocattr_new, 	\
	int (*)(SETPROCATTR_TYPE_new2)	:ksu_setprocattr_new 	\
)
#endif

// now choose what we have
static typeof(security_setprocattr) *ksu_setprocattr __read_mostly = nullptr;
static inline void ksu_do_overload_setprocattr(void)
{
	ksu_setprocattr = OVERLOAD_SETPROCATTR(security_setprocattr);
}
#pragma GCC diagnostic pop
#undef SETPROCATTR_TYPE_new2
#undef SETPROCATTR_TYPE_new1
#undef SETPROCATTR_TYPE_old
#undef OVERLOAD_SETPROCATTR

/**
 *
 * Instead of using list/hlist abstractions and shit, since we know these things exist
 * we can just pointerwalk and walk away like its nothing.
 *
 * this should work as the first member of both list_head and hlist_head are just *
 *
 * struct list_head { struct list_head *next, *prev; };
 * struct hlist_head { struct hlist_node *first; }; / struct hlist_node { struct hlist_node *next, **pprev; };
 *
 * variant 1: 4.3 ~ 4.10
 * struct security_hook_list {
 *	struct list_head		list;	// 2 uintptr
 *	struct list_head		*head;
 *	union security_list_options	hook;	// 1 uintptr
 * };
 *
 * variant 2: 4.11 - 4.17
 * struct security_hook_list {
 *	struct list_head		list;
 * 	struct list_head		*head;
 * 	union security_list_options	hook;
 * 	char				*lsm;
 * };
 *
 * variant 3: 4.17+, normally backported to 4.14
 * struct security_hook_list {
 * 	struct hlist_node		list;
 * 	struct hlist_head		*head;
 * 	union security_list_options	hook;
 * 	char				*lsm;
 * };
 *
 */
static int ksu_hack_lsm_slot(void *hook_head, uintptr_t *old_ptr, uintptr_t new_ptr, const char *hook_name)
{
	if (!hook_head || !*(void **)hook_head)
		return 1;

	static_assert(sizeof(struct security_hook_list) >= 4 * sizeof(uintptr_t));
	static_assert(offsetof(struct security_hook_list, hook) == 3 * sizeof(uintptr_t));

	// technincally next/first
	uintptr_t node = *(uintptr_t *)hook_head;
	uintptr_t hook_slot_addr = node + 3 * sizeof(uintptr_t);

	uintptr_t current_hook = *(uintptr_t *)hook_slot_addr;
	if (!current_hook) {
		pr_info("LSM: No LSM hook on slot\n");
		return 1;
	}

#if defined(MODULE) // kallsyms strstr check
	char symbuf[KSYM_NAME_LEN];
	sprint_symbol_no_offset(symbuf, current_hook);
	if (!strstr(symbuf, hook_name)) {
		pr_info("LSM: expected: %s on 0x%lx mismatches ksym: %s\n", hook_name, current_hook, symbuf);
		return 2;
	}
	pr_info("LSM: expected: %s on 0x%lx matches ksym: %s\n", hook_name, current_hook, symbuf);
#endif

	WRITE_ONCE(*old_ptr, current_hook);
	smp_mb();

	if (sizeof(struct security_hook_list) == 5 * sizeof(uintptr_t))
		pr_info("LSM: 0x%lx found at 0x%lx slot, name: %s \n", current_hook, hook_slot_addr, *(char **)(node + 4 * sizeof(uintptr_t)));
	else
		pr_info("LSM: 0x%lx found at slot 0x%lx\n", current_hook, hook_slot_addr);

	int err = ksu_write_to_readonly_slot(hook_slot_addr, new_ptr);
	if (err) {
		pr_err("LSM: ksu_write_to_readonly_slot err: %d\n", err);
		return 1;
	}

	pr_info("LSM: 0x%lx written to slot\n", new_ptr);
	return 0;
}

#if defined(MODULE)
static void ksu_bruteforce_lsm_slot(uintptr_t *old_ptr, uintptr_t new_ptr, const char *hook_name)
{
	// context: https://github.com/PhoenixKernel/linux-staging/commit/63074fbdb6971ec43f39934b96f4b475eedcaf7e
	extern struct security_hook_heads security_hook_heads;

	uintptr_t *heads_arr = (uintptr_t *)&security_hook_heads;
	constexpr size_t compiled_size = sizeof(security_hook_heads);

	unsigned int total_slots = ksu_get_ksym_size((uintptr_t *)&security_hook_heads, compiled_size) / sizeof(uintptr_t);
	pr_info("LSM: slots: const: %u / live: %u addr: 0x%lx\n", compiled_size/sizeof(uintptr_t),  total_slots, heads_arr);

	uintptr_t first_node = 0;
	uintptr_t current_hook_fn = 0;
	unsigned int i = 0;

start_scan:
	if (!!copy_from_kernel_nofault(&first_node, &heads_arr[i], sizeof(first_node)))
		goto increment;

	if (!first_node)
		goto increment;

	uintptr_t hook_slot_addr = first_node + (3 * sizeof(uintptr_t));
	if (!!copy_from_kernel_nofault(&current_hook_fn, (void *)hook_slot_addr, sizeof(current_hook_fn)))
		goto increment;

	if (!current_hook_fn)
		goto increment;

	char symbuf[KSYM_NAME_LEN];
	sprint_symbol_no_offset(symbuf, current_hook_fn);
	if (!strstr(symbuf, hook_name))
		goto increment;
	
	pr_info("LSM: tries: %u expected: %s found on 0x%lx matches ksym: %s\n", i, hook_name, current_hook_fn, symbuf);
	ksu_hack_lsm_slot(&heads_arr[i], old_ptr, new_ptr, hook_name);
	return;

increment:
	i++;
	if (total_slots > i)
		goto start_scan;
}
#else
#define ksu_bruteforce_lsm_slot(...) do { } while (0)
#endif

#define LSM_HACK_INIT(hook_name, hook_fn)							\
do {												\
	pr_info("LSM: Initializing hook for %s\n", #hook_name);					\
	void *hook_head = (void *)&security_hook_heads.hook_name;				\
	uintptr_t *old_ptr = (uintptr_t *)&hook_name##_fn;					\
	int ret = ksu_hack_lsm_slot(hook_head, old_ptr, (uintptr_t)(hook_fn), #hook_name);	\
	if (ret == 2)										\
		ksu_bruteforce_lsm_slot(old_ptr, (uintptr_t)(hook_fn), #hook_name);		\
} while (0)

#define LSM_HACK_RESTORE(hook_name)								\
do {												\
	if (!hook_name##_fn)									\
		break;										\
	uintptr_t dummy_int;									\
	pr_info("LSM: Restoring original hook for %s\n", #hook_name);				\
	void *hook_head = (void *)&security_hook_heads.hook_name;				\
	ksu_hack_lsm_slot(hook_head, &dummy_int, (uintptr_t)hook_name##_fn, #hook_name);	\
} while (0)

static int ksu_restore_file_permission(void *data)
{
	set_user_nice(current, 19); // low prio

loop_start:
	msleep(1000);
	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

	msleep(1000);

	LSM_HACK_RESTORE(file_permission);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static int ksu_restore_bprm_set_creds(void *data)
{
	set_user_nice(current, 19); // low prio

loop_start:
	msleep(5000);
	if (!*(volatile bool *)&ksu_boot_completed)
		goto loop_start;

	msleep(1000);

	LSM_HACK_RESTORE(bprm_set_creds);
	return 0;
}
#endif

static __init void ksu_lsm_hook_init(void)
{
	LSM_HACK_INIT(task_fix_setuid, ksu_task_fix_setuid);
	LSM_HACK_INIT(inode_rename, ksu_inode_rename);

	ksu_do_overload_setprocattr();
	LSM_HACK_INIT(setprocattr, ksu_setprocattr);

#ifdef CONFIG_KSU_FEATURE_SULOG
	LSM_HACK_INIT(bprm_committing_creds, ksu_bprm_committing_creds);
#endif

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
	LSM_HACK_INIT(file_permission, ksu_file_permission);
	kthread_run(ksu_restore_file_permission, NULL, "kthread");
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	LSM_HACK_INIT(bprm_set_creds, ksu_bprm_set_creds);
	kthread_run(ksu_restore_bprm_set_creds, NULL, "kthread");
#endif

}

static void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}
