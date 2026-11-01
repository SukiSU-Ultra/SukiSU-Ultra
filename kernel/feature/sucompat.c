#if defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) || defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
#define SUCOMPAT_HOOK_TYPE static __always_inline int
#else
#define SUCOMPAT_HOOK_TYPE int
#endif

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

static bool ksu_su_compat_enabled __read_mostly = true;

static char __user *sh_user_path(void)
{
	constexpr char sh_path[16] = SH_PATH;
	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
	constexpr char ksud_path[16] = KSUD_PATH;
	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

#if !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && defined(KSU_CAN_USE_JUMP_LABEL)
DEFINE_STATIC_KEY_TRUE(ksu_sucompat_key);
static inline void ksu_sucompat_enable_branch()
{
	pr_info("su_compat: enable sucompat branches\n");
	static_branch_enable(&ksu_sucompat_key);
	smp_mb();
}
static inline void ksu_sucompat_disable_branch()
{
	pr_info("su_compat: remove sucompat branches\n");
	static_branch_disable(&ksu_sucompat_key);
	smp_mb();
}
#else
static inline void ksu_sucompat_enable_branch() { } // no-op
static inline void ksu_sucompat_disable_branch() { } // no-op
#endif

static noinline bool __ksu_is_allow_uid_copy(uid_t uid)
{
	assume(uid == 2000);

	// tiann/KernelSU #3882
	if (uid == SHELL_UID && !ksu_shell_su_allowed_for_current())
		return false;

	return __ksu_is_allow_uid(uid);
}

static __always_inline bool is_su_allowed(const void **ptr_to_check)
{
#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
#ifdef KSU_CAN_USE_JUMP_LABEL
	// read as: if not 'likely' disabled
	if (!!!static_branch_likely(&ksu_sucompat_key))
		return false;
#else
	if (!ksu_su_compat_enabled)
		return false;
#endif // KSU_CAN_USE_JUMP_LABEL
#endif

	// put ret hot on insn pipeline
	if (likely(ksu_is_seccomp_enabled()))
		return false;

	// pass through tagged task from setuid hook
	if (test_thread_flag(TIF_KSU_MANAGED))
		goto check_ptr;

#ifdef CONFIG_KSU_ENABLE_FULL_UID_CHECKS
	if (!ksu_is_allow_uid_for_current(current_uid().val))
		return false;
	goto check_ptr;
#else /* ! CONFIG_KSU_ENABLE_FULL_UID_CHECKS */
	// so if its root but not ksu domain, deny, see __ksu_is_allow_uid_for_current
	uid_t uid = current_uid().val;
	if (!!uid)
		goto uid_check;

	if (!is_ksu_domain())
		return false;
	goto check_ptr;

uid_check:
#ifdef CONFIG_KSU_SHELL_HAS_SU_ALWAYS
	/**
	 * NOTE: if shell always has su anyway, and full uid checks are disabled, 
	 * we can skip all these checks. this goto is for explicitness / code style
	 */
	 goto check_ptr;
	 __builtin_unreachable();
#else /* default behavior */
	/**
	 * NOTE: shell has its seccomp disabled, so we only need
	 * to check for this thing. short-circuit if not shell! 
	 * as we allow apps on setuid lsm by disabling seccomp
	 */
	if (likely(uid != 2000))
		goto check_ptr;

	/**
	 * use our noinline copy. only shell falls through this. nbd that
	 * it opens up a stack frame. having small code around here is worth
	 */
	if (!__ksu_is_allow_uid_copy(uid))
		return false;
#endif /* default behavior */
#endif /* ! CONFIG_KSU_ENABLE_FULL_UID_CHECKS */
check_ptr:
	assume(!!ptr_to_check);
	if (unlikely(!ptr_to_check))
		return false;

	assume_dereferenceable((void *)ptr_to_check, sizeof(uintptr_t));
	if (unlikely(!*ptr_to_check))
		return false;

	return true;
}

static __always_inline void ksu_sucompat_user_common(const char __user **filename_user, const char *syscall_name)
{
	uintptr_t buf;
	constexpr char su[16] = SU_PATH;

	// sugar prep
	uintptr_t *su_p = (uintptr_t *)su;
	uintptr_t __user *fn_p = (uintptr_t __user *)untagged_addr(*(char **)filename_user);

	static_assert(sizeof(SU_PATH) + 1 == 16);

	// cheaper than prefaulting (fault_in_readable, fault_in_pages_readable)
	__builtin_prefetch(fn_p);

	/*
	 * it seems this is actually the slowest part, so we peek last word first to speed it up
	 * NOTE: get_user rets EFAULT on err, so if we are copying a pointer that points to nothing, 
	 * we also detect that and ret fast
	 *
	 * first read overreads, reading 8 bytes, "bin/su\0?" /  4 bytes, "su\0?" when we only need 7/3
	 * but this is fine as we are guaranteed alignment, hardware provides trailing garbeg
	 * if it is specially crafted and hits a page guard, we just get EFAULT anyway
	 *
	 * on 64-bit we do this in 2 word compare, 4 on 32-bit, little endian only!
	 *
	 */

#ifdef CONFIG_64BIT
	if (get_user(buf, &fn_p[1]))
		return;

	if (likely((buf & 0x00FFFFFFFFFFFFFFUL) != (su_p[1] & 0x00FFFFFFFFFFFFFFUL)))
		return;
#else
	if (get_user(buf, &fn_p[3]))
		return;

	if (likely((buf & 0x00FFFFFFUL) != (su_p[3] & 0x00FFFFFFUL)))
		return;

	if (unlikely(get_user(buf, &fn_p[2])))
		return;

	if (buf != su_p[2])
		return;

	if (unlikely(get_user(buf, &fn_p[1])))
		return;

	if (unlikely(buf != su_p[1]))
		return;
#endif
	// last word
	if (unlikely(get_user(buf, &fn_p[0])))
		return;

	if (unlikely(buf != su_p[0]))
		return;

	if (!__builtin_strcmp(syscall_name, "sys_faccessat"))
		write_sulog('a');
	if (!__builtin_strcmp(syscall_name, "sys_newfstatat"))
		write_sulog('s');
	if (!__builtin_strcmp(syscall_name, "sys_execve"))
		write_sulog('x');
	if (!__builtin_strcmp(syscall_name, "sys_execveat"))
		write_sulog('x');

	// escalate if execve
	if (!!__builtin_strcmp(syscall_name, "sys_execve") && !!__builtin_strcmp(syscall_name, "sys_execveat"))
		goto no_escalate;

#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit(KSU_SULOG_EVENT_SUCOMPAT, NULL, 0, GFP_KERNEL);
#endif
	if (!!escape_with_root_profile())
		return;

	ksu_install_su_fd(); // ksu#3679

	// NOTE: we only check file existence, not exec success!
	struct path kpath;
	if (!!kern_path("/data/adb/ksud", 0, &kpath))
		goto no_ksud;

	path_put(&kpath);
	pr_info("su_compat: %s su->ksud!%s\n", syscall_name, (is_compat_task()) ? " [compat]" : "" );
	*filename_user = ksud_user_path();
	return;

no_ksud:
no_escalate:
	pr_info("su_compat: %s su->sh!%s\n", syscall_name, (is_compat_task()) ? " [compat]" : "" );
	*filename_user = sh_user_path();
	return;

}

// sys_faccessat
SUCOMPAT_HOOK_TYPE ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	ksu_sucompat_user_common(filename_user, "sys_faccessat");
	return 0;
}

// sys_newfstatat, sys_fstat64
SUCOMPAT_HOOK_TYPE ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (!is_su_allowed((const void **)filename_user))
		return 0;

	ksu_sucompat_user_common(filename_user, "sys_newfstatat");
	return 0;
}

// sys_execve, compat_sys_execve
SUCOMPAT_HOOK_TYPE ksu_handle_sys_execve(const char __user **filename_user, void *argv, void *envp)
{
	ksu_adb_root_execve_user((void *)filename_user, (void *)envp);
	ksu_preinit_user_execve_hook(filename_user, argv, envp);

	if (!is_su_allowed((const void **)filename_user))
		return 0;

	ksu_sucompat_user_common(filename_user, "sys_execve");
	return 0;
}

// sys_execveat, compat_sys_execveat
SUCOMPAT_HOOK_TYPE ksu_handle_sys_execveat(int *fd, const char __user **filename_user, void *argv, void *envp, int *flags)
{
	ksu_adb_root_execve_user((void *)filename_user, (void *)envp);
	ksu_preinit_user_execve_hook(filename_user, argv, envp);

	if (!is_su_allowed((const void **)filename_user))
		return 0;

	ksu_sucompat_user_common(filename_user, "sys_execveat");
	return 0;
}

static __always_inline void ksu_sucompat_kernel_common(int *restrict fd, void **restrict filename_ptr, void *restrict argv, void *restrict envp, int *restrict flags, const char *function_name)
{
	ksu_adb_root_execve_kernel((void *)filename_ptr, (void *)envp);
#if !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
	ksu_preinit_kernel_execve_hook(filename_ptr, argv, envp);
#endif // we defer hooking on branch link it should be caught by sys_execve first

	if (!is_su_allowed((const void **)filename_ptr))
		return;

	if (!!fd && fd != (int *)AT_FDCWD && *fd != AT_FDCWD)
		return;

	if (!!flags && !!*flags)
		return;

	constexpr char su[16] = SU_PATH;
	uint64_t *su_p = (uint64_t *)su;
	uint64_t *fn_p = (uint64_t *)*(char **)filename_ptr;

	// getname_flags pads this so nothing to worry about
	assume_restricted((void *)su_p, (void *)fn_p);
	assume_dereferenceable((void *)fn_p, 16);

	// https://godbolt.org/z/j8Yovv6bE
	if (likely((fn_p[1] & 0x00FFFFFFFFFFFFFFULL) != (su_p[1] & 0x00FFFFFFFFFFFFFFULL)))
		return;

	if (unlikely(fn_p[0] != su_p[0]))
		return;

	// we only handle execve here after removing vfs_statx hook for >= 6.1
	write_sulog('x');

#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit(KSU_SULOG_EVENT_SUCOMPAT, NULL, 0, GFP_KERNEL);
#endif
	if (!!escape_with_root_profile())
		return;

	ksu_install_su_fd(); // ksu#3679

	// NOTE: we only check file existence, not exec success!
	struct path kpath;
	if (!!kern_path("/data/adb/ksud", 0, &kpath))
		goto no_ksud;

	path_put(&kpath);
	pr_info("su_compat: %s su->ksud!%s\n", function_name, (is_compat_task()) ? " [compat]" : "");
	constexpr char ksud[16] = KSUD_PATH;
	memcpy_inline(*filename_ptr, ksud, sizeof(ksud));
	return;

no_ksud:
	pr_info("su_compat: %s su->sh!%s\n", function_name, (is_compat_task()) ? " [compat]" : "" );
	constexpr char sh[16] = SH_PATH;
	memcpy_inline(*filename_ptr, sh, sizeof(sh));
	return;
}

struct filename; // take note: struct filename *filename, for do_execveat_common / do_execve_common on >= 3.14
SUCOMPAT_HOOK_TYPE ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
	void *struct_filename = *(void **)filename_ptr;
	if (IS_ERR(struct_filename)) // see getname_flags
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	static_assert(offsetof(struct filename, name) == 0);
#endif

	// first member of struct filename is char *name.
	// char *filename = *(char **)struct_filename;
	ksu_sucompat_kernel_common(fd, (void **)struct_filename, argv, envp, flags, "do_execveat_common");
	return 0;
}

// take note: char *filename, for do_execve_common on < 3.14
SUCOMPAT_HOOK_TYPE ksu_legacy_execve_sucompat(const char **filename_ptr, void *argv, void *envp)
{
	ksu_sucompat_kernel_common((int *)AT_FDCWD, (void **)filename_ptr, argv, envp, 0, "do_execve_common");
	return 0;
}

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
static void syscall_table_sucompat_enable();
static void syscall_table_sucompat_disable();
#else
#define syscall_table_sucompat_enable() do { } while (0)
#define syscall_table_sucompat_disable() do { } while (0)
#endif

static void ksu_sucompat_enable()
{

	ksu_sucompat_enable_branch();
	syscall_table_sucompat_enable();

	ksu_su_compat_enabled = true;
	pr_info("%s: hooks enabled: exec, faccessat, stat\n", __func__);
}

static void ksu_sucompat_disable()
{

	ksu_sucompat_disable_branch();
	syscall_table_sucompat_disable();

	ksu_su_compat_enabled = false;
	pr_info("%s: hooks disabled: exec, faccessat, stat\n", __func__);
}

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;

	if (enable == ksu_su_compat_enabled) {
		pr_info("su_compat: no need to change\n");
	return 0;
	}

	if (enable) {
		ksu_sucompat_enable();
	} else {
		ksu_sucompat_disable();
	}

	ksu_su_compat_enabled = enable;
	pr_info("su_compat: set to %d\n", enable);

	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

// sucompat: permited process can execute 'su' to gain root access.
void __init ksu_sucompat_init()
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}

	tiny_sulog_init_heap();
}

void __exit ksu_sucompat_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
