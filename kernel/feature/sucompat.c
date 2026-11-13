#if defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) || defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
#define SUCOMPAT_HOOK_TYPE static __always_inline int
#else
#define SUCOMPAT_HOOK_TYPE int
#endif

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

#ifdef CONFIG_KSU_SUSFS
/*
 * CONFIG_KSU_SUSFS means the susfs4ksu kernel patch is in the tree and its
 * inline hooks call us directly. The kernel side needs a real symbol named
 * ksu_su_compat_enabled (fs/exec.c, fs/namei.c, fs/stat.c), so this cannot
 * stay a private bool.
 *
 * Kernel-side ABI by version (3.4 - 5.4 ARM64):
 *   >= 4.3 : extern struct static_key_true ksu_su_compat_enabled;
 *            test with static_branch_likely(&ksu_su_compat_enabled);
 *   <  4.3 : extern bool ksu_su_compat_enabled;
 *            test with a plain READ_ONCE().
 * 4.3 is the first release with the typed struct static_key_{true,false}
 * wrappers; older trees only have bare struct static_key and SukiSU's own
 * ksu_static_key_true_false wrapper, which the kernel source cannot use.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
DEFINE_STATIC_KEY_TRUE(ksu_su_compat_enabled);
#define ksu_su_compat_active()	static_key_enabled(&ksu_su_compat_enabled.key)
#define ksu_su_compat_set(on)	do {					\
	if (on)								\
		static_branch_enable(&ksu_su_compat_enabled);		\
	else								\
		static_branch_disable(&ksu_su_compat_enabled);		\
} while (0)
#else
bool ksu_su_compat_enabled __read_mostly = true;
#define ksu_su_compat_active()	(READ_ONCE(ksu_su_compat_enabled))
#define ksu_su_compat_set(on)	WRITE_ONCE(ksu_su_compat_enabled, (on))
#endif

static const char su_path[] = SU_PATH;
static const char sh_path[] = SH_PATH;
static const char ksud_path[] = KSUD_PATH;
#else
static bool ksu_su_compat_enabled __read_mostly = true;
#endif

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

#ifdef CONFIG_KSU_SUSFS

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
/*
 * 3.14+ ABI. Everything below is called from the inline hooks that the
 * susfs4ksu kernel patch installs in fs/exec.c, fs/namei.c and fs/stat.c.
 * These calls happen at the very beginning of the syscall, with a kernel
 * struct filename that we are allowed to rewrite in place.
 *
 * Return convention: 0 means "this is a handled su session", any other value
 * means "not ours, keep going".
 */
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags);

static int ksu_handle_execveat_init(struct filename *filename, struct user_arg_ptr *argv_user,
				    struct user_arg_ptr *envp_user)
{
	int ret = 0;

	if (current->pid == 1)
		return -EINVAL;

	if (!is_init(get_current_cred()))
		return -EINVAL;

	if (unlikely(!strcmp(filename->name, KSUD_PATH))) {
		pr_info("hook_manager: escape to root for init executing ksud: %d\n", current->pid);
#ifdef CONFIG_KSU_FEATURE_SULOG
		ksu_sulog_emit(KSU_SULOG_EVENT_SUCOMPAT, NULL, 0, GFP_KERNEL);
#endif
		ret = escape_to_root_for_init();
		if (ret) {
			pr_err("escape_to_root_for_init() failed: %d\n", ret);
			return ret;
		}
		return 0;
	}

	if (likely(!strstr(filename->name, "/app_process") && !strstr(filename->name, "/adbd") &&
		   !strstr(filename->name, "/stub_zygote"))) {
		pr_info("susfs: mark no sucompat checks for pid: '%d', exec: '%s'\n",
			current->pid, filename->name);
		susfs_set_current_proc_no_su();
		/*
		 * Marking proc umounted here is useless because only zygote spawned
		 * processes will umount the sus mounts, tho other susfs features
		 * still rely on the proc_umounted check. It is fine to not spoof
		 * for init spawned processes.
		 */
		return 0;
	}

#ifdef CONFIG_KSU_FEATURE_ADBROOT
#ifdef CONFIG_COMPAT
	if (unlikely(envp_user->is_compat))
		ret = ksu_adb_root_handle_execveat(filename->name, (void ***)&envp_user->ptr.compat);
	else
		ret = ksu_adb_root_handle_execveat(filename->name, (void ***)&envp_user->ptr.native);
#else
	ret = ksu_adb_root_handle_execveat(filename->name, (void ***)&envp_user->ptr.native);
#endif
#endif

	if (ret)
		pr_err("adb root failed: %d\n", ret);

	return ret;
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *argv_user, void *envp_user, int *flags)
{
	struct filename *filename;
	int ret;

	if (unlikely(!filename_ptr))
		return -EINVAL;

	filename = *filename_ptr;
	if (IS_ERR(filename))
		return -EINVAL;

	if (!ksu_handle_execveat_init(filename, (struct user_arg_ptr *)argv_user,
				      (struct user_arg_ptr *)envp_user))
		return -EINVAL;

	if (likely(!__ksu_is_allow_uid_for_current(current_uid().val)))
		return -EINVAL;

	if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
		return -EINVAL;

	ret = escape_with_root_profile();
	if (ret) {
		pr_err("escape_with_root_profile() failed: %d\n", ret);
		return -EINVAL;
	}

	pr_info("ksu_handle_execveat_sucompat: su->ksud!\n");

#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit(KSU_SULOG_EVENT_SUCOMPAT, NULL, 0, GFP_KERNEL);
#endif

	memcpy_inline(filename->name, ksud_path, sizeof(ksud_path));
	return 0;
}

int ksu_handle_post_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv_user,
				      void *envp_user, int *flags, int *retval)
{
	if (*retval >= 0)
		(void)ksu_install_su_fd();

	return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp, flags);
}

int ksu_handle_faccessat(int *dfd, struct filename **filename_ptr, int *mode, int *__unused_flags)
{
	struct filename *filename = *filename_ptr;

	if (unlikely(IS_ERR(filename) || filename->name == NULL))
		return 0;

	if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
		return 0;

	pr_info("ksu_handle_faccessat: su->sh!\n");
	memcpy_inline(filename->name, sh_path, sizeof(sh_path));
	return 0;
}

int ksu_handle_stat(int *dfd, struct filename **filename_ptr, int *flags)
{
	struct filename *filename = *filename_ptr;

	if (unlikely(IS_ERR(filename) || filename->name == NULL))
		return 0;

	if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
		return 0;

	pr_info("ksu_handle_stat: su->sh!\n");
	memcpy_inline(filename->name, sh_path, sizeof(sh_path));
	return 0;
}

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0) */

/*
 * 3.4 - 3.13 ABI. These kernels have no struct filename: do_execve_common()
 * gets a plain kernel string, while the syscall entry points still get the
 * user pointer. The kernel-side SUSFS port can hook either one; both use
 * the same function names as the non-SUSFS backends so the same hook code
 * works no matter whether CONFIG_KSU_SUSFS is set.
 *
 * Gating is done again here on purpose: the legacy kernels have no
 * reliable branch patching, so the hook may stay callable after sucompat
 * has been turned off.
 */

static bool ksu_legacy_is_su_user(const char __user *filename_user)
{
	char buf[sizeof(SU_PATH) + 1] = { 0 };

	if (unlikely(!filename_user || IS_ERR(filename_user)))
		return false;

	if (strncpy_from_user(buf, filename_user, sizeof(SU_PATH)) < 0)
		return false;

	return !strcmp(buf, SU_PATH);
}

static bool ksu_legacy_is_su_kern(const char *filename)
{
	return likely(filename && !strcmp(filename, SU_PATH));
}

static bool ksu_legacy_has_ksud(void)
{
	struct path kpath;
	bool found;

	if (kern_path(KSUD_PATH, 0, &kpath))
		return false;

	found = true;
	path_put(&kpath);
	return found;
}

static bool ksu_legacy_escape(const char *syscall_name)
{
	pr_info("su_compat: %s su found\n", syscall_name);

#ifdef CONFIG_KSU_FEATURE_SULOG
	ksu_sulog_emit(KSU_SULOG_EVENT_SUCOMPAT, NULL, 0, GFP_KERNEL);
#endif
	if (!!escape_with_root_profile())
		return false;

	ksu_install_su_fd(); // ksu#3679
	return true;
}

/* sys_execve / compat_sys_execve, user filename pointer */
int ksu_handle_sys_execve(const char __user **filename_user, void *argv, void *envp)
{
	if (likely(!ksu_su_compat_active()))
		return 0;

	if (unlikely(!filename_user || !*filename_user))
		return 0;

	ksu_adb_root_execve_user((void *)filename_user, (void *)envp);

	if (likely(!__ksu_is_allow_uid_for_current(current_uid().val)))
		return 0;

	if (!ksu_legacy_is_su_user(*filename_user))
		return 0;

	write_sulog('x');
	if (!ksu_legacy_escape("sys_execve"))
		return 0;

	if (ksu_legacy_has_ksud()) {
		pr_info("su_compat: sys_execve su->ksud!%s\n", is_compat_task() ? " [compat]" : "");
		*filename_user = ksud_user_path();
	} else {
		pr_info("su_compat: sys_execve su->sh!%s\n", is_compat_task() ? " [compat]" : "");
		*filename_user = sh_user_path();
	}

	return 0;
}

/* do_execve_common, kernel filename pointer */
int ksu_legacy_execve_sucompat(const char **filename_ptr, void *argv, void *envp)
{
	if (likely(!ksu_su_compat_active()))
		return 0;

	ksu_adb_root_execve_kernel((void *)filename_ptr, (void *)envp);

	if (likely(!filename_ptr || !*filename_ptr))
		return 0;

	if (likely(!__ksu_is_allow_uid_for_current(current_uid().val)))
		return 0;

	if (!ksu_legacy_is_su_kern(*filename_ptr))
		return 0;

	write_sulog('x');
	if (!ksu_legacy_escape("do_execve_common"))
		return 0;

	/*
	 * The string comes from getname(), i.e. a __getname() PATH_MAX buffer,
	 * so it is writable and big enough for both paths (as on >= 3.14).
	 */
	if (ksu_legacy_has_ksud()) {
		constexpr char ksud[16] = KSUD_PATH;
		pr_info("su_compat: do_execve_common su->ksud!%s\n", is_compat_task() ? " [compat]" : "");
		memcpy_inline((void *)*filename_ptr, ksud, sizeof(ksud));
	} else {
		constexpr char sh[16] = SH_PATH;
		pr_info("su_compat: do_execve_common su->sh!%s\n", is_compat_task() ? " [compat]" : "");
		memcpy_inline((void *)*filename_ptr, sh, sizeof(sh));
	}

	return 0;
}

static void ksu_legacy_filename_to_sh(const char __user **filename_user, const char *syscall_name,
				      uint8_t sulog_sym)
{
	if (likely(!ksu_su_compat_active()))
		return;

	if (!ksu_legacy_is_su_user(*filename_user))
		return;

	write_sulog(sulog_sym);
	pr_info("su_compat: %s su->sh!%s\n", syscall_name, is_compat_task() ? " [compat]" : "");
	*filename_user = sh_user_path();
}

/* sys_faccessat */
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
	ksu_legacy_filename_to_sh(filename_user, "sys_faccessat", 'a');
	return 0;
}

/* sys_newfstatat, sys_fstat64 */
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	ksu_legacy_filename_to_sh(filename_user, "sys_newfstatat", 's');
	return 0;
}

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0) */

static void ksu_sucompat_enable(void)
{
	ksu_su_compat_set(true);
	smp_mb();
	pr_info("%s: hooks enabled: exec, faccessat, stat\n", __func__);
}

static void ksu_sucompat_disable(void)
{
	ksu_su_compat_set(false);
	smp_mb();
	pr_info("%s: hooks disabled: exec, faccessat, stat\n", __func__);
}

#else /* !CONFIG_KSU_SUSFS */

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

static __always_inline bool is_user_filename_su(const char __user **filename_user)
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
		return false;

	if (likely((buf & 0x00FFFFFFFFFFFFFFUL) != (su_p[1] & 0x00FFFFFFFFFFFFFFUL)))
		return false;
#else
	if (get_user(buf, &fn_p[3]))
		return false;

	if (likely((buf & 0x00FFFFFFUL) != (su_p[3] & 0x00FFFFFFUL)))
		return false;

	if (unlikely(get_user(buf, &fn_p[2])))
		return false;

	if (buf != su_p[2])
		return false;

	if (unlikely(get_user(buf, &fn_p[1])))
		return false;

	if (unlikely(buf != su_p[1]))
		return false;
#endif
	// last word
	if (unlikely(get_user(buf, &fn_p[0])))
		return false;

	if (unlikely(buf != su_p[0]))
		return false;

	return true;
}

static __always_inline void ksu_sucompat_user_execve(const char __user **filename_user, void *restrict argv, void *restrict envp, const char *syscall_name)
{
	ksu_adb_root_execve_user((void *)filename_user, (void *)envp);
	ksu_preinit_user_execve_hook(filename_user, argv, envp);

	if (!is_su_allowed((const void **)filename_user))
		return;

	if (!is_user_filename_su(filename_user))
		return;

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
	pr_info("su_compat: %s su->ksud!%s\n", syscall_name, (is_compat_task()) ? " [compat]" : "" );
	*filename_user = ksud_user_path();
	return;

no_ksud:
	pr_info("su_compat: %s su->sh!%s\n", syscall_name, (is_compat_task()) ? " [compat]" : "" );
	*filename_user = sh_user_path();
	return;
}

static __always_inline void ksu_sucompat_user_common(const char __user **filename_user, const char *syscall_name)
{
	if (!is_su_allowed((const void **)filename_user))
		return;

	if (!is_user_filename_su(filename_user))
		return;

	if (!__builtin_strcmp(syscall_name, "sys_faccessat"))
		write_sulog('a');
	if (!__builtin_strcmp(syscall_name, "sys_newfstatat"))
		write_sulog('s');

	pr_info("su_compat: %s su->sh!%s\n", syscall_name, (is_compat_task()) ? " [compat]" : "" );
	*filename_user = sh_user_path();
	return;
}

// sys_faccessat
SUCOMPAT_HOOK_TYPE ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
	ksu_sucompat_user_common(filename_user, "sys_faccessat");
	return 0;
}

// sys_newfstatat, sys_fstat64
SUCOMPAT_HOOK_TYPE ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	ksu_sucompat_user_common(filename_user, "sys_newfstatat");
	return 0;
}

// sys_execve, compat_sys_execve
SUCOMPAT_HOOK_TYPE ksu_handle_sys_execve(const char __user **filename_user, void *argv, void *envp)
{
	ksu_sucompat_user_execve(filename_user, argv, envp, "sys_execve");
	return 0;
}

// sys_execveat, compat_sys_execveat
SUCOMPAT_HOOK_TYPE ksu_handle_sys_execveat(int *fd, const char __user **filename_user, void *argv, void *envp, int *flags)
{
	ksu_sucompat_user_execve(filename_user, argv, envp, "sys_execveat");
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

#endif /* CONFIG_KSU_SUSFS */

static int su_compat_feature_get(u64 *value)
{
#ifdef CONFIG_KSU_SUSFS
	*value = ksu_su_compat_active() ? 1 : 0;
#else
	*value = ksu_su_compat_enabled ? 1 : 0;
#endif
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;

#ifdef CONFIG_KSU_SUSFS
	if (enable == ksu_su_compat_active()) {
#else
	if (enable == ksu_su_compat_enabled) {
#endif
		pr_info("su_compat: no need to change\n");
	return 0;
	}

	if (enable) {
		ksu_sucompat_enable();
	} else {
		ksu_sucompat_disable();
	}

#ifndef CONFIG_KSU_SUSFS
	ksu_su_compat_enabled = enable;
#endif
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
