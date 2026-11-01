#ifdef CONFIG_KSU_FEATURE_ADBROOT

static bool ksu_adb_root __read_mostly = false;

static inline long is_exec_adbd(const char __user **filename_user)
{
	// should be bigger than `/apex/com.android.adbd/bin/adbd`
	char buf[40] = { 0 };
	size_t copysize = sizeof("/apex/com.android.adbd/bin/adbd");

	if (!!copy_from_user(buf, *filename_user, copysize))
		return 0;

	if (!!endswith(buf, "/adbd"))
		return 0;

	pr_info("%s: adbd: %s \n", __func__, buf);

	return 1;
}

static long is_libadbroot_ok()
{
	static const char kLibAdbRoot[] = "/data/adb/ksu/lib/libadbroot.so";
	struct path path;
	long ret = kern_path(kLibAdbRoot, 0, &path);
	if (ret < 0) {
		if (ret == -ENOENT) {
			pr_err("libadbroot.so not exists, skip adb root. Please run `ksud install`\n");
			ret = 0;
		} else {
			pr_err("access libadbroot.so failed: %ld, skip adb root\n", ret);
		}
		return ret;
	} else {
		ret = 1;
	}
	path_put(&path);
	return ret;
}

// NOTE: envp is (void ***), void * const char __user * const char __user *
static long setup_ld_preload(void ***envp_arg)
{
	constexpr char kLdPreload[] = "LD_PRELOAD=/data/adb/ksu/lib/libadbroot.so";
	constexpr char kLdLibraryPath[] = "LD_LIBRARY_PATH=/data/adb/ksu/lib";

	if (!envp_arg || !*envp_arg)
		return -EINVAL;

	char __user **envp = (char __user **)untagged_addr(*(void ***)envp_arg);

	// we do it this way so compiler can assert and fold at compile time.
	size_t kPtrSize = sizeof(uintptr_t);
#ifdef CONFIG_COMPAT
	if (is_compat_task())
		kPtrSize = sizeof(uint32_t);
#endif

	// lets do this like gtk. we have the ***envp
	size_t env_count = 0;
	uintptr_t val = 0;

envp_count_loop:
	if (kPtrSize == sizeof(uint32_t)) {
		uint32_t v32;
		uint32_t __user *array = (uint32_t __user *)envp;
		if (get_user(v32, &array[env_count] ))
			return -EFAULT;
		val = v32;
	}

	if (kPtrSize == sizeof(uint64_t)) {
		uint64_t v64;
		uint64_t __user *array = (uint64_t __user *)envp;
		if (get_user(v64, &array[env_count]))
			return -EFAULT;
		val = v64;
	}

	if (!val)
		goto envp_count_done;

	env_count = env_count + 1;

	// thats just too much.
	if (env_count > 64)
		return -E2BIG;

	goto envp_count_loop;

envp_count_done:
	pr_info("%s: envp_count: %u \n", __func__, env_count);

	// null env, we dont care
	if (!env_count)
		return -EINVAL;

	// this is freed once adb exits/gets replaced (sys_exit / execve->bprm), one page is no big deal, we leave it mapped
	uintptr_t mmap_page = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
	if (IS_ERR_VALUE(mmap_page))
		return -ENOMEM;

	pr_info("%s: vm_mmap: 0x%lx page to userspace \n", __func__, mmap_page);

	/**
	 *  PLAN:
	 * 	on 0, we put kLdPreload
	 *	offset kLdLibraryPath at +64 bytes
	 *	offset new envp at +128 bytes
	 */
	static_assert(sizeof(kLdPreload) < 64);
	static_assert((sizeof(kLdPreload) + sizeof(kLdLibraryPath)) < 128);

	void __user *kLdPreload_p = (void __user *)mmap_page;
	void __user *kLdLibraryPath_p = (void __user *)(mmap_page + 64);
	void __user *envp_array_p = (void __user *)(mmap_page + 128);

	if (!!copy_to_user(kLdPreload_p, kLdPreload, sizeof(kLdPreload)))
		return -EFAULT;

	if (!!copy_to_user(kLdLibraryPath_p, kLdLibraryPath, sizeof(kLdLibraryPath)))
		return -EFAULT;

	// prepare uintptr_t array for new char **envp
	// 2 entries plus a NULL
	size_t total_ptrs = env_count + 2 + 1;
	size_t array_bytes = total_ptrs * kPtrSize;

	// well, it will overflow.
	if (128 + array_bytes > PAGE_SIZE)
		return -E2BIG;

	void *buf __offstack_flags(array_bytes, GFP_KERNEL | __GFP_ZERO);
	if (!buf)
		return -ENOMEM;

	// copy original envp array addresses
	if (copy_from_user(buf, envp, env_count * kPtrSize))
		return -EFAULT;

	// 32-on-64 assumes LE.
	if (kPtrSize == sizeof(uint32_t)) {
		uint32_t *array = (uint32_t *)buf;
		array[env_count + 0] = *(uint32_t *)&kLdPreload_p;
		array[env_count + 1] = *(uint32_t *)&kLdLibraryPath_p;
		array[env_count + 2] = 0x0;
	}
	if (kPtrSize == sizeof(uint64_t)) {
		uint64_t *array = (uint64_t *)buf;
		array[env_count + 0] = *(uint64_t *)&kLdPreload_p;
		array[env_count + 1] = *(uint64_t *)&kLdLibraryPath_p;
		array[env_count + 2] = 0x0;
	}

	// blast new envp array to userspace
	if (!!copy_to_user(envp_array_p, buf, array_bytes))
		return -EFAULT;

	*(void ***)envp_arg = (void **)envp_array_p;
	pr_info("%s: new envp array blasted to userspace\n", __func__);
	return 0;	
}

static noinline void do_ksu_adb_root_execve_user(void *restrict filename, void *restrict envp_in)
{
	if (likely(ksu_is_seccomp_enabled()))
		return;

	uid_t uid = current_euid().val;
	if (uid != 0 && uid != 2000)
        	return;

	// filename is void * char __user *
	const char __user **filename_user = (const char __user **)filename;

	if (likely(!is_exec_adbd(filename_user)))
		return;

	if (unlikely(!is_libadbroot_ok()))
		return;

	if (setup_ld_preload((void ***)envp_in))
		return;

	pr_info("escape to root for adb\n");
	escape_to_root_for_adb_root();
	escape_with_root_profile(); // why is this needed for 3.x?
	return;
}

static noinline void do_ksu_adb_root_execve_kernel(void *restrict filename, void *restrict envp_in)
{
	if (likely(ksu_is_seccomp_enabled()))
		return;

	uid_t uid = current_euid().val;
	if (uid != 0 && uid != 2000)
        	return;

	if (!filename)
		return;

	// filename is char **
	if (!*(void **)filename)
		return;

	if (!!endswith(*(char **)filename, "/adbd"))
		return;

	if (unlikely(!is_libadbroot_ok()))
		return;

	if (!envp_in)
		return;

	struct user_arg_ptr *envp = (struct user_arg_ptr *)envp_in;

	void ***envp_addr = (void ***)&envp->ptr.native;
#ifdef CONFIG_COMPAT
	if (unlikely(envp->is_compat))
		envp_addr = (void ***)&envp->ptr.compat;
#endif

	pr_info("%s: envp 0x%lx \n", __func__, (uintptr_t)*envp_addr );

	if (setup_ld_preload(envp_addr))
		return; 

	pr_info("escape to root for adb\n");
	escape_to_root_for_adb_root();
	escape_with_root_profile(); // why is this needed?
	return;
}

#ifdef KSU_CAN_USE_JUMP_LABEL // see kernel_compat.h

DEFINE_STATIC_KEY_FALSE(ksu_adb_root_key);

static inline void ksu_adb_root_execve_user(void *restrict filename, void *restrict envp_in)
{
	if (static_branch_unlikely(&ksu_adb_root_key))
		do_ksu_adb_root_execve_user(filename, envp_in);
}
static inline void ksu_adb_root_execve_kernel(void *restrict filename, void *restrict envp_in)
{
	if (static_branch_unlikely(&ksu_adb_root_key))
		do_ksu_adb_root_execve_kernel(filename, envp_in);
}

static inline void ksu_adb_root_branch_enable() { static_branch_enable(&ksu_adb_root_key); smp_mb(); }
static inline void ksu_adb_root_branch_disable() { static_branch_disable(&ksu_adb_root_key); smp_mb(); }
#else /* ! KSU_CAN_USE_JUMP_LABEL */
static inline void ksu_adb_root_execve_user(void *restrict filename, void *restrict envp_in)
{
	if (unlikely(ksu_adb_root))
		do_ksu_adb_root_execve_user(filename, envp_in);
}
static inline void ksu_adb_root_execve_kernel(void *restrict filename, void *restrict envp_in)
{
	if (unlikely(ksu_adb_root))
		do_ksu_adb_root_execve_kernel(filename, envp_in);
}
static inline void ksu_adb_root_branch_enable() { } // no-op
static inline void ksu_adb_root_branch_disable() { } // no-op
#endif // KSU_CAN_USE_JUMP_LABEL

static int kernel_adb_root_feature_get(u64 *value)
{
	*value = ksu_adb_root ? 1 : 0;
	return 0;
}

static int kernel_adb_root_feature_set(u64 value)
{
	bool enable = value != 0;

	// prevent double enable / double disable
	// as old api does ref inc / dec, its a 'lil risky
	if (enable == ksu_adb_root)
		return 0;

	if (enable) {
		ksu_adb_root = true;
		ksu_adb_root_branch_enable();
	} else {
		ksu_adb_root = false;
		ksu_adb_root_branch_disable();
	}
	pr_info("adb_root: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler ksu_adb_root_handler = {
	.feature_id = KSU_FEATURE_ADB_ROOT,
	.name = "adb_root",
	.get_handler = kernel_adb_root_feature_get,
	.set_handler = kernel_adb_root_feature_set,
};

void __init ksu_adb_root_init(void)
{
	if (ksu_register_feature_handler(&ksu_adb_root_handler)) {
		pr_err("Failed to register adb_root feature handler\n");
	}
}

void __exit ksu_adb_root_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_ADB_ROOT);
}

#endif // CONFIG_KSU_FEATURE_ADBROOT
