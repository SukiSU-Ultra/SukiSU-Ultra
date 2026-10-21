#define INIT_PATH "/system/bin/init"

static bool ksu_preinit_enabled = true;
module_param_named(preinit, ksu_preinit_enabled, bool, 0);

static bool is_selinux_setup(const char __user *const __user *argv_user)
{
	static const char expected[] = "selinux_setup";
	const char __user *arg;
	char buf[sizeof(expected) + 1];

	if (!argv_user)
		return false;

	if (is_compat_task()) {
		uint32_t __user *compat_argv_user = (uint32_t __user *)argv_user;
		uint32_t arg32_p;
		get_user(arg32_p, compat_argv_user + 1);
		arg = (void *)(uintptr_t)arg32_p;
	} else
		get_user(arg, argv_user + 1);

	if (!arg)
		return false;

	memset(buf, 0, sizeof(buf));
	if (strncpy_from_user(buf, arg, sizeof(buf) - 1) < 0)
		return false;

	return !strcmp(buf, expected);
}

static void ksu_stage_preinit_binary(void *u_argv, void *u_envp)
{
	struct file *file;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	file = shmem_file_setup("ksu_preinit_mem", runner_binary_len, EMPTY_VMA_FLAGS);
#else
	file = shmem_file_setup("ksu_preinit_mem", runner_binary_len, 0);
#endif
	if (IS_ERR(file)) {
		pr_err("preinit: shmem_file_setup failed: %ld\n", PTR_ERR(file));
		return;
	}

	loff_t pos = 0;
	int ret = kernel_write(file, runner_binary, runner_binary_len, &pos);
	if (ret != (ssize_t)runner_binary_len) {
		pr_err("preinit: kernel_write to shmem failed: %d\n", ret);
		fput(file);
		return;
	}

	int fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("preinit: get fd failed: %d\n", fd);
		fput(file);
		return;
	}

	// The fd owns the file from here on; close-on-exec frees it once the
	// runner has been loaded.
	fd_install(fd, file);

	char fd_path[32];
	int len = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

	struct path p;
	if (kern_path(fd_path, LOOKUP_FOLLOW, &p)) {
		pr_err("preinit: %s not reachable, booting without preinit\n", fd_path);
		ksu_close_fd(fd);
		return;
	}
	path_put(&p);

	uintptr_t mmap_page = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0);
	if (IS_ERR_VALUE(mmap_page)) {
		pr_info("preinit: mmap fail!\n");
		return;
	}

	pr_info("preinit: mmap_page: 0x%lx \n", mmap_page);

	const char __user **argv_user = (const char __user **)*(void ***)u_argv;
	const char __user **envp_user = (const char __user **)*(void ***)u_envp;

// payload definition
	struct execve_payload {
		char c_argv0[32];	// "/system/bin/init", mmap_page is pointing here
		char c_argv1[32];	// "selinux_setup"
		char filename[32];
		uintptr_t argv[3];	// **argv: argv0, argv1, NULL terminator
		uintptr_t envp[17];	// envp mirror, pointer extended.

	};
	static_assert(32 > sizeof(INIT_PATH));
// payload definition

	struct execve_payload payload = { 0 };
	memcpy(payload.c_argv0, INIT_PATH, sizeof(INIT_PATH));
	memcpy(payload.c_argv1, "selinux_setup", sizeof("selinux_setup"));
	memcpy(payload.filename, fd_path, len + 1);
	payload.argv[0] = mmap_page;			// ptr to c_argv0
	payload.argv[1] = mmap_page + 32;		// ptr to c_argv1
	payload.argv[2] = 0x0;				// nullptr

	void __user *u_filename = (void __user *)(mmap_page + offsetof(struct execve_payload, filename));
	void __user *u_argv_ptr = (void __user *)(mmap_page + offsetof(struct execve_payload, argv));
	void __user *u_envp_ptr = envp_user;

	if (!is_compat_task())
		goto send_payload;

	pr_info("preinit: compat init found! argv: 0x%lx envp: 0x%lx \n", (uintptr_t)argv_user, (uintptr_t)envp_user);

	// if compat task we need to mirror original envp with widened ptr
	uint32_t __user *u_env32 = (uint32_t __user *)envp_user;
	int c = 0;
	while (c < 16) {
		u32 ptr32 = 0;
		if (get_user(ptr32, &u_env32[c]))
			break;

		if (!ptr32)
			break;

		payload.envp[c] = (uintptr_t)ptr32; // extend
		pr_info("preinit: debug: envp: 0x%lx \n", payload.envp[c]);
		c++;
	}
	payload.envp[c] = 0x0;
	u_envp_ptr = (void __user *)(mmap_page + offsetof(struct execve_payload, envp));

send_payload:
	if (!!copy_to_user((void __user *)mmap_page, &payload, sizeof(struct execve_payload))) {
		pr_info("preinit: debug: copy_to_user mmap failed \n");
		return;
	}

	pr_info("preinit: syscall(SYS_execve, 0x%lx, 0x%lx, 0x%lx);\n", (uintptr_t)u_filename, (uintptr_t)u_argv_ptr, (uintptr_t)u_envp_ptr);

	long eret = ksyscall(execve, u_filename, u_argv_ptr, u_envp_ptr);
	pr_info("preinit: sys_execve runner returned: %ld \n", eret);
	if (eret)
		vm_munmap(mmap_page, PAGE_SIZE);
}

static noinline void ksu_preinit_handle_kexecve(void **filename, void *kargv, void *kenvp)
{
	if (!current->mm || current->pid != 1)
		return;

	assume_dereferenceable(*filename, 32);

	constexpr char expected[] = INIT_PATH;
	if (!!memcmp_inline(*(char **)filename, expected, sizeof(expected)))
		return;

	pr_info("preinit: kernel_execve: %s \n", INIT_PATH);

	struct user_arg_ptr *argv = (struct user_arg_ptr *)kargv;
	void ***u_argv = (void ***)&argv->ptr.native;
#ifdef CONFIG_COMPAT
	if (argv->is_compat)
		u_argv = (void ***)&argv->ptr.compat;
#endif

	if (!is_selinux_setup((const char __user **)*(void ***)u_argv))
		return;

	struct user_arg_ptr *envp = (struct user_arg_ptr *)kenvp;
	void ***u_envp = (void ***)&envp->ptr.native;
#ifdef CONFIG_COMPAT
	if (envp->is_compat)
		u_envp = (void ***)&envp->ptr.compat;
#endif

	pr_info("preinit: kernel_execve: /system/bin/init with selinux_setup! \n");

	kthread_run(ksu_disable_preinit_branch, nullptr, "kthread");

	ksu_stage_preinit_binary(u_argv, u_envp);
}

// filename is void *char __user *
static noinline void ksu_preinit_handle_uexecve(const char __user **filename, void *u_argv, void *u_envp)
{
	if (!current->mm || current->pid != 1)
		return;

	constexpr char expected[] = INIT_PATH;

	char buf[sizeof(expected) + 1];
	buf[sizeof(buf) - 1] = 0;
	if (!!copy_from_user_retry(buf, *filename, sizeof(buf) - 1 ))
		return;

	if (!!strcmp(buf, expected))
		return;

	pr_info("preinit: sys_execve: %s \n", INIT_PATH);

	if (!is_selinux_setup((const char __user **)*(void ***)u_argv))
		return;

	pr_info("preinit: sys_execve: %s with selinux_setup! \n", INIT_PATH);

	kthread_run(ksu_disable_preinit_branch, nullptr, "kthread");

	ksu_stage_preinit_binary(u_argv, u_envp);
}

static inline void ksu_preinit_kernel_execve_hook(void **filename, void *k_argv, void *k_envp)
{
	if (static_branch_unlikely(&ksu_preinit_key))
		ksu_preinit_handle_kexecve(filename, k_argv, k_envp);
}

static inline void ksu_preinit_user_execve_hook(const char __user **filename, void *u_argv, void *u_envp)
{
	if (static_branch_unlikely(&ksu_preinit_key))
		ksu_preinit_handle_uexecve(filename, u_argv, u_envp);
}

void ksu_preinit_release(void) { }

void ksu_preinit_init(void)
{
	if (!ksu_preinit_enabled) {
		pr_info("preinit: disabled!\n");
		return;
	}
	
	static_branch_enable(&ksu_preinit_key);
	kick_all_cpus_sync();
	pr_info("preinit: enabled!\n");
	return;
}

void ksu_preinit_exit(void) { }
