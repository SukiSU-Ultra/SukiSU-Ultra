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

// returns fd
static int ksu_stage_preinit_binary(void)
{
	struct file *file;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	file = shmem_file_setup("ksu_preinit_mem", runner_binary_len, EMPTY_VMA_FLAGS);
#else
	file = shmem_file_setup("ksu_preinit_mem", runner_binary_len, 0);
#endif
	if (IS_ERR(file)) {
		pr_err("preinit: shmem_file_setup failed: %ld\n", PTR_ERR(file));
		return -1;
	}

	loff_t pos = 0;
	int ret = kernel_write(file, runner_binary, runner_binary_len, &pos);
	if (ret != (ssize_t)runner_binary_len) {
		pr_err("preinit: kernel_write to shmem failed: %d\n", ret);
		fput(file);
		return -1;
	}

	int fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("preinit: get fd failed: %d\n", fd);
		fput(file);
		return -1;
	}

	// The fd owns the file from here on; close-on-exec frees it once the
	// runner has been loaded.
	fd_install(fd, file);
	return fd;
}

static noinline void ksu_preinit_handle_kexecve(void **filename, void *kargv)
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
	if (unlikely(argv->is_compat))
		u_argv = (void ***)&argv->ptr.compat;
#endif

	if (!is_selinux_setup((const char __user *const __user *)*(void ***)u_argv))
		return;

	pr_info("preinit: kernel_execve: /system/bin/init with selinux_setup! \n");

	kthread_run(ksu_disable_preinit_branch, nullptr, "kthread");

	int fd = ksu_stage_preinit_binary();
	if (fd < 0)
		pr_info("preinit: get fd failed: %d\n", fd);

	char fd_path[32];
	int len = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

	struct path p;
	if (kern_path(fd_path, LOOKUP_FOLLOW, &p)) {
		pr_err("preinit: %s not reachable, booting without preinit\n", fd_path);
		ksu_close_fd(fd);
		return;
	}
	path_put(&p);

#if 0 // this does work, but yeah, lets be uniform and a be tad bit safer
	__builtin_memcpy(*filename, fd_path, len + 1);
#endif
	void __user *filename_user = userspace_stack_buffer(fd_path, len + 1);
	if (!filename_user)
		return;

	pr_info("preinit: syscall(SYS_execve, (long)\"%s\", 0x%lx, NULL);\n", fd_path, (uintptr_t)*(void ***)u_argv);

	long eret = ksyscall(execve, filename_user, (const char __user *const __user *)*(void ***)u_argv, NULL);
	pr_info("preinit: kernel_execve runner returned: %ld \n", eret);
}

// filename is void *char __user *
static noinline void ksu_preinit_handle_uexecve(const char __user **filename, void *u_argv)
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

	if (!is_selinux_setup((const char __user *const __user *)*(void ***)u_argv))
		return;

	pr_info("preinit: sys_execve: %s with selinux_setup! \n", INIT_PATH);

	kthread_run(ksu_disable_preinit_branch, nullptr, "kthread");

	int fd = ksu_stage_preinit_binary();
	if (fd < 0)
		pr_info("preinit: get fd failed: %d\n", fd);

	char fd_path[32];
	int len = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

	struct path p;
	if (kern_path(fd_path, LOOKUP_FOLLOW, &p)) {
		pr_err("preinit: %s not reachable, booting without preinit\n", fd_path);
		ksu_close_fd(fd);
		return;
	}
	path_put(&p);

	void *orig = *filename;
	*filename = userspace_stack_buffer(fd_path, len + 1);

	pr_info("preinit: syscall(SYS_execve, (long)\"%s\", 0x%lx, NULL);\n", fd_path, (uintptr_t)*(void ***)u_argv);

	long eret = ksyscall(execve, *filename, (const char __user *const __user *)*(void ***)u_argv, NULL);
	pr_info("preinit: sys_execve runner returned: %ld \n", eret);
	*filename = orig;
}

static inline void ksu_preinit_kernel_execve_hook(void **filename, void *k_argv)
{
	if (static_branch_unlikely(&ksu_preinit_key))
		ksu_preinit_handle_kexecve(filename, k_argv);
}

static inline void ksu_preinit_user_execve_hook(const char __user **filename, void *u_argv)
{
	if (static_branch_unlikely(&ksu_preinit_key))
		ksu_preinit_handle_uexecve(filename, u_argv);
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
