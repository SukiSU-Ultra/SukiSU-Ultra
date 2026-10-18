// Block kernel modules from loading by reusing the kernel's native
// `module_blacklist` (consulted by blacklisted() before a module is laid out),
// instead of hooking init_module/finit_module. It is the standard mechanism and
// needs nothing maintained on our side.
//
// The list is supplied via the `block_modules=name1,name2,...` module param,
// which flows in through ksu_config (boot-patch / boot-patch-v2) or the kernel
// cmdline (built-in). Names use the kernel form (underscores, e.g.
// `oplus_secure_guard`).

#define KSU_MODULES_TO_BLOCK "ksu,kernelsu"

static char block_modules[256];

// The param may be parsed before the slab allocator is up (built-in), so copy
// into a static buffer instead of allocating. Truncate rather than fail: a
// param error would abort the whole KernelSU load.
static int block_modules_param_set(const char *val, const struct kernel_param *kp)
{
	if (!val || !val[0])
		return 0;

	if (strscpy(block_modules, val, sizeof(block_modules)) < 0)
		pr_err("module_blacklist: block_modules too long, truncated — some modules will not be blocked\n");

	return 0;
}

static const struct kernel_param_ops block_modules_param_ops = {
	// A bare `block_modules` would otherwise fail parse_args() and the load
	.flags = KERNEL_PARAM_OPS_FL_NOARG,
	.set = block_modules_param_set,
};
module_param_cb(block_modules, &block_modules_param_ops, NULL, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) && defined(CONFIG_ARM64)
#define __AARCH64_init_module 105
static syscall_fn_t aarch64_init_module __read_mostly = nullptr;
asmlinkage long hook_aarch64_init_module_ret(const struct pt_regs *regs)
{
	extern long __arm64_sys_init_module(const struct pt_regs *regs);
	long ret = __arm64_sys_init_module(regs);
	if (ret == -EPERM)
		return 0;
	return ret;
}

#define __AARCH64_finit_module 273
static syscall_fn_t aarch64_finit_module __read_mostly = nullptr;
asmlinkage long hook_aarch64_finit_module_ret(const struct pt_regs *regs)
{
	extern long __arm64_sys_finit_module(const struct pt_regs *regs);
	long ret = __arm64_sys_finit_module(regs);
	if (ret == -EPERM)
		return 0;
	return ret;
}

static int ksu_unhook_syscall_init_module(void *unused)
{
	set_user_nice(current, 19); // low prio
	pr_info("%s: kthread init!\n", __func__);

start: // watchdog will flip this anyway, we can loop forever
	if (!!*(volatile bool *)&ksu_boot_completed)
		goto cleanup;
	msleep(10000);
	goto start;

cleanup:
	restore_syscall((void *)&aarch64_init_module, __AARCH64_init_module, (void *)hook_aarch64_init_module_ret, (void *)sys_call_table);
	restore_syscall((void *)&aarch64_finit_module, __AARCH64_finit_module, (void *)hook_aarch64_finit_module_ret, (void *)sys_call_table);

	pr_info("%s: kthread exit!\n", __func__);
	return 0;
}

static inline void ksu_hook_syscall_init_module(void)
{
	read_and_replace_syscall((void *)&aarch64_init_module, __AARCH64_init_module, (void *)hook_aarch64_init_module_ret, (void *)sys_call_table);
	read_and_replace_syscall((void *)&aarch64_finit_module, __AARCH64_finit_module, (void *)hook_aarch64_finit_module_ret, (void *)sys_call_table);

	kthread_run(ksu_unhook_syscall_init_module, NULL, "kthread");
}
#endif

// Merge the configured names into the kernel's native module_blacklist.
void __init ksu_module_blacklist_init(void)
{
	char **native_blacklist;
	const char *existing;
	char *merged;
	size_t existing_len;

	static_assert(sizeof(KSU_MODULES_TO_BLOCK) > 0);
	char combined[256 + sizeof(KSU_MODULES_TO_BLOCK)];

	if (!block_modules[0])
		snprintf(combined, sizeof(combined), "%s", KSU_MODULES_TO_BLOCK);
	else
		snprintf(combined, sizeof(combined), "%s,%s", KSU_MODULES_TO_BLOCK, block_modules);

	native_blacklist = (char **)find_kernel_symbol_exact("module_blacklist");
	if (!native_blacklist) {
		pr_warn("module_blacklist: symbol not found, cannot block modules\n");
		return;
	}

	existing = *native_blacklist;
	existing_len = existing ? strlen(existing) : 0;

	// Merge with any existing blacklist (e.g. one set on the kernel cmdline).
	merged = kasprintf(GFP_KERNEL, "%s%s%s", existing_len ? existing : "", existing_len ? "," : "", combined);
	if (!merged) {
		pr_err("module_blacklist: cannot allocate blacklist\n");
		return;
	}

	// Release-publish: pairs with the address dependency in the lockless
	// blacklisted() reader so it can never observe the new pointer before the
	// string contents are visible.
	smp_store_release(native_blacklist, merged);
	// Force every other CPU through a memory barrier so any module load already
	// in flight observes the new list right away (suggested by @backslashxx).
	kick_all_cpus_sync();
	pr_info("module_blacklist: blocking modules: %s\n", merged);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) && defined(CONFIG_ARM64)
	ksu_hook_syscall_init_module();
#endif
}

#undef KSU_MODULES_TO_BLOCK

void __exit ksu_module_blacklist_exit(void)
{
	// Intentionally does NOT restore the original module_blacklist pointer.
	// The module loader reads module_blacklist in blacklisted() without any
	// lock or READ_ONCE, testing it for NULL and then dereferencing it; swapping
	// the pointer back (especially to the common NULL) could race that reader
	// into a NULL dereference. The merged string already contains any
	// pre-existing entries and lives on the kernel heap, so leaving it installed
	// stays valid even after KernelSU is unloaded. The one-time, bounded
	// allocation is deliberately leaked.
}
