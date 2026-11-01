#ifndef __KSU_H_PREINIT
#define __KSU_H_PREINIT

#if !defined(CONFIG_ARM64) || !defined(KSU_CAN_USE_JUMP_LABEL)
#define KSU_NO_PREINIT
#endif

#ifndef KSU_NO_PREINIT

void ksu_preinit_init(void);
void ksu_preinit_exit(void);

// NOTE: even if this has to be enabled by default, this has better codegen on execve.
DEFINE_STATIC_KEY_FALSE(ksu_preinit_key);

static inline void ksu_preinit_kernel_execve_hook(void **filename, void *k_argv, void *k_envp);
static inline void ksu_preinit_user_execve_hook(const char __user **filename, void *u_argv, void *u_envp);

static int ksu_disable_preinit_branch(void *data)
{
	static bool disabled = false;
	if (disabled)
		return 0;

	pr_info("preinit: remove preinit execve branches\n");
	static_branch_disable(&ksu_preinit_key);
	kick_all_cpus_sync();

	disabled = true;
	return 0;
}
#else

#define ksu_preinit_init() do { } while (0)
#define ksu_preinit_exit() do { } while (0)

#define ksu_preinit_kernel_execve_hook(...)	do { } while (0)
#define ksu_preinit_user_execve_hook(...)	do { } while (0)

#define ksu_disable_preinit_branch(...)		do { } while (0)

#endif // KSU_NO_PREINIT

#endif // __KSU_H_PREINIT
