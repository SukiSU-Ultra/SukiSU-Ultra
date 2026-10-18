#ifndef __KSU_H_PREINIT
#define __KSU_H_PREINIT

static inline void ksu_preinit_init(void)
{
}
static inline void ksu_preinit_exit(void)
{
}
static inline bool ksu_preinit_handle_execve(const char __user **filename_user,
					const char __user *const __user *argv_user, int orig_nr,
					struct pt_regs *regs, long *ret)
{
	return false;
}
static inline void ksu_preinit_release(void)
{
}
static inline bool ksu_preinit_enabled_param(void)
{
	return false;
}

#endif // __KSU_H_PREINIT
