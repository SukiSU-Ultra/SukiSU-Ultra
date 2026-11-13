#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#define KSUD_PATH "/data/adb/ksud"

void ksu_ksud_init();
void ksu_ksud_exit();

static void ksu_stop_input_hook_runtime();

static bool ksu_vfs_read_hook __read_mostly;
static bool ksu_input_hook __read_mostly;

#ifdef CONFIG_KSU_SUSFS
/*
 * The SUSFS kernel patch passes the kernel's own struct user_arg_ptr
 * (include/linux/binfmts.h) to the inline hook callbacks. fs/exec.c has a
 * private copy of this helper; we need our own for preinit.
 */
#define KSU_MAX_ARG_STRINGS 0x7FFFFFFF

static inline const char __user *ksu_get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}
#endif // CONFIG_KSU_SUSFS

#endif
