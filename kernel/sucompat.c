#include <linux/dcache.h>
#include <linux/security.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#ifdef CONFIG_KSU_SUSFS_SUS_SU
#include <linux/susfs_def.h>
#endif
#else
#include <linux/sched.h>
#endif

#include "objsec.h"
#include "allowlist.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

#ifndef CONFIG_KSU_KPROBES_HOOK
static bool ksu_sucompat_non_kp __read_mostly = true;
#endif

#ifndef CONFIG_KSU_SUSFS_SUS_SU
bool ksu_devpts_hook __read_mostly = true;
#endif

extern void ksu_escape_to_root();

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
    static const char sh_path[] = SH_PATH;
    return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
	const char su[] = SU_PATH;

#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_sucompat_non_kp) {
 		return 0;
 	}
#endif

	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}

	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su, sizeof(su)))) {
		pr_info("faccessat su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) && defined(CONFIG_KSU_SUSFS_SUS_SU)
struct filename* susfs_ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags) {
    const char su[] = SU_PATH;
    struct filename *name = getname_flags(*filename_user, getname_statx_lookup_flags(*flags), NULL);

    if (unlikely(IS_ERR(name) || name->name == NULL)) {
        return name;
    }

    if (!ksu_is_allow_uid(current_uid().val)) {
        return name;
    }

    if (likely(memcmp(name->name, su, sizeof(su)))) {
        return name;
    }

    const char sh[] = SH_PATH;
    pr_info("vfs_fstatat su->sh!\n");
    memcpy((void *)name->name, sh, sizeof(sh));
    return name;
}
#endif

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	// const char sh[] = SH_PATH;
	const char su[] = SU_PATH;

#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_sucompat_non_kp) {
 		return 0;
 	}
#endif

	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}

	if (unlikely(!filename_user)) {
		return 0;
	}

	char path[sizeof(su) + 1];
	memset(path, 0, sizeof(path));
// Remove this later!! we use syscall hook, so this will never happen!!!!!
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0) && 0
	// it becomes a `struct filename *` after 5.18
	// https://elixir.bootlin.com/linux/v5.18/source/fs/stat.c#L216
	const char sh[] = SH_PATH;
	struct filename *filename = *((struct filename **)filename_user);
	if (IS_ERR(filename)) {
		return 0;
	}
	if (likely(memcmp(filename->name, su, sizeof(su))))
		return 0;
	pr_info("vfs_statx su->sh!\n");
	memcpy((void *)filename->name, sh, sizeof(sh));
#else
	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su, sizeof(su)))) {
		pr_info("newfstatat su->sh!\n");
		*filename_user = sh_user_path();
	}
#endif

	return 0;
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *__never_use_argv, void *__never_use_envp, int *__never_use_flags)
{
	struct filename *filename;
    const char su[] = SU_PATH;
    const char ksud[] = KSUD_PATH;

#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_sucompat_non_kp) {
 		return 0;
 	}
#endif

	if (unlikely(!filename_ptr)) {
    return 0;
	}

	filename = *filename_ptr;

	if (IS_ERR(filename)) {
		return 0;
	}

    if (likely(memcmp(filename->name, su, sizeof(su))))
        return 0;

    if (!ksu_is_allow_uid(current_uid().val))
        return 0;

    pr_info("do_execveat_common su found\n");
    memcpy((void *)filename->name, ksud, sizeof(ksud));

    ksu_escape_to_root();

    return 0;
}

int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user, void *__never_use_argv, void *__never_use_envp, int *__never_use_flags)
{
	const char su[] = SU_PATH;
	char path[sizeof(su) + 1];


#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_sucompat_non_kp){
 		return 0;
 	}
#endif

	if (unlikely(!filename_user))
		return 0;

	/*
	 * nofault variant fails silently due to pagefault_disable
	 * some cpus dont really have that good speculative execution
	 * access_ok to substitute set_fs, we check if pointer is accessible
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
	if (!access_ok(VERIFY_READ, *filename_user, sizeof(path)))
		return 0;
#else
	if (!access_ok(*filename_user, sizeof(path)))
		return 0;
#endif
	// success = returns number of bytes and should be less than path
	long len = strncpy_from_user(path, *filename_user, sizeof(path));
	if (len <= 0)
		return 0;

	// strncpy_from_user_nofault does this too
	path[sizeof(path) - 1] = '\0';

    if (likely(memcmp(path, su, sizeof(su))))
        return 0;

    if (!ksu_is_allow_uid(current_uid().val))
        return 0;

    pr_info("sys_execve su found\n");
    *filename_user = ksud_user_path();

    ksu_escape_to_root();

    return 0;
}

int ksu_handle_devpts(struct inode *inode)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_sucompat_non_kp) {
		return 0;
	}
#endif

	if (!current->mm) {
		return 0;
	}

    uid_t uid = current_uid().val;
    if (uid % 100000 < 10000) {
        return 0;
    }

	if (!ksu_is_allow_uid(uid))
		return 0;

	if (ksu_devpts_sid) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
		struct inode_security_struct *sec = selinux_inode(inode);
#else
        struct inode_security_struct *sec = (struct inode_security_struct *)inode->i_security;
#endif
		if (sec) {
			sec->sid = ksu_devpts_sid;
		}
	}

	return 0;
}

#ifdef CONFIG_KSU_KPROBES_HOOK
static int faccessat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int *dfd = (int *)&PT_REGS_PARM1(real_regs);
	const char __user **filename_user =
		(const char **)&PT_REGS_PARM2(real_regs);
	int *mode = (int *)&PT_REGS_PARM3(real_regs);

	return ksu_handle_faccessat(dfd, filename_user, mode, NULL);
}

static int newfstatat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int *dfd = (int *)&PT_REGS_PARM1(real_regs);
	const char __user **filename_user =
		(const char **)&PT_REGS_PARM2(real_regs);
	int *flags = (int *)&PT_REGS_SYSCALL_PARM4(real_regs);

	return ksu_handle_stat(dfd, filename_user, flags);
}

static int execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	const char __user **filename_user =
		(const char **)&PT_REGS_PARM1(real_regs);

	return ksu_handle_execve_sucompat(AT_FDCWD, filename_user, NULL, NULL,
					  NULL);
}

static int pts_unix98_lookup_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct inode *inode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	struct file *file = (struct file *)PT_REGS_PARM2(regs);
	inode = file->f_path.dentry->d_inode;
#else
	inode = (struct inode *)PT_REGS_PARM2(regs);
#endif

	return ksu_handle_devpts(inode);
}

static struct kprobe *init_kprobe(const char *name,
				  kprobe_pre_handler_t handler)
{
	struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
	if (!kp)
		return NULL;
	kp->symbol_name = name;
	kp->pre_handler = handler;

	int ret = register_kprobe(kp);
	pr_info("sucompat: register_%s kprobe: %d\n", name, ret);
	if (ret) {
		kfree(kp);
		return NULL;
	}

	return kp;
}

static void destroy_kprobe(struct kprobe **kp_ptr)
{
	struct kprobe *kp = *kp_ptr;
	if (!kp)
		return;
	unregister_kprobe(kp);
	synchronize_rcu();
	kfree(kp);
	*kp_ptr = NULL;
}

static struct kprobe *su_kps[6];
#endif

// sucompat: permited process can execute 'su' to gain root access.
void ksu_sucompat_init()
{
#ifdef CONFIG_KSU_KPROBES_HOOK
	su_kps[0] = init_kprobe(SYS_EXECVE_SYMBOL, execve_handler_pre);
	su_kps[1] = init_kprobe(SYS_EXECVE_COMPAT_SYMBOL, execve_handler_pre);
	su_kps[2] = init_kprobe(SYS_FACCESSAT_SYMBOL, faccessat_handler_pre);
	su_kps[3] = init_kprobe(SYS_NEWFSTATAT_SYMBOL, newfstatat_handler_pre);
	su_kps[4] = init_kprobe(SYS_FSTATAT64_SYMBOL, newfstatat_handler_pre);
	su_kps[5] = init_kprobe("pts_unix98_lookup", pts_unix98_lookup_pre);
#else
	ksu_sucompat_non_kp = true;
	pr_info("ksu_sucompat_init: hooks enabled: execve/execveat_su, faccessat, stat\n");
#endif
}

void ksu_sucompat_exit()
{
#ifdef CONFIG_KSU_KPROBES_HOOK
	int i;
	for (i = 0; i < ARRAY_SIZE(su_kps); i++) {
		destroy_kprobe(&su_kps[i]);
	}
#else
	ksu_sucompat_non_kp = false;
	pr_info("ksu_sucompat_exit: hooks disabled: execve/execveat_su, faccessat, stat\n");
#endif
}

#ifdef CONFIG_KSU_SUSFS_SUS_SU
extern bool ksu_su_compat_enabled;
bool ksu_devpts_hook = false;
bool susfs_is_sus_su_hooks_enabled __read_mostly = false;
int susfs_sus_su_working_mode = 0;

static bool ksu_is_su_kps_enabled(void) {
	int i;
	for (i = 0; i < ARRAY_SIZE(su_kps); i++) {
		if (su_kps[i]) {
			return true;
		}
	}
	return false;
}

void ksu_susfs_disable_sus_su(void) {
	susfs_is_sus_su_hooks_enabled = false;
	ksu_devpts_hook = false;
	susfs_sus_su_working_mode = SUS_SU_DISABLED;
	// Re-enable the su_kps for user, users need to toggle off the kprobe hooks again in ksu manager if they want it disabled.
	if (!ksu_is_su_kps_enabled()) {
		ksu_sucompat_init();
		ksu_su_compat_enabled = true;
	}
}

void ksu_susfs_enable_sus_su(void) {
	if (ksu_is_su_kps_enabled()) {
		ksu_sucompat_exit();
		ksu_su_compat_enabled = false;
	}
	susfs_is_sus_su_hooks_enabled = true;
	ksu_devpts_hook = true;
	susfs_sus_su_working_mode = SUS_SU_WITH_HOOKS;
}
#endif // CONFIG_KSU_SUSFS_SUS_SU
