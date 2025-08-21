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
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif

#include "objsec.h"
#include "allowlist.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"
#include "include/ksu_creds.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

static const char su[] = SU_PATH;
static const char ksud_path[] = KSUD_PATH;

extern void escape_to_root();

bool ksu_sucompat_hook_state __read_mostly = true;

static inline void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static inline char __user *sh_user_path(void)
{
	const char sh_path[] = SH_PATH;
	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static inline char __user *ksud_user_path(void)
{
	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static inline bool __is_su_allowed(const void *ptr_to_check)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_sucompat_hook_state)
		return false;
#endif
	if (likely(!ksu_is_allow_uid(ksu_current_uid())))
		return false;

	if (unlikely(!ptr_to_check))
		return false;

	return true;
}
#define is_su_allowed(ptr) __is_su_allowed((const void *)ptr)

static int ksu_sucompat_user_common(const char __user **filename_user,
				    const char *syscall_name,
				    const bool escalate)
{
	char path[sizeof(su)]; // sizeof includes nullterm already!
	memset(path, 0, sizeof(path));

	ksu_strncpy_from_user_retry(path, *filename_user, sizeof(path));

	if (memcmp(path, su, sizeof(su)))
		return 0;

	if (escalate) {
		pr_info("%s su found\n", syscall_name);
		*filename_user = ksud_user_path();
		escape_to_root(); // escalate !!
	} else {
		pr_info("%s su->sh!\n", syscall_name);
		*filename_user = sh_user_path();
	}

	return 0;
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
	if (!is_su_allowed(filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "faccessat", false);
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (!is_su_allowed(filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "newfstatat", false);
}

int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
			       void *__never_use_argv, void *__never_use_envp,
			       int *__never_use_flags)
{
	if (!is_su_allowed(filename_user))
		return 0;

	return ksu_sucompat_user_common(filename_user, "sys_execve", true);
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;

	if (!is_su_allowed(filename_ptr))
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename))
		return 0;

	if (likely(memcmp(filename->name, su, sizeof(su))))
		return 0;

	pr_info("do_execveat_common su found\n");
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	escape_to_root();

	return 0;
}

static int ksu_inline_handle_devpts(struct inode *inode)
{
	if (!current->mm) {
		return 0;
	}

	uid_t uid = ksu_current_uid();
	if (uid % 100000 < 10000) {
		// not untrusted_app, ignore it
		return 0;
	}

	if (!ksu_is_allow_uid(uid))
		return 0;

	if (ksu_devpts_sid) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
		struct inode_security_struct *sec = selinux_inode(inode);
#else
		struct inode_security_struct *sec =
			(struct inode_security_struct *)inode->i_security;
#endif
		if (sec) {
			sec->sid = ksu_devpts_sid;
		}
	}

	return 0;
}

int __ksu_handle_devpts(struct inode *inode)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
	if (!ksu_sucompat_hook_state)
		return 0;
#endif
	return ksu_inline_handle_devpts(inode);
}

// dead code, we are phasing out ksu_handle_devpts for LSM hooks.
int __maybe_unused ksu_handle_devpts(struct inode *inode)
{
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

#ifdef MODULE
static struct kprobe *su_kps[6];
static int pts_unix98_lookup_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct inode *inode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	struct file *file = (struct file *)PT_REGS_PARM2(regs);
	inode = file->f_path.dentry->d_inode;
#else
	inode = (struct inode *)PT_REGS_PARM2(regs);
#endif

	return ksu_inline_handle_devpts(inode);
}
#else
static struct kprobe *su_kps[5];
#endif

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
#ifdef MODULE
	su_kps[5] = init_kprobe("pts_unix98_lookup", pts_unix98_lookup_pre);
#endif
#else
	ksu_sucompat_hook_state = true;
	pr_info("ksu_sucompat init\n");
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
	ksu_sucompat_hook_state = false;
	pr_info("ksu_sucompat exit\n");
#endif
}
