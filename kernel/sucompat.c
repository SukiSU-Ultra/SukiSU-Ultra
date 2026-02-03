#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/compiler.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif
#include <asm/current.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#include <linux/namei.h>
#include "selinux/selinux.h"
#include "objsec.h"
#endif // #ifdef CONFIG_KSU_SUSFS

#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"
#include "sucompat.h"
#include "app_profile.h"
#ifdef CONFIG_KSU_SYSCALL_HOOK
#include "kp_util.h"
#endif
#include "selinux/selinux.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

bool ksu_su_compat_enabled __read_mostly = true;

static const char su_path[] = SU_PATH;
static const char ksud_path[] = KSUD_PATH;
static const char sh_path[] = SH_PATH;

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_su_compat_enabled = enable;
	pr_info("su_compat: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	// To avoid having to mmap a page in userspace, just write below the stack
	// pointer.
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
	return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
	return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

static inline bool is_su_allowed(void)
{
#if defined(CONFIG_KSU_MANUAL_HOOK) && !defined(CONFIG_KSU_SUSFS)
	if (!ksu_su_compat_enabled)
		return false;
#endif
#ifdef CONFIG_SECCOMP
	if (likely(!!current->seccomp.mode))
		return false;
#endif
	if (!ksu_is_allow_uid_for_current(current_uid().val))
		return false;

	return true;
}

static inline void ksu_handle_execveat_init(struct filename **filename_ptr)
{
	struct filename *filename;
	filename = *filename_ptr;

	if (unlikely(!filename_ptr))
		return;
	if (IS_ERR(filename))
		return;

	if (current->pid != 1 && is_init(get_current_cred())) {
		if (unlikely(strcmp(filename->name, KSUD_PATH) == 0)) {
			pr_info("hook_manager: escape to root for init executing ksud: %d\n",
				current->pid);
			escape_to_root_for_init();
		}
#ifdef CONFIG_KSU_SUSFS
		else if (likely(strstr(filename->name, "/app_process") == NULL &&
				strstr(filename->name, "/adbd") == NULL) &&
				!susfs_is_current_proc_umounted()) {
					pr_info("susfs: mark no sucompat checks for pid: '%d', exec: '%s'\n", current->pid, filename->name);
					susfs_set_current_proc_umounted();
		}
#endif
	}
}

static int ksu_sucompat_user_common(const char __user **filename_user,
				    const char *syscall_name,
				    const bool escalate)
{
	char path[sizeof(su_path) + 1];

	if (unlikely(!filename_user))
		return 0;
	if (!is_su_allowed())
		return 0;

	memset(path, 0, sizeof(path));
	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (memcmp(path, su_path, sizeof(su_path)))
		return 0;

	if (escalate) {
		write_sulog('x');
		pr_info("%s su found\n", syscall_name);
		*filename_user = ksud_user_path();
		escape_with_root_profile(); // escalate !!
	} else {
		write_sulog('$');
		pr_info("%s su->sh!\n", syscall_name);
		*filename_user = sh_user_path();
	}

	return 0;
}

#ifdef CONFIG_KSU_SYSCALL_HOOK
static int do_execve_sucompat_for_kp(const char __user **filename_user)
{
	char path[sizeof(su_path) + 1];

	if (unlikely(!filename_user))
		return 0;
	if (!is_su_allowed())
		return 0;
	if (!ksu_retry_filename_access(filename_user, path, sizeof(path), true))
		return 0;
	if (likely(memcmp(path, su_path, sizeof(su_path))))
		return 0;

	pr_info("sys_execve su found\n");
	*filename_user = ksud_user_path();

	escape_with_root_profile();

	return 0;
}
#define handle_execve_sucompat(filename_ptr)                                   \
	(do_execve_sucompat_for_kp(filename_ptr))
#else
#define handle_execve_sucompat(filename_ptr)                                   \
	(ksu_sucompat_user_common(filename_ptr, "sys_execve", true))
#endif

#ifndef CONFIG_KSU_SUSFS
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
	return ksu_sucompat_user_common(filename_user, "faccessat", false);
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	return ksu_sucompat_user_common(filename_user, "newfstatat", false);
}

int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
			       void *__never_use_argv, void *__never_use_envp,
			       int *__never_use_flags)
{
	return handle_execve_sucompat(filename_user);
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;

	if (unlikely(!filename_ptr))
		return 0;
	if (!is_su_allowed())
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename))
		return 0;
	if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
		return 0;

	pr_info("do_execveat_common su found\n");
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	escape_with_root_profile();

	return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	ksu_handle_execveat_init(filename_ptr);
	ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
					    flags);
}

// dead code: devpts handling
int __maybe_unused ksu_handle_devpts(struct inode *inode)
{
	return 0;
}
#else
// the call from execve_handler_pre won't provided correct value for __never_use_argument, use them after fix execve_handler_pre, keeping them for consistence for manually patched code
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;

	if (unlikely(!filename_ptr))
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename)) {
		return 0;
	}

	if (!ksu_is_allow_uid_for_current(current_uid().val)) {
		write_sulog('$');
		return 0;
	}

	if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
		return 0;

	write_sulog('x');
	pr_info("ksu_handle_execveat_sucompat: su found\n");
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	escape_with_root_profile();

	return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	ksu_handle_execveat_init(filename_ptr);
	ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
					    flags);
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
	char path[sizeof(su_path) + 1] = { 0 };

	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		pr_info("ksu_handle_faccessat: su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
int ksu_handle_stat(int *dfd, struct filename **filename, int *flags)
{
	if (unlikely(IS_ERR(*filename) || (*filename)->name == NULL)) {
		return 0;
	}

	if (likely(memcmp((*filename)->name, su_path, sizeof(su_path)))) {
		return 0;
	}

	pr_info("ksu_handle_stat: su->sh!\n");
	memcpy((void *)((*filename)->name), sh_path, sizeof(sh_path));
	return 0;
}
#else
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	char path[sizeof(su_path) + 1] = { 0 };

	if (unlikely(!filename_user)) {
		return 0;
	}

	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
		pr_info("ksu_handle_stat: su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)

int ksu_handle_devpts(struct inode *inode)
{
	if (!current->mm) {
		return 0;
	}

	uid_t uid = current_uid().val;
	if (uid % 100000 < 10000) {
		// not untrusted_app, ignore it
		return 0;
	}

	if (!__ksu_is_allow_uid_for_current(uid))
		return 0;

	if (ksu_file_sid) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) ||                           \
	defined(KSU_OPTIONAL_SELINUX_INODE)
		struct inode_security_struct *sec = selinux_inode(inode);
#else
		struct inode_security_struct *sec =
			(struct inode_security_struct *)inode->i_security;
#endif
		if (sec) {
			sec->sid = ksu_file_sid;
		}
	}

	return 0;
}
#endif // #ifndef CONFIG_KSU_SUSFS

// sucompat: permitted process can execute 'su' to gain root access.
void ksu_sucompat_init(void)
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}
}

void ksu_sucompat_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
