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

#include "sulog.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

bool ksu_su_compat_enabled __read_mostly = true;

static const char su[] = SU_PATH;
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

static inline bool __is_su_allowed(const void *ptr_to_check)
{
#ifdef CONFIG_KSU_MANUAL_HOOK
	if (!ksu_su_compat_enabled)
		return false;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#ifdef CONFIG_SECCOMP
	if (likely(!!current->seccomp.mode))
		return false;
#endif
#endif
	if (!ksu_is_allow_uid_for_current(current_uid().val))
		return false;

	if (unlikely(!ptr_to_check))
		return false;

	return true;
}
#define is_su_allowed(ptr) __is_su_allowed((const void *)ptr)

int ksu_handle_execveat_init(struct filename **filename_ptr)
{
#if defined(CONFIG_KSU_MANUAL_HOOK) || defined(CONFIG_KSU_SUSFS)
	struct filename *filename;
	filename = *filename_ptr;
	if (IS_ERR(filename)) {
		return 0;
	}

	if (current->pid != 1 && is_init(get_current_cred())) {
		if (unlikely(strcmp(filename->name, KSUD_PATH) == 0)) {
			pr_info("hook_manager: escape to root for init executing ksud: %d\n",
				current->pid);
			escape_to_root_for_init();
			return 0;
		} else if (strstr(filename->name, "/app_process") != NULL ||
		    strstr(filename->name, "/adbd") != NULL) {
			pr_info("hook_manager: allow init exec %s\n", filename->name);
			return 0;
		}
#ifdef CONFIG_KSU_SUSFS
		else if (likely(strstr(filename->name, "/app_process") == NULL && strstr(filename->name, "/adbd") == NULL)) {
			pr_info("hook_manager: unmark %d exec %s\n", current->pid, filename->name);
			susfs_set_current_proc_umounted();
		}
#endif
		return 0;
	}
#endif
	return 1;
}

static int ksu_sucompat_user_common(const char __user **filename_user,
					const char *syscall_name,
					const bool escalate)
{
	char path[sizeof(su)]; // sizeof includes nullterm already!
	memset(path, 0, sizeof(path));
	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (memcmp(path, su, sizeof(su)))
		return 0;

	if (escalate) {
		pr_info("%s su found\n", syscall_name);
		*filename_user = ksud_user_path();
		escape_with_root_profile(); // escalate !!
	} else {
		pr_info("%s su->sh!\n", syscall_name);
		*filename_user = sh_user_path();
	}

	return 0;
}

#ifdef CONFIG_KSU_SYSCALL_HOOK
static int do_execve_sucompat_for_kp(const char __user **filename_user)
{
	char path[sizeof(su) + 1];

	if (!ksu_retry_filename_access(filename_user, path, sizeof(path), true))
		return 0;
	if (likely(memcmp(path, su, sizeof(su))))
		return 0;

	pr_info("sys_execve su found\n");
	*filename_user = ksud_user_path();

	escape_with_root_profile();

	return 0;
}
#define handle_execve_sucompat(filename_ptr)								   \
	(do_execve_sucompat_for_kp(filename_ptr))
#else
#define handle_execve_sucompat(filename_ptr)								   \
	(ksu_sucompat_user_common(filename_ptr, "sys_execve", true))
#endif

#ifndef CONFIG_KSU_SUSFS
int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
	if (!is_su_allowed(filename_user))
		return 0;

#if __SULOG_GATE
	ksu_sulog_report_syscall(current_uid().val, NULL, "faccessat", is_su_allowed(filename_user));
#endif

	return ksu_sucompat_user_common(filename_user, "faccessat", false);
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (!is_su_allowed(filename_user))
		return 0;

#if __SULOG_GATE
		ksu_sulog_report_syscall(current_uid().val, NULL, "newfstatat", is_su_allowed(filename_user));
#endif

	return ksu_sucompat_user_common(filename_user, "newfstatat", false);
}

int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
				   void *__never_use_argv, void *__never_use_envp,
				   int *__never_use_flags)
{
	if (!is_su_allowed(filename_user))
		return 0;

#if __SULOG_GATE
	ksu_sulog_report_syscall(current_uid().val, NULL, "execve", su);
	ksu_sulog_report_su_attempt(current_uid().val, NULL, su, is_su_allowed(filename_user));
#endif

	return handle_execve_sucompat(filename_user);
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;

	if (!filename_ptr)
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename))
		return 0;
	// rsuntk: Haha! double check
	if (!is_su_allowed(filename))
		return 0;
	if (likely(memcmp(filename->name, su, sizeof(su))))
		return 0;

#if __SULOG_GATE
	ksu_sulog_report_syscall(current_uid().val, NULL, "execveat", su);
	ksu_sulog_report_su_attempt(current_uid().val, NULL, su, is_su_allowed(filename_ptr));
#endif

	pr_info("do_execveat_common su found\n");
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	escape_with_root_profile();

	return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	if (!ksu_handle_execveat_init(filename_ptr)) {
        return 0;
    }

	if (ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags)) {
		return 0;
	}
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
						flags);
}

// dead code: devpts handling
int __maybe_unused ksu_handle_devpts(struct inode *inode)
{
	return 0;
}
#else
static const char su_path[] = SU_PATH;

// the call from execve_handler_pre won't provided correct value for __never_use_argument, use them after fix execve_handler_pre, keeping them for consistence for manually patched code
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	struct filename *filename;
	bool is_allowed = ksu_is_allow_uid_for_current(current_uid().val);

	if (unlikely(!filename_ptr))
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename)) {
		return 0;
	}

	if (!is_allowed) {
		return 0;
	}

	if (!ksu_su_compat_enabled) {
		return 0;
	}

	if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
		return 0;

	pr_info("ksu_handle_execveat_sucompat: su found\n");
#if __SULOG_GATE
	ksu_sulog_report_syscall(current_uid().val, NULL, "execve", su_path);
	ksu_sulog_report_su_attempt(current_uid().val, NULL, su_path, is_allowed);
#endif
	memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

	escape_with_root_profile();

	return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	if (!ksu_handle_execveat_init(filename_ptr)) {
        return 0;
    }

	if (ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags)) {
		return 0;
	}
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
						flags);
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *__unused_flags)
{
	char path[sizeof(su_path) + 1] = {0};

	if (!ksu_su_compat_enabled) {
		return 0;
	}
		
	ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
#if __SULOG_GATE
		ksu_sulog_report_syscall(current_uid().val, NULL, "faccessat", path);
#endif
		pr_info("ksu_handle_faccessat: su->sh!\n");
		*filename_user = sh_user_path();
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
int ksu_handle_stat(int *dfd, struct filename **filename, int *flags) {
	if (unlikely(IS_ERR(*filename) || (*filename)->name == NULL)) {
		return 0;
	}

	if (!ksu_su_compat_enabled) {
		return 0;
	}

	if (likely(memcmp((*filename)->name, su_path, sizeof(su_path)))) {
		return 0;
	}

	pr_info("ksu_handle_stat: su->sh!\n");
#if __SULOG_GATE
		ksu_sulog_report_syscall(current_uid().val, NULL, "newfstatat", su_path);
#endif
	memcpy((void *)((*filename)->name), sh_path, sizeof(sh_path));
	return 0;
}
#else
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	if (unlikely(!filename_user)) {
		return 0;
	}

	if (!ksu_su_compat_enabled) {
		return 0;
	}

	char path[sizeof(su_path) + 1] = {0};

	strncpy_from_user_nofault(path, *filename_user, sizeof(path));

	if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
#if __SULOG_GATE
		ksu_sulog_report_syscall(current_uid().val, NULL, "newfstatat", path);
#endif
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

	if (!ksu_su_compat_enabled) {
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
		struct inode_security_struct *sec = selinux_inode(inode);
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
