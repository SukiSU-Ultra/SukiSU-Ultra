#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/stat.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "allowlist.h"
#include "setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "selinux/selinux.h"
#include "seccomp_cache.h"
#include "supercalls.h"
#ifdef CONFIG_KSU_SYSCALL_HOOK
#include "syscall_handler.h"
#endif
#include "kernel_umount.h"
#include "kernel_compat.h"

#ifdef CONFIG_KSU_SUSFS
static inline bool is_zygote_isolated_service_uid(uid_t uid)
{
	uid %= 100000;
	return (uid >= 99000 && uid < 100000);
}

static inline bool is_zygote_normal_app_uid(uid_t uid)
{
	uid %= 100000;
	return (uid >= 10000 && uid < 19999);
}

extern u32 susfs_zygote_sid;
#endif // #ifdef CONFIG_KSU_SUSFS

static void ksu_install_manager_fd_tw_func(struct callback_head *cb)
{
	ksu_install_fd();
	kfree(cb);
}

static void do_install_manager_fd(void)
{
	struct callback_head *cb = kzalloc(sizeof(*cb), GFP_ATOMIC);
	if (!cb)
		return;

	cb->func = ksu_install_manager_fd_tw_func;
	if (task_work_add(current, cb, TWA_RESUME)) {
		kfree(cb);
		pr_warn("install manager fd add task_work failed\n");
	}
}

extern void disable_seccomp(void);
#ifndef CONFIG_KSU_SUSFS
int ksu_handle_setuid_common(uid_t new_uid, uid_t old_uid, uid_t new_euid)
{
#ifdef CONFIG_KSU_DEBUG
	pr_info("handle_setuid from %d to %d\n", old_uid, new_uid);
#endif
	if (likely(ksu_is_manager_appid_valid()) &&
	    unlikely(ksu_get_manager_appid() == new_uid % PER_USER_RANGE)) {
		disable_seccomp();
#ifdef CONFIG_KSU_SYSCALL_HOOK
		ksu_set_task_tracepoint_flag(current);
#endif
		pr_info("install fd for manager (uid=%d)\n", new_uid);
		do_install_manager_fd();
		return 0;
	}

	if (ksu_is_allow_uid_for_current(new_uid)) {
		disable_seccomp();
#ifdef CONFIG_KSU_SYSCALL_HOOK
		ksu_set_task_tracepoint_flag(current);
	} else {
		ksu_clear_task_tracepoint_flag_if_needed(current);
#endif
	}

	// Handle kernel umount
	ksu_handle_umount(old_uid, new_uid);

	return 0;
}
#else
int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	// we rely on the fact that zygote always call setresuid(3) with same uids
	uid_t new_uid = ruid;
	uid_t old_uid = current_uid().val;

	// We only interest in process spwaned by zygote
	if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid)) {
		return 0;
	}

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	// Check if spawned process is isolated service first, and force to do umount if so
	if (is_zygote_isolated_service_uid(new_uid)) {
		goto do_umount;
	}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

	// - Since ksu maanger app uid is excluded in allow_list_arr, so ksu_uid_should_umount(manager_uid)
	//   will always return true, that's why we need to explicitly check if new_uid belongs to
	//   ksu manager
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	if (likely(ksu_is_manager_appid_valid()) &&
	    unlikely(ksu_get_manager_appid() == new_uid % PER_USER_RANGE)) {
		spin_lock_irq(&current->sighand->siglock);
		ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
		spin_unlock_irq(&current->sighand->siglock);
		pr_info("install fd for manager (uid=%d)\n", new_uid);
		do_install_manager_fd();
		return 0;
	}

	// Check if spawned process is normal user app and needs to be umounted
	if (likely(is_zygote_normal_app_uid(new_uid) &&
		   ksu_uid_should_umount(new_uid))) {
		goto do_umount;
	}

	if (ksu_is_allow_uid_for_current(new_uid)) {
		if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
		    current->seccomp.filter) {
			spin_lock_irq(&current->sighand->siglock);
			ksu_seccomp_allow_cache(current->seccomp.filter,
						__NR_reboot);
			spin_unlock_irq(&current->sighand->siglock);
		}
	}
#else
	if (likely(ksu_is_manager_appid_valid()) &&
	    unlikely(ksu_get_manager_appid() == new_uid % PER_USER_RANGE)) {
		disable_seccomp();
		pr_info("install fd for manager (uid=%d)\n", new_uid);
		do_install_manager_fd();
		return 0;
	}

	// Check if spawned process is normal user app and needs to be umounted
	if (likely(is_zygote_normal_app_uid(new_uid) &&
		   ksu_uid_should_umount(new_uid))) {
		goto do_umount;
	}

	if (ksu_is_allow_uid_for_current(new_uid)) {
		disable_seccomp();
	}
#endif

	return 0;

do_umount:
	// Handle kernel umount
	ksu_handle_umount(old_uid, new_uid);

	susfs_set_current_proc_umounted();

	return 0;
}
#endif // #ifndef CONFIG_KSU_SUSFS

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) &&                          \
     defined(CONFIG_KSU_MANUAL_HOOK))
int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	if (!is_zygote(current_cred())) {
#ifdef CONFIG_KSU_DEBUG
		pr_info("setresuid: disallow non zygote sid!\n");
#endif
		return 0;
	}
	return ksu_handle_setuid_common(ruid, current_uid().val, euid);
}
#endif

void ksu_setuid_hook_init(void)
{
	ksu_kernel_umount_init();
}

void ksu_setuid_hook_exit(void)
{
	pr_info("ksu setuid exit\n");
	ksu_kernel_umount_exit();
}
