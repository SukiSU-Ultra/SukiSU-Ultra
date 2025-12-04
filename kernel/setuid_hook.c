#include <linux/compiler.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "allowlist.h"
#include "setuid_hook.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "selinux/selinux.h"
#include "seccomp_cache.h"
#include "supercalls.h"
#if !defined(CONFIG_KSU_SUSFS) && !defined(CONFIG_KSU_MANUAL_HOOK)
#include "syscall_hook_manager.h"
#endif
#include "kernel_umount.h"
#include "sulog.h"

#ifdef CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#endif

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
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
extern void susfs_run_sus_path_loop(uid_t uid);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
extern void susfs_reorder_mnt_id(void);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#endif // #ifdef CONFIG_KSU_SUSFS

static bool ksu_enhanced_security_enabled = false;

static int enhanced_security_feature_get(u64 *value)
{
	*value = ksu_enhanced_security_enabled ? 1 : 0;
	return 0;
}

static int enhanced_security_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_enhanced_security_enabled = enable;
	pr_info("enhanced_security: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler enhanced_security_handler = {
	.feature_id = KSU_FEATURE_ENHANCED_SECURITY,
	.name = "enhanced_security",
	.get_handler = enhanced_security_feature_get,
	.set_handler = enhanced_security_feature_set,
};

static inline bool is_allow_su(void)
{
	if (is_manager()) {
		// we are manager, allow!
		return true;
	}
	return ksu_is_allow_uid_for_current(current_uid().val);
}

// force_sig kcompat, TODO: move it out of core_hook.c
// https://elixir.bootlin.com/linux/v5.3-rc1/source/kernel/signal.c#L1613
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define __force_sig(sig) force_sig(sig)
#else
#define __force_sig(sig) force_sig(sig, current)
#endif
extern void disable_seccomp(struct task_struct *tsk);

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
	// we rely on the fact that zygote always call setresuid(3) with same uids
	return ksu_handle_setuid(ruid, current_uid().val, euid);
}

#ifndef CONFIG_KSU_SUSFS
int ksu_handle_setuid(uid_t new_uid, uid_t old_uid, uid_t euid) {// (new_euid)
	if (old_uid != new_uid)
		pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

	// if old process is root, ignore it.
	if (old_uid != 0 && ksu_enhanced_security_enabled) {
		// disallow any non-ksu domain escalation from non-root to root!
		// euid is what we care about here as it controls permission
		if (unlikely(euid == 0)) {
			if (!is_ksu_domain()) {
				pr_warn("find suspicious EoP: %d %s, from %d to %d\n",
					current->pid, current->comm, old_uid,
					new_uid);
				__force_sig(SIGKILL);
				return 0;
			}
		}
		// disallow appuid decrease to any other uid if it is not allowed to su
		if (is_appuid(old_uid)) {
			if (euid < current_euid().val &&
				!ksu_is_allow_uid_for_current(old_uid)) {
				pr_warn("find suspicious EoP: %d %s, from %d to %d\n",
					current->pid, current->comm, old_uid,
					new_uid);
				__force_sig(SIGKILL);
				return 0;
			}
		}
		return 0;
	}

	// if on private space, see if its possibly the manager
	if (new_uid > PER_USER_RANGE &&
		new_uid % PER_USER_RANGE == ksu_get_manager_uid()) {
		ksu_set_manager_uid(new_uid);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	if (ksu_get_manager_uid() == new_uid) {
		pr_info("install fd for ksu manager(uid=%d)\n", new_uid);
		ksu_install_fd();
		spin_lock_irq(&current->sighand->siglock);
		ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
		ksu_set_task_tracepoint_flag(current);
		spin_unlock_irq(&current->sighand->siglock);
		return 0;
	}

	if (ksu_is_allow_uid_for_current(new_uid)) {
		if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
			current->seccomp.filter) {
			spin_lock_irq(&current->sighand->siglock);
			ksu_seccomp_allow_cache(current->seccomp.filter,
						__NR_reboot);
			spin_unlock_irq(&current->sighand->siglock);
		}
		ksu_set_task_tracepoint_flag(current);
	} else {
		ksu_clear_task_tracepoint_flag_if_needed(current);
	}
#else
	if (ksu_is_allow_uid_for_current(new_uid)) {
		spin_lock_irq(&current->sighand->siglock);
		disable_seccomp(current);
		spin_unlock_irq(&current->sighand->siglock);

		if (ksu_get_manager_uid() == new_uid) {
			pr_info("install fd for ksu manager(uid=%d)\n",
				new_uid);
			ksu_install_fd();
		}

		return 0;
	}
#endif

	// Handle kernel umount
	ksu_handle_umount(old_uid, new_uid);

	return 0;
}
#else
int ksu_handle_setuid(uid_t new_uid, uid_t old_uid, uid_t euid) {
	// if old process is root, ignore it.
	if (old_uid != 0 && ksu_enhanced_security_enabled) {
		// disallow any non-ksu domain escalation from non-root to root!
		// euid is what we care about here as it controls permission
		if (unlikely(euid == 0)) {
			if (!is_ksu_domain()) {
				pr_warn("find suspicious EoP: %d %s, from %d to %d\n", 
					current->pid, current->comm, old_uid, new_uid);
				__force_sig(SIGKILL);
				return 0;
			}
		}
		// disallow appuid decrease to any other uid if it is not allowed to su
		if (is_appuid(old_uid)) {
			if (euid < current_euid().val && !ksu_is_allow_uid_for_current(old_uid)) {
				pr_warn("find suspicious EoP: %d %s, from %d to %d\n", 
					current->pid, current->comm, old_uid, new_uid);
				__force_sig(SIGKILL);
				return 0;
			}
		}
		return 0;
	}

	// We only interest in process spwaned by zygote
	if (!susfs_is_sid_equal(current_cred()->security, susfs_zygote_sid)) {
		return 0;
	}

#if __SULOG_GATE
	ksu_sulog_report_syscall(new_uid, NULL, "setuid", NULL);
#endif

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
	if (ksu_get_manager_uid() == new_uid) {
		pr_info("install fd for ksu manager(uid=%d)\n", new_uid);
		ksu_install_fd();
		spin_lock_irq(&current->sighand->siglock);
		ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
		spin_unlock_irq(&current->sighand->siglock);
		return 0;
	}

	if (ksu_is_allow_uid_for_current(new_uid)) {
		if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
			current->seccomp.filter) {
			spin_lock_irq(&current->sighand->siglock);
			ksu_seccomp_allow_cache(current->seccomp.filter,
						__NR_reboot);
			spin_unlock_irq(&current->sighand->siglock);
		}
	} else {
		ksu_clear_task_tracepoint_flag_if_needed(current);
	}
#else
	if (ksu_is_allow_uid_for_current(new_uid)) {
		spin_lock_irq(&current->sighand->siglock);
		disable_seccomp(current);
		spin_unlock_irq(&current->sighand->siglock);

		if (ksu_get_manager_uid() == new_uid) {
			pr_info("install fd for ksu manager(uid=%d)\n",
				new_uid);
			ksu_install_fd();
		}

		return 0;
	}
#endif

	// Check if spawned process is normal user app and needs to be umounted
	if (likely(is_zygote_normal_app_uid(new_uid) && ksu_uid_should_umount(new_uid))) {
		goto do_umount;
	}

	return 0;

do_umount:
	// Handle kernel umount
	ksu_handle_umount(old_uid, new_uid);

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	// We can reorder the mnt_id now after all sus mounts are umounted
	susfs_reorder_mnt_id();
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	susfs_run_sus_path_loop(new_uid);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH

	susfs_set_current_proc_umounted();

	return 0;
}
#endif // #ifndef CONFIG_KSU_SUSFS

#ifdef CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	uid_t new_uid = new->uid.val;
	uid_t old_uid = old->uid.val;
	uid_t new_euid = new->euid.val;

	return ksu_handle_setuid(new_uid, old_uid, new_euid);
}

static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid)
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
const struct lsm_id ksu_lsmid = {
	.name = "ksu",
	.id = 996,
};
#endif
#endif

void ksu_setuid_hook_init(void)
{
	ksu_kernel_umount_init();
	if (ksu_register_feature_handler(&enhanced_security_handler)) {
		pr_err("Failed to register enhanced security feature handler\n");
	}

#ifdef CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), &ksu_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
#endif
}

void ksu_setuid_hook_exit(void)
{
	pr_info("ksu_setuid_hook_exit\n");
	ksu_kernel_umount_exit();
	ksu_unregister_feature_handler(KSU_FEATURE_ENHANCED_SECURITY);
}
