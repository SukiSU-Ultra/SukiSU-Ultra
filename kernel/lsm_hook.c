#include <linux/lsm_hooks.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/uidgid.h>
#include <linux/string.h>

#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"
#include "ksud.h"
#include "setuid_hook.h"
#include "throne_tracker.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0) && defined(CONFIG_KSU_MANUAL_SU)
#include "manual_su.h"

static int ksu_task_alloc(struct task_struct *task,
						  unsigned long clone_flags)
{
	ksu_try_escalate_for_uid(task_uid(task).val);
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||						   \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
static int ksu_key_permission(key_ref_t key_ref, const struct cred *cred,
				  unsigned perm)
{
	if (init_session_keyring != NULL) {
		return 0;
	}
	if (strcmp(current->comm, "init")) {
		// we are only interested in `init` process
		return 0;
	}
	init_session_keyring = cred->session_keyring;
	pr_info("kernel_compat: got init_session_keyring\n");
	return 0;
}
#endif

#ifdef CONFIG_KSU_MANUAL_HOOK
static int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
				struct inode *new_inode, struct dentry *new_dentry)
{
	// skip kernel threads
	if (!current->mm) {
		return 0;
	}

	// skip non system uid
	if (current_uid().val != 1000) {
		return 0;
	}

	if (!old_dentry || !new_dentry) {
		return 0;
	}

	// /data/system/packages.list.tmp -> /data/system/packages.list
	if (strcmp(new_dentry->d_iname, "packages.list")) {
		return 0;
	}

	char path[128];
	char *buf = dentry_path_raw(new_dentry, path, sizeof(path));
	if (IS_ERR(buf)) {
		pr_err("dentry_path_raw failed.\n");
		return 0;
	}

	if (!strstr(buf, "/system/packages.list")) {
		return 0;
	}

	pr_info("renameat: %s -> %s, new path: %s\n", old_dentry->d_iname,
		new_dentry->d_iname, buf);

	/*
	 * RKSU: track_throne(true) only occurs when
	 * on_boot_completed. So let's make it once-lock.
	 */
	static bool do_once = false;
	if (ksu_boot_completed && !do_once) {
		do_once = true;
		track_throne(true);
		return 0;
	}

	track_throne(false);

	return 0;
}

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
				   int flags)
{
	if (!new || !old)
		return 0;

	kuid_t old_uid = old->uid;
	kuid_t old_euid = old->euid;
	kuid_t new_uid = new->uid;
	kuid_t new_euid = new->euid;

	return ksu_handle_setuid_common(new_uid.val, old_uid.val, new_euid.val,
					old_euid.val);
}
#endif

static struct security_hook_list ksu_hooks[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||						   \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	LSM_HOOK_INIT(key_permission, ksu_key_permission),
#endif
#ifdef CONFIG_KSU_MANUAL_HOOK
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid)
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0) && defined(CONFIG_KSU_MANUAL_SU)
	LSM_HOOK_INIT(task_alloc, ksu_task_alloc),
#endif
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
static const struct lsm_id ksu_lsmid = {
	.name = "ksu",
	.id = 912,
};
#endif

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), &ksu_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	// https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
	pr_info("LSM hooks initialized.\n");
}
