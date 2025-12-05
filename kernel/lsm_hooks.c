#include <linux/version.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/key.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/uidgid.h>

#include "kernel_compat.h"
#include "ksu.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0) && defined(CONFIG_KSU_MANUAL_SU)
#include "manual_su.h"

static int ksu_task_alloc(struct task_struct *task,
						  unsigned long clone_flags)
{
	ksu_try_escalate_for_uid(task_uid(task).val);
	return 0;
}
#endif

// kernel 4.4 and 4.9
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||	\
	defined(CONFIG_IS_HW_HISI) ||	\
	defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
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

#ifdef CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK
extern int ksu_handle_setuid(uid_t new_uid, uid_t old_uid, uid_t euid);
static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	uid_t new_uid = new->uid.val;
	uid_t old_uid = old->uid.val;
	uid_t new_euid = new->euid.val;

	return ksu_handle_setuid(new_uid, old_uid, new_euid);
}
#endif

static struct security_hook_list ksu_hooks[] = {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0) && defined(CONFIG_KSU_MANUAL_SU)
	LSM_HOOK_INIT(task_alloc, ksu_task_alloc),
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	LSM_HOOK_INIT(key_permission, ksu_key_permission),
#endif

#ifdef CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
#endif
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
const struct lsm_id ksu_lsmid = {
	.name = "ksu",
	.id = 912,
};
#endif

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	// https://elixir.bootlin.com/linux/v6.8/source/include/linux/lsm_hooks.h#L120
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), &ksu_lsmid);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	// https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
}
