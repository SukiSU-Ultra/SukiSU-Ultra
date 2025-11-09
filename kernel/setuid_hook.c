#include <linux/compiler.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/lsm_hooks.h>
#include <linux/binfmts.h>
#include <linux/tty.h>

#ifndef KSU_HAS_PATH_UMOUNT
#include <linux/syscalls.h> // sys_umount (<4.17) & ksys_umount (4.17+)
#endif

#ifdef MODULE
#include <linux/list.h>
#include <linux/irqflags.h>
#include <linux/mm_types.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>
#endif

#include "allowlist.h"
#include "setuid_hook.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"
#include "ksu.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "seccomp_cache.h"
#include "supercalls.h"
#include "syscall_hook_manager.h"
#include "kernel_umount.h"
#include "app_profile.h"

#include "sulog.h"

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

static inline bool is_unsupported_uid(uid_t uid)
{
#define LAST_APPLICATION_UID 19999
    uid_t appid = uid % 100000;
    return appid > LAST_APPLICATION_UID;
}

static bool is_appuid(uid_t uid)
{
#define PER_USER_RANGE 100000
#define FIRST_APPLICATION_UID 10000
#define LAST_APPLICATION_UID 19999

    uid_t appid = uid % PER_USER_RANGE;
    return appid >= FIRST_APPLICATION_UID && appid <= LAST_APPLICATION_UID;
}

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    uid_t new_uid = ruid;
	uid_t old_uid = current_uid().val;
    pr_info("handle_setuid from %d to %d\n", old_uid, new_uid);

    if (0 != old_uid) {
        // old process is not root, ignore it.
        if (ksu_enhanced_security_enabled) {
            // disallow any non-ksu domain escalation from non-root to root!
            if (unlikely(new_uid) == 0) {
                if (!is_ksu_domain()) {
                    pr_warn("find suspicious EoP: %d %s, from %d to %d\n", 
                        current->pid, current->comm, old_uid, new_uid);
                    ksu_force_sig(SIGKILL);
                    return 0;
                }
            }
            // disallow appuid decrease to any other uid if it is allowed to su
            if (is_appuid(old_uid)) {
                if (new_uid < old_uid && !ksu_is_allow_uid_for_current(old_uid)) {
                    pr_warn("find suspicious EoP: %d %s, from %d to %d\n", 
                        current->pid, current->comm, old_uid, new_uid);
                    ksu_force_sig(SIGKILL);
                    return 0;
                }
            }
        }
        return 0;
    }

    if (new_uid == 2000) {
        ksu_set_task_tracepoint_flag(current);
    }

    if (!is_appuid(new_uid) || is_unsupported_uid(new_uid)) {
        pr_info("handle setuid ignore non application or isolated uid: %d\n", new_uid);
        ksu_clear_task_tracepoint_flag(current);
        return 0;
    }

    // if on private space, see if its possibly the manager
    if (unlikely(new_uid > 100000 && new_uid % 100000 == ksu_get_manager_uid())) {
         ksu_set_manager_uid(new_uid);
    }

    if (unlikely(ksu_get_manager_uid() == new_uid)) {
        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        spin_lock_irq(&current->sighand->siglock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 2) // Android backport this feature in 5.10.2
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
#else
        // we dont have those new fancy things upstream has
	    // lets just do original thing where we disable seccomp
        disable_seccomp();
#endif
        ksu_set_task_tracepoint_flag(current);
        spin_unlock_irq(&current->sighand->siglock);
        return 0;
    }

    if (unlikely(ksu_is_allow_uid_for_current(new_uid))) {
        if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
            current->seccomp.filter) {
            spin_lock_irq(&current->sighand->siglock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 2) // Android backport this feature in 5.10.2
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
#else
            // we don't have those new fancy things upstream has
            // lets just do original thing where we disable seccomp
            disable_seccomp();
#endif
            spin_unlock_irq(&current->sighand->siglock);
        }
        ksu_set_task_tracepoint_flag(current);
    } else {
        ksu_clear_task_tracepoint_flag(current);
    }

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

    return 0;
}

// kernel 4.4 and 4.9
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||    \
    defined(CONFIG_IS_HW_HISI) ||    \
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

#ifndef MODULE
static struct security_hook_list ksu_hooks[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || \
    defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
    LSM_HOOK_INIT(key_permission, ksu_key_permission)
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
#endif

void ksu_setuid_hook_init(void)
{
    ksu_lsm_hook_init();
    ksu_kernel_umount_init();
    if (ksu_register_feature_handler(&enhanced_security_handler)) {
        pr_err("Failed to register enhanced security feature handler\n");
    }
}

void ksu_setuid_hook_exit(void)
{
    pr_info("ksu_core_exit\n");
    ksu_kernel_umount_exit();
    ksu_unregister_feature_handler(KSU_FEATURE_ENHANCED_SECURITY);
}
