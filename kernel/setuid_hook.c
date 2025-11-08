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
#include <linux/binfmts.h>
#include <linux/tty.h>

#include "allowlist.h"
#include "setuid_hook.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "selinux/selinux.h"
#include "seccomp_cache.h"
#include "supercalls.h"
#include "syscall_hook_manager.h"
#include "kernel_umount.h"

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

static inline bool is_allow_su()
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

// ksu_handle_prctl removed - now using ioctl via reboot hook

static bool is_appuid(uid_t uid)
{
#define PER_USER_RANGE 100000
#define FIRST_APPLICATION_UID 10000
#define LAST_APPLICATION_UID 19999

    uid_t appid = uid % PER_USER_RANGE;
    return appid >= FIRST_APPLICATION_UID && appid <= LAST_APPLICATION_UID;
}

static bool should_umount(struct path *path)
{
    if (!path) {
        return false;
    }

    if (current->nsproxy->mnt_ns == init_nsproxy.mnt_ns) {
        pr_info("ignore global mnt namespace process: %d\n",
            current_uid().val);
        return false;
    }

    if (path->mnt && path->mnt->mnt_sb && path->mnt->mnt_sb->s_type) {
        const char *fstype = path->mnt->mnt_sb->s_type->name;
        return strcmp(fstype, "overlay") == 0;
    }
    return false;
}
extern int path_umount(struct path *path, int flags);
static void ksu_umount_mnt(struct path *path, int flags)
{
    int err = path_umount(path, flags);
    if (err) {
        pr_info("umount %s failed: %d\n", path->dentry->d_iname, err);
    }
}

static void try_umount(const char *mnt, bool check_mnt, int flags)
{
    struct path path;
    int err = kern_path(mnt, 0, &path);
    if (err) {
        return;
    }

    if (path.dentry != path.mnt->mnt_root) {
        // it is not root mountpoint, maybe umounted by others already.
        path_put(&path);
        return;
    }

    // we are only interest in some specific mounts
    if (check_mnt && !should_umount(&path)) {
        path_put(&path);
        return;
    }

    ksu_umount_mnt(&path, flags);
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
                    force_sig(SIGKILL);
                    return 0;
                }
            }
            // disallow appuid decrease to any other uid if it is allowed to su
            if (is_appuid(old_uid)) {
                if (new_uid < old_uid && !ksu_is_allow_uid_for_current(old_uid)) {
                    pr_warn("find suspicious EoP: %d %s, from %d to %d\n", 
                        current->pid, current->comm, old_uid, new_uid);
                    force_sig(SIGKILL);
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
    
#if __SULOG_GATE
    ksu_sulog_report_syscall(new_uid, NULL, "setuid", NULL);
#endif

    return 0;
}

void ksu_setuid_hook_init(void)
{
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
