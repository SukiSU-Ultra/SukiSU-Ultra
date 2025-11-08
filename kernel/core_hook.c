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
#include "core_hook.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "selinux/selinux.h"
#include "supercalls.h"
#include "sucompat.h"
#include "sulog.h"
#include "seccomp_cache.h"
#include "ksud.h"
#include "hook_manager.h"

#include "throne_comm.h"
#include "umount_manager.h"

#ifdef CONFIG_KSU_MANUAL_SU
#include "manual_su.h"
#endif

#ifdef CONFIG_COMPAT
bool ksu_is_compat __read_mostly = false;
#endif

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC    0x1cd1
#endif

extern int __ksu_handle_devpts(struct inode *inode); // sucompat.c

#ifdef CONFIG_KSU_MANUAL_SU
static void ksu_try_escalate_for_uid(uid_t uid)
{
    if (!is_pending_root(uid))
        return;
    
    pr_info("pending_root: UID=%d temporarily allowed\n", uid);
    remove_pending_root(uid);
}
#endif

static bool ksu_kernel_umount_enabled = true;
static bool ksu_enhanced_security_enabled = false;

static int kernel_umount_feature_get(u64 *value)
{
    *value = ksu_kernel_umount_enabled ? 1 : 0;
    return 0;
}

static int kernel_umount_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_kernel_umount_enabled = enable;
    pr_info("kernel_umount: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
    .feature_id = KSU_FEATURE_KERNEL_UMOUNT,
    .name = "kernel_umount",
    .get_handler = kernel_umount_feature_get,
    .set_handler = kernel_umount_feature_set,
};

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

struct umount_tw {
    struct callback_head cb;
    const struct cred *old_cred;
};

static void umount_tw_func(struct callback_head *cb)
{
    struct umount_tw *tw = container_of(cb, struct umount_tw, cb);
    const struct cred *saved = NULL;
    if (tw->old_cred) {
        saved = override_creds(tw->old_cred);
    }

    ksu_umount_manager_execute_all(tw->old_cred);

    if (saved)
        revert_creds(saved);

    if (tw->old_cred)
        put_cred(tw->old_cred);

    kfree(tw);
}

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    struct umount_tw *tw;
    uid_t new_uid = ruid;
	uid_t old_uid = current_uid().val;
    // pr_info("handle_setuid from %d to %d\n", old_uid, new_uid);

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
        if (ksu_su_compat_enabled) {
            ksu_set_task_tracepoint_flag(current);
        }
    }

    if (!is_appuid(new_uid) || is_unsupported_uid(new_uid)) {
        // pr_info("handle setuid ignore non application or isolated uid: %d\n", new_uid);
        return 0;
    }

    // if on private space, see if its possibly the manager
    if (unlikely(new_uid > 100000 && new_uid % 100000 == ksu_get_manager_uid())) {
         ksu_set_manager_uid(new_uid);
    }

    if (unlikely(ksu_get_manager_uid() == new_uid)) {
        pr_info("install fd for: %d\n", new_uid);

        ksu_install_fd();
        spin_lock_irq(&current->sighand->siglock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 2) // Android backport this feature in 5.10.2
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
#else
        // we dont have those new fancy things upstream has
	    // lets just do original thing where we disable seccomp
        disable_seccomp();
#endif
        if (ksu_su_compat_enabled) {
            ksu_set_task_tracepoint_flag(current);
        }
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
        if (ksu_su_compat_enabled) {
            ksu_set_task_tracepoint_flag(current);
        }
    } else {
        // Disable syscall tracepoint sucompat for non-allowed processes
        if (ksu_su_compat_enabled) {
            ksu_clear_task_tracepoint_flag(current);
        }
    }

    // this hook is used for umounting overlayfs for some uid, if there isn't any module mounted, just ignore it!
    if (!ksu_module_mounted) {
        return 0;
    }

    if (!ksu_kernel_umount_enabled) {
        return 0;
    }

    if (!ksu_uid_should_umount(new_uid)) {
        return 0;
    } else {
#ifdef CONFIG_KSU_DEBUG
        pr_info("uid: %d should not umount!\n", current_uid().val);
#endif
    }

    // check old process's selinux context, if it is not zygote, ignore it!
    // because some su apps may setuid to untrusted_app but they are in global mount namespace
    // when we umount for such process, that is a disaster!
    bool is_zygote_child = is_zygote(get_current_cred());
    if (!is_zygote_child) {
        pr_info("handle umount ignore non zygote child: %d\n", current->pid);
        return 0;
    }
    
#if __SULOG_GATE
    ksu_sulog_report_syscall(new_uid.val, NULL, "setuid", NULL);
#endif

#ifdef CONFIG_KSU_DEBUG
    // umount the target mnt
    pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);
#endif

    tw = kmalloc(sizeof(*tw), GFP_ATOMIC);
    if (!tw)
        return 0;

    tw->old_cred = get_current_cred();
    tw->cb.func = umount_tw_func;

    int err = task_work_add(current, &tw->cb, TWA_RESUME);
    if (err) {
        if (tw->old_cred) {
            put_cred(tw->old_cred);
        }
        kfree(tw);
        pr_warn("unmount add task_work failed\n");
    }

    return 0;
}

// 2. cap_task_fix_setuid hook for handling setuid
static int cap_task_fix_setuid_handler_pre(struct kprobe *p,
                                           struct pt_regs *regs)
{
    struct cred *new = (struct cred *)PT_REGS_PARM1(regs);
    const struct cred *old = (const struct cred *)PT_REGS_PARM2(regs);

    ksu_handle_setuid(new, old);

    return 0;
}

static struct kprobe cap_task_fix_setuid_kp = {
    .symbol_name = "cap_task_fix_setuid",
    .pre_handler = cap_task_fix_setuid_handler_pre,
};

// 3.inode_permission hook for handling devpts
static int ksu_inode_permission_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct inode *inode = (struct inode *)PT_REGS_PARM1(regs);

    if (inode && inode->i_sb && unlikely(inode->i_sb->s_magic == DEVPTS_SUPER_MAGIC)) {
        // pr_info("%s: handling devpts for: %s \n", __func__, current->comm);
        __ksu_handle_devpts(inode);
    }

    return 0;
}

static struct kprobe ksu_inode_permission_kp = {
    .symbol_name = "security_inode_permission",
    .pre_handler = ksu_inode_permission_handler_pre,
};


// 4. bprm_check_security hook for handling ksud compatibility
static int ksu_bprm_check_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(regs);
    char *filename = (char *)bprm->filename;

    if (likely(!ksu_execveat_hook))
        return 0;

#ifdef CONFIG_COMPAT
    static bool compat_check_done __read_mostly = false;
    if (unlikely(!compat_check_done) && unlikely(!strcmp(filename, "/data/adb/ksud"))
        && !memcmp(bprm->buf, "\x7f\x45\x4c\x46", 4)) {
        if (bprm->buf[4] == 0x01)
            ksu_is_compat = true;

        pr_info("%s: %s ELF magic found! ksu_is_compat: %d \n", __func__, filename, ksu_is_compat);
        compat_check_done = true;
    }
#endif

    ksu_handle_pre_ksud(filename);

#ifdef CONFIG_KSU_MANUAL_SU
    ksu_try_escalate_for_uid(current_uid().val);
#endif

    return 0;
}

static struct kprobe ksu_bprm_check_kp = {
    .symbol_name = "security_bprm_check",
    .pre_handler = ksu_bprm_check_handler_pre,
};

#ifdef CONFIG_KSU_MANUAL_SU
// 5. task_alloc hook for handling manual su escalation
static int ksu_task_alloc_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(regs);

    ksu_try_escalate_for_uid(task_uid(task).val);
    return 0;
}

static struct kprobe ksu_task_alloc_kp = {
    .symbol_name = "security_task_alloc",
    .pre_handler = ksu_task_alloc_handler_pre,
};
#endif

__maybe_unused int ksu_kprobe_init(void)
{
    int rc = 0;
    rc = register_kprobe(&cap_task_fix_setuid_kp);
    if (rc) {
        pr_err("cap_task_fix_setuid kprobe failed: %d\n", rc);
        unregister_kprobe(&reboot_kp);
    } else {
        pr_info("cap_task_fix_setuid_kp kprobe registered successfully\n");
    }

    // Register inode_permission kprobe
    rc = register_kprobe(&ksu_inode_permission_kp);
    if (rc) {
        pr_err("inode_permission kprobe failed: %d\n", rc);
    } else {
        pr_info("inode_permission kprobe registered successfully\n");
    }

    // Register bprm_check_security kprobe
    rc = register_kprobe(&ksu_bprm_check_kp);
    if (rc) {
        pr_err("bprm_check_security kprobe failed: %d\n", rc);
    } else {
        pr_info("bprm_check_security kprobe registered successfully\n");
    }

#ifdef CONFIG_KSU_MANUAL_SU
    // Register task_alloc kprobe
    rc = register_kprobe(&ksu_task_alloc_kp);
    if (rc) {
        pr_err("task_alloc kprobe failed: %d\n", rc);
    } else {
        pr_info("task_alloc kprobe registered successfully\n");
    }
#endif

    return 0;
}

__maybe_unused int ksu_kprobe_exit(void)
{
    unregister_kprobe(&cap_task_fix_setuid_kp);
    unregister_kprobe(&ksu_inode_permission_kp);
    unregister_kprobe(&ksu_bprm_check_kp);
#ifdef CONFIG_KSU_MANUAL_SU
    unregister_kprobe(&ksu_task_alloc_kp);
#endif
    return 0;
}

void __init ksu_core_init(void)
{
    int rc = 0;
#ifdef CONFIG_KPROBES
    rc = ksu_kprobe_init();
    if (rc) {
        pr_err("ksu_kprobe_init failed: %d\n", rc);
    }
#endif
    rc = ksu_umount_manager_init();
    if (rc) {
        pr_err("Failed to initialize umount manager: %d\n", rc);
    }
    if (ksu_register_feature_handler(&kernel_umount_handler)) {
        pr_err("Failed to register umount feature handler\n");
    }
    if (ksu_register_feature_handler(&enhanced_security_handler)) {
        pr_err("Failed to register enhanced security feature handler\n");
    }
}

void ksu_core_exit(void)
{
    ksu_uid_exit();
    ksu_throne_comm_exit();
#if __SULOG_GATE
    ksu_sulog_exit();
#endif
#ifdef CONFIG_KPROBES
    pr_info("ksu_core_exit\n");
    ksu_kprobe_exit();
#endif
    ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
    ksu_unregister_feature_handler(KSU_FEATURE_ENHANCED_SECURITY);
}
