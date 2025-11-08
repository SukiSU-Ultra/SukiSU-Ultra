#include "kprobe_hook_manager.h"
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uidgid.h>

#include "arch.h"
#include "klog.h"
#include "ksud.h"

#ifdef CONFIG_KSU_MANUAL_SU
#include "manual_su.h"
#endif

#ifdef CONFIG_COMPAT
bool ksu_is_compat __read_mostly = false;
#endif

#ifdef CONFIG_KSU_MANUAL_SU
static void ksu_try_escalate_for_uid(uid_t uid)
{
    if (!is_pending_root(uid))
        return;
    
    pr_info("pending_root: UID=%d temporarily allowed\n", uid);
    remove_pending_root(uid);
}
#endif

// inode_permission hook for handling devpts
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


// bprm_check_security hook for handling ksud compatibility
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
// task_alloc hook for handling manual su escalation
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
    unregister_kprobe(&ksu_inode_permission_kp);
    unregister_kprobe(&ksu_bprm_check_kp);
#ifdef CONFIG_KSU_MANUAL_SU
    unregister_kprobe(&ksu_task_alloc_kp);
#endif
    return 0;
}

void ksu_kprobe_hook_init(void)
{
    int rc = 0;
#ifdef CONFIG_KPROBES
    rc = ksu_kprobe_init();
    if (rc) {
        pr_err("ksu_kprobe_init failed: %d\n", rc);
    }
#endif
}

void ksu_kprobe_hook_exit(void)
{
#ifdef CONFIG_KPROBES
    pr_info("ksu_core_exit\n");
    ksu_kprobe_exit();
#endif
}