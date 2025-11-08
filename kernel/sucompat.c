#include "linux/compiler.h"
#include "linux/printk.h"
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched/task_stack.h>
#include <linux/ptrace.h>

#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "sucompat.h"
#include "app_profile.h"
#include "syscall_hook_manager.h"


#include "sulog.h"
#include "kprobe_hook_manager.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

bool ksu_su_compat_enabled __read_mostly = true;

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
    /* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
    char __user *p = (void __user *)current_user_stack_pointer() - len;

    return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
    static const char sh_path[] = "/system/bin/sh";

    return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
    static const char ksud_path[] = KSUD_PATH;

    return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
             int *__unused_flags)
{
    const char su[] = SU_PATH;

#ifndef KSU_HAVE_SYSCALL_TRACEPOINTS_HOOK
    if (!ksu_su_compat_enabled) {
        return 0;
    }
#endif

    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        return 0;
    }

    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
#if __SULOG_GATE
        ksu_sulog_report_syscall(current_uid().val, NULL, "faccessat", path);
#endif
        pr_info("faccessat su->sh!\n");
        *filename_user = sh_user_path();
    }

    return 0;
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    // const char sh[] = SH_PATH;
    const char su[] = SU_PATH;

#ifndef KSU_HAVE_SYSCALL_TRACEPOINTS_HOOK
    if (!ksu_su_compat_enabled) {
         return 0;
     }
#endif
    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        return 0;
    }

    if (unlikely(!filename_user)) {
        return 0;
    }

    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
// Remove this later!! we use syscall hook, so this will never happen!!!!!
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0) && 0
    // it becomes a `struct filename *` after 5.18
    // https://elixir.bootlin.com/linux/v5.18/source/fs/stat.c#L216
    const char sh[] = SH_PATH;
    struct filename *filename = *((struct filename **)filename_user);
    if (IS_ERR(filename)) {
        return 0;
    }
    if (likely(memcmp(filename->name, su, sizeof(su))))
        return 0;
    pr_info("vfs_statx su->sh!\n");
    memcpy((void *)filename->name, sh, sizeof(sh));
#else
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
#if __SULOG_GATE
        ksu_sulog_report_syscall(current_uid().val, NULL, "newfstatat", path);
#endif
        pr_info("newfstatat su->sh!\n");
        *filename_user = sh_user_path();
    }
#endif

    return 0;
}

// the call from execve_handler_pre won't provided correct value for __never_use_argument, use them after fix execve_handler_pre, keeping them for consistence for manually patched code
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
                 void *__never_use_argv, void *__never_use_envp,
                 int *__never_use_flags)
{
    struct filename *filename;
    const char sh[] = KSUD_PATH;
    const char su[] = SU_PATH;

#ifndef KSU_HAVE_SYSCALL_TRACEPOINTS_HOOK
    if (!ksu_su_compat_enabled) {
         return 0;
     }
#endif
    if (unlikely(!filename_ptr))
        return 0;

    filename = *filename_ptr;
    if (IS_ERR(filename)) {
        return 0;
    }

    if (likely(memcmp(filename->name, su, sizeof(su))))
        return 0;

#if __SULOG_GATE
    bool is_allowed = ksu_is_allow_uid_for_current(current_uid().val);
    ksu_sulog_report_syscall(current_uid().val, NULL, "execve", filename->name);

    if (!is_allowed) {
        return 0;
    }

    ksu_sulog_report_su_attempt(current_uid().val, NULL, filename->name, is_allowed);
#else
    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        return 0;
    }
#endif

    pr_info("do_execveat_common su found\n");
    memcpy((void *)filename->name, sh, sizeof(sh));

    escape_with_root_profile();

    return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
            void *envp, int *flags)
{
    return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp, flags);
}

int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user,
                   void *__never_use_argv, void *__never_use_envp,
                   int *__never_use_flags)
{
    const char su[] = SU_PATH;
    char path[sizeof(su) + 1];

#ifndef KSU_HAVE_SYSCALL_TRACEPOINTS_HOOK
    if (!ksu_su_compat_enabled){
         return 0;
     }
#endif
    if (unlikely(!filename_user))
        return 0;

    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (likely(memcmp(path, su, sizeof(su))))
        return 0;

#if __SULOG_GATE
    bool is_allowed = ksu_is_allow_uid_for_current(current_uid().val);
    ksu_sulog_report_syscall(current_uid().val, NULL, "execve", path);
    
    if (!is_allowed)
        return 0;

    ksu_sulog_report_su_attempt(current_uid().val, NULL, path, is_allowed);
#else
    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        return 0;
    }
#endif

    pr_info("sys_execve su found\n");
    *filename_user = ksud_user_path();

    escape_with_root_profile();

    return 0;
}

int __ksu_handle_devpts(struct inode *inode)
{

#ifndef KSU_HAVE_SYSCALL_TRACEPOINTS_HOOK
    if (!ksu_su_compat_enabled)
        return 0;
#endif

    if (!current->mm) {
        return 0;
    }

    uid_t uid = current_uid().val;
    if (uid % 100000 < 10000) {
        // not untrusted_app, ignore it
        return 0;
    }

    if (likely(!ksu_is_allow_uid_for_current(uid)))
        return 0;

    struct inode_security_struct *sec = selinux_inode(inode);

    if (ksu_file_sid && sec)
        sec->sid = ksu_file_sid;

    return 0;
}

// sucompat: permited process can execute 'su' to gain root access.
void ksu_sucompat_init()
{
    if (ksu_register_feature_handler(&su_compat_handler)) {
        pr_err("Failed to register su_compat feature handler\n");
    }
}

void ksu_sucompat_exit()
{
    ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}