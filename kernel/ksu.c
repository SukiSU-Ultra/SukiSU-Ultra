#include "kernel_includes.h"

// uapi
#include "include/uapi/app_profile.h"
#include "include/uapi/feature.h"
#include "include/uapi/selinux.h"
#include "include/uapi/supercall.h"
#include "include/uapi/sulog.h"
#include "include/uapi/manager.h"
#include "include/uapi/extension.h"

// includes
#include "include/klog.h"
#include "include/ksu.h"

// kernel compat, lite ones
#include "infra/kernel_compat.h"

#include "policy/app_profile.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"
#include "manager/pkg_observer.h"
#include "supercall/internal.h"
#include "supercall/supercall.h"
#include "infra/su_mount_ns.h"
#include "infra/file_wrapper.h"
#include "infra/event_queue.h"
#include "infra/symbol_resolver.h"
#include "feature/adb_root.h"
#include "feature/kernel_umount.h"
#include "feature/sucompat.h"
#include "feature/sulog.h"
#include "feature/mount_hide.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include "feature/selinux_hide.h"
#endif
#include "feature/shell_su_adb_only.h"
#include "runtime/ksud.h"
#include "sulog/event.h"
#include "sulog/fd.h"

#include "selinux/selinux.h"
#include "selinux/sepolicy.h"

// selinux includes
#include "avc_ss.h"
#include "objsec.h"
#include "ss/services.h"
#include "ss/symtab.h"
#include "xfrm.h"
#ifndef KSU_COMPAT_USE_SELINUX_STATE
#include "avc.h"
#endif

#include "extension/extension.h"
#include "extension/cpu_spoof.h"
#include "extension/umount_paths.h"
#include "extension/dynamic_manager.h"
#include "extension/kpm.h"
#include "extension/kpm/kpm.h"
#include "extension/kpm/compact.h"
#include "extension/kpm/super_access.h"
#include "extension/susfs_extension.h"

// unity build
#include "extension/extension.c"
#include "extension/cpu_spoof.c"
#include "extension/umount_paths.c"
#include "extension/dynamic_manager.c"
#include "extension/kpm.c"
#include "extension/kpm/kpm.c"
#include "extension/kpm/compact.c"
#include "extension/kpm/super_access.c"
#include "extension/susfs_extension.c"

#include "policy/allowlist.c"
#include "policy/app_profile.c"
#include "policy/feature.c"
#include "manager/apk_sign.c"
#include "manager/throne_tracker.c"
#include "manager/pkg_observer.c"

#include "supercall/perm.c"
#include "supercall/dispatch.c"
#include "supercall/supercall.c"

#include "infra/su_mount_ns.c"
#include "infra/file_wrapper.c"
#include "infra/event_queue.c"

#ifdef CONFIG_KSU_FEATURE_ADBROOT
#include "feature/adb_root.c"
#endif
#include "feature/kernel_umount.c"
#include "feature/sucompat.c"
#include "feature/sulog.c"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#include "feature/selinux_hide.c"
#endif
#include "feature/shell_su_adb_only.c"
#include "feature/mount_hide.c"
#include "runtime/ksud.c"

#include "sulog/event.c"
#include "sulog/fd.c"

#include "hook/lsm_hook.c"

#include "selinux/selinux.c"
#include "selinux/sepolicy.c"
#include "selinux/rules.c"

#include "infra/kernel_compat.c"
#include "infra/symbol_resolver.c"

struct cred *ksu_cred;

bool allow_shell = IS_ENABLED(CONFIG_KSU_DEBUG);
module_param(allow_shell, bool, 0);

bool ksu_no_custom_rc = false;
module_param_named(norc, ksu_no_custom_rc, bool, 0);

int __init kernelsu_init(void)
{
#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif

    if (allow_shell) {
        pr_alert("shell is allowed at init!");
    }

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
        return -ENOSYS;
    }

#ifdef CONFIG_KSU_SUSFS
    susfs_init();
#endif

    ksu_feature_init();

    ksu_extension_init();

    ksu_extension_register_all();

    ksu_init_symbol_resolver();

    ksu_supercalls_init();

    ksu_lsm_hook_init();

    ksu_sucompat_init();

    ksu_sulog_init();

    ksu_adb_root_init();

    ksu_shell_su_adb_only_init();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    ksu_selinux_hide_init();
#endif

    ksu_kernel_umount_init();

	ksu_mount_hide_init();

    ksu_allowlist_init();

    ksu_dynamic_manager_load();

    ksu_throne_tracker_init();

    ksu_ksud_init();

    ksu_file_wrapper_init();

    ksu_feature_apply_forced();

    ksu_extension_apply_forced();

    return 0;
}
device_initcall(kernelsu_init);

/*
MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
*/
