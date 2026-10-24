#ifndef __KSU_UAPI_FEATURE_H
#define __KSU_UAPI_FEATURE_H

enum ksu_feature_id {
    KSU_FEATURE_SU_COMPAT = 0,
    KSU_FEATURE_KERNEL_UMOUNT = 1,
    KSU_FEATURE_SULOG = 2,
    KSU_FEATURE_ADB_ROOT = 3,
    KSU_FEATURE_SELINUX_HIDE = 4,
    // 5 was webview_zygote_umount (v3.3.0), keep it unused so stale configs don't apply
    KSU_FEATURE_SHELL_SU_ADB_ONLY = 6,

    /*
     * Fork-local features start at 16. Upstream allocates from 0 upwards, so a
     * gap here keeps a rebase from silently renumbering a feature that the
     * manager and the on-disk .feature_config already refer to by id.
     */
    KSU_FEATURE_MOUNT_HIDE = 16,

    KSU_FEATURE_AVC_SPOOF = 10003,

    KSU_FEATURE_MAX
};

#endif
