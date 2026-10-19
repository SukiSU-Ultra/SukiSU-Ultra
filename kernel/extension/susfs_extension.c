// SPDX-License-Identifier: GPL-2.0
/*
 * SuSFS extension handler stub.
 *
 * SuSFS has no sticky bit, no ioctl passthrough, and no
 * force_extension= replay. Its presence is advertised by the
 * mere fact that this handler is registered with the extension
 * subsystem — the framework itself sets `supported = true`
 * whenever a handler is found, and `ops->get` only fills the
 * optional value field.
 *
 * The SuSFS sub-screen independently checks whether the SuSFS
 * module is installed (via `ksud susfs status`) and prompts the
 * user accordingly. No additional runtime probing is needed here.
 */
#include "klog.h" // IWYU pragma: keep

int ksu_extension_susfs_get(u32 extension_id, u64 *value)
{
    if (value)
        *value = 0;
    return 0;
}

int ksu_extension_susfs_set(u32 extension_id, u64 value)
{
    return -EOPNOTSUPP;
}

int ksu_extension_susfs_io(u32 extension_id, void __user *arg)
{
    return -EOPNOTSUPP;
}

int ksu_extension_susfs_wipe(u32 extension_id)
{
    return -EOPNOTSUPP;
}

void ksu_extension_susfs_apply_forced(u32 extension_id, u64 value)
{
    /* No-op: SuSFS state is managed entirely by the userspace
     * module management flow, not by force_extension=. */
}

const struct ksu_extension_handler_ops ksu_extension_susfs_ops = {
    .get = ksu_extension_susfs_get,
    .set = NULL,
};
