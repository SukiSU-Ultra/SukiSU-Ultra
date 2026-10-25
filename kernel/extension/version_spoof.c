// SPDX-License-Identifier: GPL-2.0
/*
 * Version spoof extension.
 *
 * Overrides are deliberately isolated from KernelSU's internal build
 * constants. They affect the public GET_INFO / GET_FULL_VERSION responses,
 * and therefore can make a Manager misjudge kernel compatibility.
 */
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "version_spoof.h"
#include "ksu.h"

struct version_spoof_state {
    u32 mask;
    u32 working_version;
    u32 uapi_version;
    char full_version[sizeof(((struct ksu_version_spoof_cmd *)0)->full_version)];
};

static DEFINE_MUTEX(version_spoof_lock);
static struct version_spoof_state version_spoof;

static int version_spoof_apply(const struct ksu_version_spoof_cmd *cmd)
{
    if (cmd->mask & ~KSU_VERSION_SPOOF_MASK_ALL)
        return -EINVAL;
    if ((cmd->mask & KSU_VERSION_SPOOF_FULL_VERSION) &&
        !memchr(cmd->full_version, '\0', sizeof(cmd->full_version)))
        return -EINVAL;

    mutex_lock(&version_spoof_lock);
    version_spoof.mask = cmd->mask;
    version_spoof.working_version = cmd->working_version;
    version_spoof.uapi_version = cmd->uapi_version;
    memset(version_spoof.full_version, 0, sizeof(version_spoof.full_version));
    if (cmd->mask & KSU_VERSION_SPOOF_FULL_VERSION)
        strscpy(version_spoof.full_version, cmd->full_version,
                sizeof(version_spoof.full_version));
    mutex_unlock(&version_spoof_lock);
    return 0;
}

int ksu_extension_version_spoof_io(u32 id, void __user *raw)
{
    struct ksu_version_spoof_cmd cmd = { 0 };
    int ret = 0;

    if (!raw)
        return -EFAULT;
    if (copy_from_user(&cmd, raw, sizeof(cmd)))
        return -EFAULT;

    switch (cmd.op) {
    case KSU_VERSION_SPOOF_IO_GET:
        mutex_lock(&version_spoof_lock);
        cmd.mask = version_spoof.mask;
        cmd.working_version = version_spoof.mask & KSU_VERSION_SPOOF_WORKING_VERSION
            ? version_spoof.working_version : KERNEL_SU_VERSION;
        cmd.uapi_version = version_spoof.mask & KSU_VERSION_SPOOF_UAPI_VERSION
            ? version_spoof.uapi_version : KERNEL_SU_UAPI_VERSION;
        if (version_spoof.mask & KSU_VERSION_SPOOF_FULL_VERSION)
            strscpy(cmd.full_version, version_spoof.full_version, sizeof(cmd.full_version));
        else
            strscpy(cmd.full_version, KSU_VERSION_FULL, sizeof(cmd.full_version));
        cmd.default_working_version = KERNEL_SU_VERSION;
        cmd.default_uapi_version = KERNEL_SU_UAPI_VERSION;
        strscpy(cmd.default_full_version, KSU_VERSION_FULL, sizeof(cmd.default_full_version));
        mutex_unlock(&version_spoof_lock);
        if (copy_to_user(raw, &cmd, sizeof(cmd)))
            return -EFAULT;
        break;
    case KSU_VERSION_SPOOF_IO_SET:
        ret = version_spoof_apply(&cmd);
        break;
    case KSU_VERSION_SPOOF_IO_RESET:
        mutex_lock(&version_spoof_lock);
        memset(&version_spoof, 0, sizeof(version_spoof));
        mutex_unlock(&version_spoof_lock);
        break;
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

int ksu_extension_version_spoof_wipe(u32 id)
{
    mutex_lock(&version_spoof_lock);
    memset(&version_spoof, 0, sizeof(version_spoof));
    mutex_unlock(&version_spoof_lock);
    return 0;
}

void ksu_version_spoof_apply_info(struct ksu_get_info_cmd *cmd)
{
    mutex_lock(&version_spoof_lock);
    if (version_spoof.mask & KSU_VERSION_SPOOF_WORKING_VERSION)
        cmd->version = version_spoof.working_version;
    if (version_spoof.mask & KSU_VERSION_SPOOF_UAPI_VERSION)
        cmd->uapi_version = version_spoof.uapi_version;
    mutex_unlock(&version_spoof_lock);
}

void ksu_version_spoof_apply_info_legacy(struct ksu_get_info_legacy_cmd *cmd)
{
    mutex_lock(&version_spoof_lock);
    if (version_spoof.mask & KSU_VERSION_SPOOF_WORKING_VERSION)
        cmd->version = version_spoof.working_version;
    mutex_unlock(&version_spoof_lock);
}

void ksu_version_spoof_apply_full_version(char *buf, size_t size)
{
    mutex_lock(&version_spoof_lock);
    if (version_spoof.mask & KSU_VERSION_SPOOF_FULL_VERSION)
        strscpy(buf, version_spoof.full_version, size);
    mutex_unlock(&version_spoof_lock);
}
