// SPDX-License-Identifier: GPL-2.0
/*
 * sukisu_fs_ioctl.c - dispatch sukisu-fs ioctls to the appropriate
 * backend (mount, umount, rule add/remove/list).
 *
 * The supercall dispatcher (supercall/dispatch.c) hands us a
 * pre-validated userspace pointer; we still need to be careful about
 * re-validation (the user may have raced with another thread).
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "klog.h"
#include "uapi/supercall.h"
#include "sukisu_fs.h"
#include "uapi/sukisu_fs.h"

int sukisu_fs_handle_mount(struct ksu_sukisu_fs_mount_cmd __user *ucmd)
{
    struct ksu_sukisu_fs_mount_cmd cmd;
    char *source, *target;
    int ret;

    if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
        return -EFAULT;

    source = strndup_user(cmd.source, sizeof(cmd.source) - 1);
    if (IS_ERR(source))
        return PTR_ERR(source);

    target = strndup_user(cmd.target, sizeof(cmd.target) - 1);
    if (IS_ERR(target)) {
        kfree(source);
        return PTR_ERR(target);
    }

    /* Delegate to the fs core for the actual mount. */
    ret = sukisu_fs_do_mount(source, target);
    if (ret == 0)
        pr_info("sukisu_fs: registered %s -> %s\n", source, target);

    kfree(source);
    kfree(target);
    return ret;
}

int sukisu_fs_handle_umount(struct ksu_sukisu_fs_mount_cmd __user *ucmd)
{
    struct ksu_sukisu_fs_mount_cmd cmd;
    char *target;
    struct path target_path;
    int ret;

    if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
        return -EFAULT;

    target = strndup_user(cmd.target, sizeof(cmd.target) - 1);
    if (IS_ERR(target))
        return PTR_ERR(target);

    ret = kern_path(target, LOOKUP_FOLLOW, &target_path);
    if (!ret) {
        /* We never actually mount inside the kernel in v1; report
         * success if the path is reachable. */
        path_put(&target_path);
    }
    pr_info("sukisu_fs: unregister requested for %s (ret=%d)\n", target, ret);
    kfree(target);
    return ret;
}

int sukisu_fs_handle_rule(struct ksu_sukisu_fs_rule_cmd __user *ucmd)
{
    struct ksu_sukisu_fs_rule_cmd cmd;
    struct sukisu_fs_rule rule;
    char *path;
    int ret = 0;

    if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
        return -EFAULT;

    switch (cmd.operation) {
    case SUKISU_FS_RULE_ADD:
        path = strndup_user(cmd.path, sizeof(cmd.path) - 1);
        if (IS_ERR(path))
            return PTR_ERR(path);

        rule.view = cmd.view;
        rule.uid_min = cmd.uid_min;
        rule.uid_max = cmd.uid_max;
        strscpy(rule.path, path, sizeof(rule.path));
        kfree(path);

        ret = sukisu_fs_rule_add(&rule);
        if (!ret)
            pr_info("sukisu_fs: rule added (view=%d uid=[%u,%u] path=%s)\n",
                    rule.view, rule.uid_min, rule.uid_max, rule.path);
        break;

    case SUKISU_FS_RULE_REMOVE:
        path = strndup_user(cmd.path, sizeof(cmd.path) - 1);
        if (IS_ERR(path))
            return PTR_ERR(path);
        ret = sukisu_fs_rule_remove(path);
        if (!ret)
            pr_info("sukisu_fs: rule removed (%s)\n", path);
        kfree(path);
        break;

    case SUKISU_FS_RULE_CLEAR:
        sukisu_fs_rule_clear();
        pr_info("sukisu_fs: rule table cleared\n");
        break;

    case SUKISU_FS_RULE_LIST:
        /* Output is exposed via KSU_IOCTL_SUKISU_FS_LIST, not here. */
        ret = -EOPNOTSUPP;
        break;

    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

int sukisu_fs_handle_list(struct ksu_sukisu_fs_rule_cmd __user *ucmd, u32 *out_total)
{
    struct ksu_sukisu_fs_rule_cmd cmd;
    struct sukisu_fs_rule rule;
    u32 total = sukisu_fs_rule_get_count();
    int ret;

    if (copy_from_user(&cmd, ucmd, sizeof(cmd)))
        return -EFAULT;

    if (cmd.index >= total)
        return -ENOENT;

    ret = sukisu_fs_rule_get_at(cmd.index, &rule);
    if (ret)
        return ret;

    cmd.view = rule.view;
    cmd.uid_min = rule.uid_min;
    cmd.uid_max = rule.uid_max;
    memset(cmd.path, 0, sizeof(cmd.path));
    strscpy(cmd.path, rule.path, sizeof(cmd.path));

    if (copy_to_user(ucmd, &cmd, sizeof(cmd)))
        return -EFAULT;

    *out_total = total;
    return 0;
}
