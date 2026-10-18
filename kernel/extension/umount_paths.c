// SPDX-License-Identifier: GPL-2.0
/*
 * Umount paths extension wiring.
 *
 * Wraps the table owned by feature/kernel_umount.{h,c}: ksu_add_try_umount
 * (used by ADD/DEL/WIPE) and the listing logic from supercall/dispatch.c.
 *
 * The sticky state bit indicates whether umount-on-uid is currently armed.
 * Each io op carries the same struct as the legacy ioctl, so we just
 * copy_from_user and dispatch.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/sched.h>

#include "extension/umount_paths.h"
#include "uapi/extension.h"

#include "klog.h" // IWYU pragma: keep

/* Mount table previously owned by feature/kernel_umount.{c,h}. */
struct list_head mount_list = LIST_HEAD_INIT(mount_list);
DECLARE_RWSEM(mount_list_lock);

/*
 * The legacy add/del/wipe handling lived inline in supercall/dispatch.c.
 * We hoist it here so that KSU_IOCTL_EXTENSION is the only entry point.
 */
static int do_add_try_umount_local(void __user *arg)
{
    struct ksu_add_try_umount_cmd cmd;
    struct mount_entry *new_entry, *entry, *tmp;
    char buf[256] = { 0 };

    /*
     * NULL arg from KSU_EXTENSION_WIPE — caller wants to drop the whole
     * table without supplying a struct.
     */
    if (!arg)
        goto wipe;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    switch (cmd.mode) {
    case KSU_UMOUNT_WIPE:
wipe:
        down_write(&mount_list_lock);
        list_for_each_entry_safe (entry, tmp, &mount_list, list) {
            list_del(&entry->list);
            kfree(entry->umountable);
            kfree(entry);
        }
        up_write(&mount_list_lock);
        return 0;

    case KSU_UMOUNT_ADD: {
        long len = strncpy_from_user(buf, (const char __user *)cmd.arg, 256);
        if (len <= 0)
            return -EFAULT;
        buf[sizeof(buf) - 1] = '\0';

        new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
        if (!new_entry)
            return -ENOMEM;

        new_entry->umountable = kstrdup(buf, GFP_KERNEL);
        if (!new_entry->umountable) {
            kfree(new_entry);
            return -ENOMEM;
        }

        down_write(&mount_list_lock);
        list_for_each_entry (entry, &mount_list, list) {
            if (!strcmp(entry->umountable, buf)) {
                up_write(&mount_list_lock);
                kfree(new_entry->umountable);
                kfree(new_entry);
                return -EEXIST;
            }
        }
        new_entry->flags = cmd.flags;
        list_add(&new_entry->list, &mount_list);
        up_write(&mount_list_lock);
        return 0;
    }

    case KSU_UMOUNT_DEL: {
        long len = strncpy_from_user(buf, (const char __user *)cmd.arg, sizeof(buf) - 1);
        if (len <= 0)
            return -EFAULT;
        buf[sizeof(buf) - 1] = '\0';

        down_write(&mount_list_lock);
        list_for_each_entry_safe (entry, tmp, &mount_list, list) {
            if (!strcmp(entry->umountable, buf)) {
                list_del(&entry->list);
                kfree(entry->umountable);
                kfree(entry);
            }
        }
        up_write(&mount_list_lock);
        return 0;
    }

    default:
        return -EINVAL;
    }
}

static int do_list_try_umount_local(void __user *arg)
{
    struct ksu_list_try_umount_cmd cmd;
    struct mount_entry *entry;
    char *output_buf;
    size_t output_size, offset = 0;
    bool using_vmalloc = false;
    int mount_count = 0;
    int ret = 0;

#define EXT_UMOUNT_MAX_SIZE (2 * 1024 * 1024)
#define EXT_UMOUNT_DEFAULT_SIZE (64 * 1024)

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;
    if (cmd.buf_size > 1024 * 1024)
        return -EINVAL;

    output_size = cmd.buf_size ? cmd.buf_size : 4096;
    if (!cmd.arg || output_size == 0)
        return -EINVAL;

    down_read(&mount_list_lock);
    list_for_each_entry (entry, &mount_list, list)
        mount_count++;
    up_read(&mount_list_lock);

    output_size = 1024 + mount_count * 200;
    if (output_size < EXT_UMOUNT_DEFAULT_SIZE)
        output_size = EXT_UMOUNT_DEFAULT_SIZE;
    if (output_size > EXT_UMOUNT_MAX_SIZE)
        output_size = EXT_UMOUNT_MAX_SIZE;

    output_buf = kzalloc(output_size, GFP_KERNEL | __GFP_NOWARN);
    if (!output_buf) {
        output_buf = vzalloc(output_size);
        using_vmalloc = true;
    }
    if (!output_buf)
        return -ENOMEM;

    offset += snprintf(output_buf + offset, output_size - offset,
                       "Mount Point\tFlags\n");
    offset += snprintf(output_buf + offset, output_size - offset,
                       "----------\t-----\n");

    down_read(&mount_list_lock);
    list_for_each_entry (entry, &mount_list, list) {
        int written = snprintf(output_buf + offset, output_size - offset,
                               "%s\t%u\n", entry->umountable, entry->flags);
        if (written < 0) {
            ret = -EFAULT;
            break;
        }
        if (written >= (int)(output_size - offset)) {
            ret = -ENOSPC;
            break;
        }
        offset += written;
    }
    up_read(&mount_list_lock);

    if (ret == 0) {
        if (copy_to_user((void __user *)cmd.arg, output_buf, offset))
            ret = -EFAULT;
    }

    if (using_vmalloc)
        vfree(output_buf);
    else
        kfree(output_buf);
    return ret;
}

int ksu_extension_umount_paths_io(u32 id, void __user *raw)
{
    struct ksu_extension_umount_cmd hdr;

    /*
     * NULL user pointer means "wipe" (called by KSU_EXTENSION_WIPE op).
     */
    if (!raw)
        return do_add_try_umount_local((void __user *)NULL);

    if (copy_from_user(&hdr, raw, sizeof(hdr)))
        return -EFAULT;

    switch (hdr.op) {
    case KSU_UMOUNT_IO_OP_ADD:
    case KSU_UMOUNT_IO_OP_DEL:
        /* Legacy layout: the second union member is ksu_add_try_umount_cmd. */
        return do_add_try_umount_local((void __user *)&hdr.payload.add);
    case KSU_UMOUNT_IO_OP_LIST:
        return do_list_try_umount_local((void __user *)&hdr.payload.list);
    default:
        return -EINVAL;
    }
}

#undef EXT_UMOUNT_MAX_SIZE
#undef EXT_UMOUNT_DEFAULT_SIZE
