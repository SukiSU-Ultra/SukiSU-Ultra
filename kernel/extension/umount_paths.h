/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION_UMOUNT_PATHS
#define __KSU_H_EXTENSION_UMOUNT_PATHS

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rwsem.h>

#include "extension.h"
#include "uapi/supercall.h"

/*
 * Umount paths extension.
 *
 * Sticky state (u64 bit 0): whether the umount-at-uid feature is currently
 * overriding the mount list. The actual mount table manipulations
 * (add/del/wipe/list) are routed through the io op, accepting the same
 * ksu_add_try_umount_cmd / ksu_list_try_umount_cmd struct that the legacy
 * KSU_IOCTL_ADD_TRY_UMOUNT / KSU_IOCTL_LIST_TRY_UMOUNT did.
 */

/* The mount table that used to be in feature/kernel_umount.c. */
struct mount_entry {
    char *umountable;
    unsigned int flags;
    struct list_head list;
};
extern struct list_head mount_list;
extern struct rw_semaphore mount_list_lock;

int ksu_extension_umount_paths_get(u32 id, u64 *value);
int ksu_extension_umount_paths_set(u32 id, u64 value);
int ksu_extension_umount_paths_io(u32 id, void __user *raw);

extern const struct ksu_extension_handler_ops ksu_extension_umount_paths_ops;

#endif /* __KSU_H_EXTENSION_UMOUNT_PATHS */
