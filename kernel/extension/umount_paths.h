/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION_UMOUNT_PATHS
#define __KSU_H_EXTENSION_UMOUNT_PATHS

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rwsem.h>

#include "uapi/supercall.h"


/* The mount table that used to be in feature/kernel_umount.c. */
struct mount_entry {
    char *umountable;
    unsigned int flags;
    struct list_head list;
};
extern struct list_head mount_list;
extern struct rw_semaphore mount_list_lock;

int ksu_extension_umount_paths_io(u32 id, void __user *raw);

#endif /* __KSU_H_EXTENSION_UMOUNT_PATHS */
