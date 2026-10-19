/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION_UMOUNT_PATHS
#define __KSU_H_EXTENSION_UMOUNT_PATHS


int add_try_umount(void __user *arg);
int ksu_extension_umount_paths_io(u32 id, void __user *raw);
int ksu_extension_umount_paths_wipe(u32 id);

#endif /* __KSU_H_EXTENSION_UMOUNT_PATHS */
