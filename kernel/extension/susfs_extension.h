/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SuSFS extension handler.
 *
 * This is a thin shim that bridges the kernel extension subsystem
 * (kernel/extension/extension.c) with the SuSFS module. The
 * extension framework sets `supported = true` whenever a handler
 * is registered; ops->get only fills the optional value field.
 *
 * SuSFS has no sticky bit, no ioctl passthrough, and no
 * force_extension= replay. The SuSFS sub-screen independently
 * probes `ksud susfs status` to determine whether the module is
 * actually installed.
 */
#ifndef __KSU_H_EXTENSION_SUSFS
#define __KSU_H_EXTENSION_SUSFS

#include <linux/types.h>

int ksu_extension_susfs_get(u32 extension_id, u64 *value);
int ksu_extension_susfs_set(u32 extension_id, u64 value);
int ksu_extension_susfs_io(u32 extension_id, void __user *arg);
int ksu_extension_susfs_wipe(u32 extension_id);
void ksu_extension_susfs_apply_forced(u32 extension_id, u64 value);

/* ops table consumed by ksu_register_extension_handler() in extension.c */
extern const struct ksu_extension_handler_ops ksu_extension_susfs_ops;

#endif /* __KSU_H_EXTENSION_SUSFS */
