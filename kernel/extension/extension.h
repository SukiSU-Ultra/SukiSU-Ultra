/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION
#define __KSU_H_EXTENSION

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include "uapi/extension.h"

/*
 * An extension is a KernelSU subsystem that has a richer UI than a single
 * bit. Each subsystem registers a handler; the kernel keeps a table indexed
 * by extension_id. A single ioctl (KSU_IOCTL_EXTENSION) dispatches into
 * this table.
 *
 * Two kind of handlers exist:
 *
 *   - "value" : sticky enable bit. Caller passes a struct
 *               ksu_extension_value_cmd. The handler may simply set/get a
 *               bit. This is what KPM, DYNAMIC_MANAGER and UMOUNT_PATHS
 *               use to advertise whether the subsystem is enabled.
 *
 *   - "io"    : the handler receives the raw user pointer and is free
 *               to copy_from_user() / copy_to_user() however it pleases.
 *               CPU spoof keeps its existing ksu_set_spoof_cpu_cmd shape
 *               via this path.
 */

struct ksu_extension_handler;

typedef int (*ksu_extension_get_value_fn)(u32 extension_id, u64 *value);
typedef int (*ksu_extension_set_value_fn)(u32 extension_id, u64 value);

struct ksu_extension_handler_ops {
    /* read sticky enable bit. KSU_EXTENSION_OP_GET. */
    ksu_extension_get_value_fn get;
    /* write sticky enable bit. KSU_EXTENSION_OP_SET. */
    ksu_extension_set_value_fn set;
};

/*
 * The end-of-payload op handler. Receives the user pointer as it was
 * supplied by userspace, plus an opaque cookie (the extension id). Used by
 * the io-flavoured extensions (CPU_SPOOF, UMOUNT_LIST, DYNAMIC_MANAGER).
 *
 * Returns negative errno on failure; length copied on success.
 */
typedef int (*ksu_extension_io_fn)(u32 extension_id, void __user *arg);

struct ksu_extension_handler {
    u32 extension_id;
    const char *name;
    /* required */
    const struct ksu_extension_handler_ops *ops;
    /* optional, used by io-flavoured extensions */
    ksu_extension_io_fn io_handler;
};

int ksu_register_extension_handler(const struct ksu_extension_handler *handler);
int ksu_unregister_extension_handler(u32 extension_id);

/* Called by feature / dispatch code. Returns -EOPNOTSUPP if unknown. */
int ksu_extension_get(u32 extension_id, u64 *value, bool *supported);
int ksu_extension_set(u32 extension_id, u64 value);

/*
 * Dispatch an extension io-flavored op. The `cmd` buffer layout is
 * struct ksu_extension_cmd; cmd->user is forwarded to handler->io_handler.
 */
int ksu_extension_ioctl(u32 extension_id, void __user *raw);

/* Wipe an extension's state. Used by KSU_EXTENSION_WIPE. */
int ksu_extension_wipe(u32 extension_id);

/* Force an extension to be present. Used by force_feature= extension:<id>. */
bool ksu_extension_is_forced(u32 extension_id);

/* Lifecycle: called from ksu_feature_apply_forced. */
void ksu_extension_apply_forced(void);

void ksu_extension_init(void);
void ksu_extension_exit(void);
void ksu_extension_register_all(void);

#endif /* __KSU_H_EXTENSION */
