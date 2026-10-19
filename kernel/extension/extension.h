/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION
#define __KSU_H_EXTENSION

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/errno.h>

/*
 * An extension is a KernelSU subsystem richer than a single bit. Each
 * registers a handler; the kernel keeps a table indexed by extension_id,
 * dispatched through KSU_IOCTL_EXTENSION.
 *
 * Flavours:
 *   - value      : sticky enable bit via get/set ops. DYNAMIC_MANAGER.
 *                  KSU_EXTENSION_SET calls ops->set; KSU_EXTENSION_GET
 *                  calls ops->get.
 *   - io + get   : exposes a runtime GET (e.g. CONFIG_KPM presence) but
 *                  has no runtime SET. KSU_EXTENSION_SET returns
 *                  -EOPNOTSUPP. KPM.
 *   - io only    : no sticky bit at all; io_handler forwards raw user
 *                  payloads. CPU_SPOOF, UMOUNT_PATHS.
 *
 * Forced-by-config (force_extension=<id>:<value>) is replayed on every
 * boot: value-flavoured handlers go through ops->set; io-flavoured
 * handlers (including io + get) go through apply_forced. A handler with
 * neither refuses to be forced (warning + clear pending) — this is a
 * deliberate refusal, not a bug. The old io_handler(id, NULL) fallback
 * was unsafe (subsystem-dependent NULL semantics) and is no longer
 * used.
 *
 * Wipe (KSU_EXTENSION_WIPE) goes through handler->wipe, a
 * kernel-side callback. A handler with no wipe returns -EOPNOTSUPP.
 * Wipe is independent of apply_forced. Wipe is also refused while a
 * force_extension=<id> is in effect, to keep the locked state
 * consistent with userspace SET.
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

/*
 * Forced-by-config callback. Invoked by ksu_extension_apply_forced()
 * to apply a saved value to an io-flavoured handler on every boot.
 *
 * Kernel-side entry point: the value is extension_forced_values[id] (raw u64,
 * never a userspace pointer). No access_ok, no copy_from_user.
 * io_handler() is strictly a userspace entry point and must not
 * branch on "this is a forced sentinel".
 */
typedef void (*ksu_extension_apply_forced_fn)(u32 extension_id, u64 value);

/*
 * Wipe callback. Invoked by ksu_extension_wipe() to clear an
 * extension's runtime state. Kernel-side; no userspace pointer.
 */
typedef int (*ksu_extension_wipe_fn)(u32 extension_id);

struct ksu_extension_handler {
    u32 extension_id;
    const char *name;
    /* required */
    const struct ksu_extension_handler_ops *ops;
    /* optional, used by io-flavoured extensions */
    ksu_extension_io_fn io_handler;
    /* optional, used by io-flavoured extensions to apply a forced value */
    ksu_extension_apply_forced_fn apply_forced;
    /* optional, used to clear runtime state on KSU_EXTENSION_WIPE */
    ksu_extension_wipe_fn wipe;
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

/*
 * Force-value encoding for io-flavoured handlers.
 *
 * This is the kernel-internal ABI between `force_extension_param_set()`
 * and the per-handler `apply_forced` callback. It is NOT a UAPI: the
 * u64 never crosses the user/kernel boundary on this code path.
 *
 * # Encoding
 *
 *   force_extension=<id>:<value>
 *
 * <id>   = enum ksu_extension_id (decimal or hex)
 * <value>= u64, parsed by the kernel's kstrtou64() (decimal, 0x hex,
 *           0 octal). The value's meaning is per-extension:
 *     - value-flavoured handlers (DYNAMIC_MANAGER) treat <value> as
 *       the sticky bit (0 or 1) and replay it through ops->set().
 *     - io-flavoured handlers (KPM) may pack a (sub-op, arg) tuple
 *       into the u64 using the KSU_EXTENSION_FORCE_* macros below.
 *
 * # Replay order
 *
 *   1. ops->set      — value-flavoured handlers, replay the raw u64
 *                       extension_forced_values[id].
 *   2. apply_forced  — io-flavoured handlers, kernel-side callback
 *                       that receives the raw u64. No user pointer
 *                       is fabricated.
 *   3. neither       — log and clear forced_pending. This is a
 *                       deliberate refusal, not a bug. The old
 *                       io_handler(id, NULL) fallback was unsafe
 *                       (NULL is WIPE for umount_paths, EFAULT for
 *                       others) and is no longer used.
 *
 * # Single source of truth
 *
 * Boot config producers (bootloaders, ksud) only need to know the
 * encoding if they intentionally compose a 32-bit sub-op with a 32-bit
 * arg, which is rare. Single-sub-op forces like
 * `force_extension=kpm:7` are the common case and are unaffected.
 *
 * To keep producers and consumers in lockstep, this header is the
 * single source of truth. New sub-op authors MUST use these macros
 * instead of hand-rolling the bit shifts:
 *
 *   u64 v = KSU_EXTENSION_FORCE_PACK(7, 0x42);
 *   if (KSU_EXTENSION_FORCE_OP(v) != SUKISU_KPM_VERSION) ...;
 *   do_thing_with(KSU_EXTENSION_FORCE_ARG(v));
 *
 * # Stability
 *
 * The (op, arg) split direction is part of the ABI: op occupies the
 * low 32 bits, arg the high 32 bits. Changing either direction
 * silently corrupts every force entry; bump the encoding version
 * (or just don't change it) if you ever need to.
 */
#define KSU_EXTENSION_FORCE_OP(value) ((u32)((value) & 0xffffffffu))
#define KSU_EXTENSION_FORCE_ARG(value) ((u32)((value) >> 32))
#define KSU_EXTENSION_FORCE_PACK(op, arg) \
    (((u64)(u32)(op)) | (((u64)(u32)(arg)) << 32))

#endif /* __KSU_H_EXTENSION */
