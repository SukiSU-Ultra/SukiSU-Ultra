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
 *                  payloads. CPU_SPOOF, UMOUNT_PATHS, VERSION_SPOOF.
 *
 * The flavour is published to userspace as capability bits
 * (KSU_EXTENSION_FLAG_*) rather than inferred from which callbacks happen
 * to be non-NULL. Registration cross-checks the two representations, so a
 * table that claims STICKY without a setter is rejected instead of
 * producing a toggle the kernel would answer with -EOPNOTSUPP.
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
 * Kernel-side entry point: the value is forced_values[id] (raw u64,
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
    /*
     * Semantic capability bits (KSU_EXTENSION_FLAG_*) advertised through
     * cmd.supported. The dispatcher adds KSU_FEATURE_FLAG_SUPPORTED (and
     * FORCED when applicable) itself, so neither may appear here:
     * registration rejects them as a table bug.
     *
     * This is the only place an extension declares what it can do. The
     * manager and ksud read it back instead of keeping a mirror table,
     * which is what used to drift whenever a handler gained a setter.
     */
    u32 caps;
    /*
     * Extension ABI version a caller must speak to use this handler.
     * Callers advertising an older version get -EOPNOTSUPP, so a handler
     * that changed its payload layout never has to parse a struct the
     * caller could not have built. 0 = no requirement.
     *
     * Callers that predate KSU_EXTENSION_ABI send api_version 0 and are
     * treated as ABI 1, which is the version every handler in this tree
     * was written against.
     */
    u32 min_api_version;
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

/*
 * Called by the supercall dispatcher. `caller_api_version` is
 * ksu_extension_cmd.api_version as supplied by userspace.
 *
 * On success *caps receives the handler's semantic capability bits plus
 * KSU_FEATURE_FLAG_SUPPORTED. FORCED is not included: it is global state
 * that changes while a handler is registered, so the dispatcher adds it at
 * reply time. *caps is 0 when no handler is registered for the id; callers
 * must treat that as "unsupported" instead of calling GET and hoping.
 *
 * Returns -EOPNOTSUPP when the caller's ABI is older than the handler
 * requires; a gate failure is indistinguishable from "no handler" on
 * purpose, because from the caller's point of view the extension is not
 * usable either way.
 */
int ksu_extension_get(u32 extension_id, u32 caller_api_version, u64 *value, u32 *caps);
int ksu_extension_set(u32 extension_id, u32 caller_api_version, u64 value);

/*
 * Dispatch an extension io-flavored op. The `raw` pointer is forwarded to
 * handler->io_handler unchanged.
 */
int ksu_extension_ioctl(u32 extension_id, u32 caller_api_version, void __user *raw);

/* Wipe an extension's state. Used by KSU_EXTENSION_WIPE. */
int ksu_extension_wipe(u32 extension_id, u32 caller_api_version);

/*
 * Fill `desc` with the handler at zero-based `index` among registered
 * handlers (gaps in the id space are skipped). Used by
 * KSU_EXTENSION_ENUM so userspace does not keep a mirror of the handler
 * table. Returns -ENOENT once index is past the last handler.
 *
 * `desc->caps` already includes KSU_FEATURE_FLAG_SUPPORTED; FORCED is
 * reported separately in `desc->forced` because it is boot state.
 */
int ksu_extension_enumerate(u32 index, struct ksu_extension_desc *desc);

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
 *                       forced_values[id].
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
