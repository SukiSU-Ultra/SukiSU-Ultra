#ifndef __KSU_UAPI_EXTENSION_H
#define __KSU_UAPI_EXTENSION_H

#include <linux/ioctl.h>
#include <linux/types.h>

#include "uapi/manager.h"
#include "uapi/supercall.h"

/*
 * Extension subsystem architecture.
 *
 * The original kernel/policy/feature.{h,c} covers small, single-bit
 * features (su_compat, kernel_umount, sulog, etc.). Some KernelSU
 * subsystems however need a full UI surface (multiple lists, richer
 * payloads), so they used to expose their own ioctl numbers
 * (KSU_IOCTL_KPM, KSU_IOCTL_MANAGER, KSU_IOCTL_ADD_TRY_UMOUNT,
 *  KSU_IOCTL_LIST_TRY_UMOUNT, KSU_IOCTL_SET_SPOOF_CPU,
 *  KSU_IOCTL_ENABLE_KPM, ...).
 *
 * The extension subsystem unifies them behind a single ioctl,
 * KSU_IOCTL_EXTENSION. The first four bytes of each ioctl payload are
 * the extension id (enum ksu_extension_id). The remaining bytes are
 * opaque to the ioctl dispatcher and decoded by the registered
 * extension handler.
 *
 * There are two flavours of extension:
 *
 *   - "value-flavored": get/set a single u64 via ksu_extension_cmd.value.
 *     Suitable for sticky enable bits (KPM, DYNAMIC_MANAGER, ...).
 *
 *   - "io-flavored"   : the handler receives the raw user pointer
 *     (cmd.user_ptr) and payload, e.g. CPU spoof keeps its existing
 *     ksu_set_spoof_cpu_cmd shape and is just forwarded.
 *
 * Each handler advertises its flavour through the ksu_extension_handler
 * registration so userspace can probe it via KSU_EXTENSION_GET and read
 * cmd.supported.
 */

enum ksu_extension_id {
    KSU_EXTENSION_KPM = 0,
    KSU_EXTENSION_CPU_SPOOF = 1,
    KSU_EXTENSION_UMOUNT_PATHS = 2,
    KSU_EXTENSION_DYNAMIC_MANAGER = 3,

    KSU_EXTENSION_MAX
};

/* Operation discriminator for the unified KSU_IOCTL_EXTENSION. */
#define KSU_EXTENSION_GET  1u
#define KSU_EXTENSION_SET  2u
#define KSU_EXTENSION_IO   3u
#define KSU_EXTENSION_WIPE 4u

/* Forced flag returned in cmd.supported.
 * KSU_FEATURE_FLAG_SUPPORTED is shared with uapi/supercall.h. */
#define KSU_EXTENSION_FLAG_FORCED   (1u << 7)

/* Common header for the unified extension ioctl. */
struct ksu_extension_cmd {
    __u32 id;                  /* ksu_extension_id, in */
    __u32 op;                  /* KSU_EXTENSION_* in */
    __u32 supported;           /* KSU_FEATURE_FLAG_SUPPORTED out */
    __u32 reserved;
    __u64 value;               /* sticky state bit, in/out */
    __u64 user_ptr;            /* opaque user pointer, in (for KSU_EXTENSION_IO) */
};

/*
 * Umount paths extension io payload. A small header is followed by the
 * legacy ksu_add_try_umount_cmd or ksu_list_try_umount_cmd payload.
 * Both userspace (manager/app/src/main/cpp/ksu.cc) and the kernel
 * handler (kernel/extension/umount_paths.c) build/read this layout.
 */
struct ksu_extension_umount_cmd {
    __u32 op;                  /* KSU_UMOUNT_IO_OP_* in */
    __u32 reserved;
    union {
        struct ksu_add_try_umount_cmd add;
        struct ksu_list_try_umount_cmd list;
    } payload;
};

#define KSU_UMOUNT_IO_OP_ADD  1u
#define KSU_UMOUNT_IO_OP_DEL  2u
#define KSU_UMOUNT_IO_OP_LIST 3u

/* IOCTL command: one ioctl, four extensions. */
static const __u32 KSU_IOCTL_EXTENSION =
    _IOC(_IOC_READ | _IOC_WRITE, 'K', 300, sizeof(struct ksu_extension_cmd));

#endif /* __KSU_UAPI_EXTENSION_H */
