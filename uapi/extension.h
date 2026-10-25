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
 * There are three flavours of extension:
 *
 *   - "value-flavored": get/set a single u64 via ksu_extension_cmd.value.
 *     Suitable for sticky enable bits (DYNAMIC_MANAGER).
 *
 *   - "io-flavored"   : the handler receives the raw user pointer
 *     (cmd.user_ptr) and payload, e.g. CPU spoof keeps its existing
 *     ksu_set_spoof_cpu_cmd shape and is just forwarded; KPM
 *     forwards ksu_kpm_cmd; umount paths forward ksu_extension_umount_cmd.
 *
 *   - "io-only + get" : like KPM, supports a value GET to advertise
 *     compile-time availability (e.g. CONFIG_KPM) but has no
 *     runtime sticky SET. KSU_EXTENSION_SET returns -EOPNOTSUPP.
 *
 * Each handler advertises its flavour through the ksu_extension_handler
 * registration so userspace can probe it via KSU_EXTENSION_GET and read
 * cmd.supported.
 *
 * cmd.supported is a flag field; the only bits that are part of the
 * UAPI are:
 *   - bit 0: KSU_FEATURE_FLAG_SUPPORTED (defined in uapi/supercall.h)
 *   - bit 7: KSU_EXTENSION_FLAG_FORCED
 * All other bits are reserved and must be ignored by userspace. There
 * is currently no per-extension "STICKY" bit: whether a given
 * extension has a runtime sticky bit is determined by its flavour
 * (see userspace/ksud/src/extension_id.rs::has_sticky_bit, which is
 * the canonical Rust mirror of the kernel's handler table).
 */

enum ksu_extension_id {
    KSU_EXTENSION_KPM = 0,
    KSU_EXTENSION_CPU_SPOOF = 1,
    KSU_EXTENSION_UMOUNT_PATHS = 2,
    KSU_EXTENSION_DYNAMIC_MANAGER = 3,
    KSU_EXTENSION_SUSFS = 4,
    KSU_EXTENSION_VERSION_SPOOF = 5,

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
    __u32 supported;           /* bitfield, see flag defs above, out */
    __u32 reserved;
    __u64 value;               /* sticky state bit, in/out */
    __u64 user_ptr;            /* opaque user pointer, in (for KSU_EXTENSION_IO) */
};

// 0. KPM
static const __u32 SUKISU_KPM_LOAD = 1;
static const __u32 SUKISU_KPM_UNLOAD = 2;
static const __u32 SUKISU_KPM_NUM = 3;
static const __u32 SUKISU_KPM_LIST = 4;
static const __u32 SUKISU_KPM_INFO = 5;
static const __u32 SUKISU_KPM_CONTROL = 6;
static const __u32 SUKISU_KPM_VERSION = 7;

struct ksu_kpm_cmd {
    __aligned_u64 control_code;
    __aligned_u64 arg1;
    __aligned_u64 arg2;
    __aligned_u64 result_code;
};

// 1. CPU_SPOOF
struct ksu_set_spoof_cpu_cmd {
    __u32 cpu_index;  /* Target processor core index */
    __u32 midr;       /* Main ID Register payload */
    __u32 bogomips;   /* BogoMIPS performance timing metric */
    __u64 hwcap;      /* Main ELF Hardware Capabilities mask */
    __u64 hwcap2;     /* Auxiliary ELF Hardware Capabilities mask */
};
// 2. UMOUNT_PATHS
struct ksu_list_try_umount_cmd {
    __aligned_u64 arg; // User buffer
    __u32 buf_size; // Buffer size provided by userspace
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

/* 5. VERSION_SPOOF */
#define KSU_VERSION_SPOOF_IO_GET   1u
#define KSU_VERSION_SPOOF_IO_SET   2u
#define KSU_VERSION_SPOOF_IO_RESET 3u
#define KSU_VERSION_SPOOF_WORKING_VERSION (1u << 0)
#define KSU_VERSION_SPOOF_FULL_VERSION    (1u << 1)
#define KSU_VERSION_SPOOF_UAPI_VERSION    (1u << 2)
#define KSU_VERSION_SPOOF_MASK_ALL \
    (KSU_VERSION_SPOOF_WORKING_VERSION | KSU_VERSION_SPOOF_FULL_VERSION | \
     KSU_VERSION_SPOOF_UAPI_VERSION)
struct ksu_version_spoof_cmd {
    __u32 op;
    __u32 mask;
    __u32 working_version;
    __u32 uapi_version;
    char full_version[255];
    /* Read-only build values returned by GET. */
    __u32 default_working_version;
    __u32 default_uapi_version;
    char default_full_version[255];
};

/* IOCTL command: one ioctl, extension handlers are enumerated above. */
static const __u32 KSU_IOCTL_EXTENSION =
    _IOC(_IOC_READ | _IOC_WRITE, 'K', 300, sizeof(struct ksu_extension_cmd));

/*
 * NOTE: the `force_extension=<id>:<value>` boot-config encoding is
 * kernel-internal ABI between `force_extension_param_set()` and the
 * per-handler `apply_forced` callback. It does NOT cross the
 * user/kernel boundary on this code path. Its macros and full
 * documentation live in kernel/extension/extension.h, not here.
 */

#endif /* __KSU_UAPI_EXTENSION_H */
