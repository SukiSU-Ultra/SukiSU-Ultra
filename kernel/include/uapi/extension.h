#ifndef __KSU_UAPI_EXTENSION_H
#define __KSU_UAPI_EXTENSION_H

#include <linux/ioctl.h>
#include <linux/types.h>

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
 * ---------------------------------------------------------------------
 * Capability bits (cmd.supported)
 * ---------------------------------------------------------------------
 *
 * cmd.supported is a flag field filled by the kernel on every successful
 * call. It is the single source of truth for "what can this extension
 * do"; userspace must not keep a parallel table, because such a table
 * silently drifts from the kernel's handler table.
 *
 *   - bit 0: KSU_FEATURE_FLAG_SUPPORTED  a handler is registered
 *   - bit 1: KSU_EXTENSION_FLAG_STICKY   runtime get/set of a u64 exists,
 *                                        so a toggle is meaningful
 *   - bit 2: KSU_EXTENSION_FLAG_PERSIST  the sticky value survives reboot
 *                                        (userspace persists and replays it)
 *   - bit 3: KSU_EXTENSION_FLAG_PER_UID  the extension's state is scoped
 *                                        per uid, not one global value
 *   - bit 4: KSU_EXTENSION_FLAG_REBOOT   changes only take effect after a
 *                                        reboot
 *   - bit 7: KSU_EXTENSION_FLAG_FORCED   pinned by force_extension=; SET and
 *                                        WIPE are refused with -EPERM
 *
 * Bits 5, 6 and 8..31 are reserved: the kernel never sets them and
 * userspace must ignore them.
 *
 * ---------------------------------------------------------------------
 * Extension ABI version
 * ---------------------------------------------------------------------
 *
 * cmd.api_version carries the extension ABI version the caller speaks and
 * is overwritten with the kernel's version on success. It exists so a
 * handler can refuse a caller that is too old to build the payload the
 * handler expects: the handler declares a minimum version and the kernel
 * answers -EOPNOTSUPP instead of parsing a struct the caller never knew
 * about. 0 means "client predates this field" and is treated as ABI 1.
 *
 * The capability bits above bit 0 are only meaningful on a kernel that
 * answers KSU_EXTENSION_ABI. A version field alone cannot distinguish
 * "new kernel" from "old kernel", because kernels that predate this field
 * simply echo cmd.api_version back verbatim. The probe removes the
 * ambiguity by using an id that is out of range for the handler table, so
 * an old kernel rejects it with -EINVAL:
 *
 *   id  = KSU_EXTENSION_ABI_PROBE_ID   (never a real extension)
 *   op  = KSU_EXTENSION_ABI
 *   out: cmd.api_version = highest ABI version the kernel speaks (>= 1)
 *
 * ABI 2 adds KSU_EXTENSION_ENUM, which lets userspace discover handlers
 * without a compiled-in copy of enum ksu_extension_id.
 *
 * Userspace MUST treat any error from the probe as "legacy kernel, the
 * capability bits are unavailable" and fall back to its own knowledge for
 * that boot only.
 */

#ifdef __BINDGEN__
#define DECLARE(type, name, val) static const type name = val
#else
#define DECLARE(type, name, val) enum { name = val }
#endif

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
DECLARE(__u32, KSU_EXTENSION_GET,  1);
DECLARE(__u32, KSU_EXTENSION_SET,  2);
DECLARE(__u32, KSU_EXTENSION_IO,   3);
DECLARE(__u32, KSU_EXTENSION_WIPE, 4);
/* Answers the extension ABI probe; see the api_version discussion above. */
DECLARE(__u32, KSU_EXTENSION_ABI, 5);

/*
 * Enumerates registered handlers so userspace does not need a mirror of
 * enum ksu_extension_id. ABI 2+ only.
 *
 *   id       = KSU_EXTENSION_ABI_PROBE_ID (keeps pre-ABI-2 kernels rejecting
 *              the call with -EINVAL instead of misreading it)
 *   value    = zero-based index among registered handlers
 *   user_ptr = struct ksu_extension_desc __user *
 *
 * Returns 0 and fills the descriptor, or -ENOENT once index is past the last
 * registered handler. The reply also echoes id/supported/api_version, but the
 * descriptor is the authoritative copy.
 */
DECLARE(__u32, KSU_EXTENSION_ENUM, 6);

/*
 * Extension ABI version spoken by this kernel, and the id reserved for the
 * probe that reports it. The id is deliberately out of range for
 * enum ksu_extension_id so kernels that predate the probe reject the call
 * with -EINVAL instead of treating it as a regular GET.
 */
#define KSU_EXTENSION_API_VERSION   2u
#define KSU_EXTENSION_ABI_PROBE_ID  0xFFFFFFFFu

/* Longest handler name reported through KSU_EXTENSION_ENUM, including NUL. */
#define KSU_EXTENSION_NAME_LEN 32

/*
 * One handler as reported by KSU_EXTENSION_ENUM. `caps` carries the same
 * semantic bits as cmd.supported plus KSU_FEATURE_FLAG_SUPPORTED; `forced`
 * is split out because it is mutable boot state, not a handler property.
 * `min_api_version` is the lowest caller ABI the handler accepts (0 = any).
 */
struct ksu_extension_desc {
    __u32 id;
    __u32 caps;
    __u32 min_api_version;
    __u32 forced;
    char name[KSU_EXTENSION_NAME_LEN];
};

/* Capability bits returned in cmd.supported.
 * KSU_FEATURE_FLAG_SUPPORTED is shared with uapi/supercall.h; bit 7 keeps
 * its historical value so managers built before the other bits existed
 * still read FORCED correctly. */
DECLARE(__u32, KSU_EXTENSION_FLAG_STICKY, (1u << 1));
DECLARE(__u32, KSU_EXTENSION_FLAG_PERSIST, (1u << 2));
DECLARE(__u32, KSU_EXTENSION_FLAG_PER_UID, (1u << 3));
DECLARE(__u32, KSU_EXTENSION_FLAG_REBOOT, (1u << 4));
DECLARE(__u32, KSU_EXTENSION_FLAG_FORCED, (1u << 7));

/* Common header for the unified extension ioctl. */
struct ksu_extension_cmd {
    __u32 id;                  /* ksu_extension_id, in */
    __u32 op;                  /* KSU_EXTENSION_* in */
    __u32 supported;           /* capability bitfield, out (see above) */
    __u32 api_version;         /* extension ABI version, in/out (see above) */
    __u64 value;               /* sticky state bit, in/out */
    __u64 user_ptr;            /* opaque user pointer, in (for KSU_EXTENSION_IO) */
};

// 0. KPM
DECLARE(__u32, SUKISU_KPM_LOAD, 1);
DECLARE(__u32, SUKISU_KPM_UNLOAD, 2);
DECLARE(__u32, SUKISU_KPM_NUM, 3);
DECLARE(__u32, SUKISU_KPM_LIST, 4);
DECLARE(__u32, SUKISU_KPM_INFO, 5);
DECLARE(__u32, SUKISU_KPM_CONTROL, 6);
DECLARE(__u32, SUKISU_KPM_VERSION, 7);
/* Optional event-aware load used for boot-stage modules. */
DECLARE(__u32, SUKISU_KPM_LOAD_EVENT, 8);

struct ksu_kpm_cmd {
    __aligned_u64 control_code;
    __aligned_u64 arg1;
    __aligned_u64 arg2;
    __aligned_u64 result_code;
};

/* arg2 payload for SUKISU_KPM_LOAD_EVENT. Both fields are user pointers. */
struct ksu_kpm_load_event_cmd {
    __aligned_u64 args;
    __aligned_u64 event;
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

DECLARE(__u32, KSU_UMOUNT_IO_OP_ADD,  1);
DECLARE(__u32, KSU_UMOUNT_IO_OP_DEL,  2);
DECLARE(__u32, KSU_UMOUNT_IO_OP_LIST, 3);

/* 5. VERSION_SPOOF */
DECLARE(__u32, KSU_VERSION_SPOOF_IO_GET, 1);
DECLARE(__u32, KSU_VERSION_SPOOF_IO_SET, 2);
DECLARE(__u32, KSU_VERSION_SPOOF_IO_RESET, 3);
DECLARE(__u32, KSU_VERSION_SPOOF_WORKING_VERSION, (1u << 0));
DECLARE(__u32, KSU_VERSION_SPOOF_FULL_VERSION, (1u << 1));
DECLARE(__u32, KSU_VERSION_SPOOF_UAPI_VERSION, (1u << 2));

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
DECLARE(__u32, KSU_IOCTL_EXTENSION,
        _IOC(_IOC_READ | _IOC_WRITE, 'K', 300,
             sizeof(struct ksu_extension_cmd)));

/*
 * NOTE: the `force_extension=<id>:<value>` boot-config encoding is
 * kernel-internal ABI between `force_extension_param_set()` and the
 * per-handler `apply_forced` callback. It does NOT cross the
 * user/kernel boundary on this code path. Its macros and full
 * documentation live in kernel/extension/extension.h, not here.
 */

#endif /* __KSU_UAPI_EXTENSION_H */
