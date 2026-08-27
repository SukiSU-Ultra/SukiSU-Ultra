#ifndef __KSU_UAPI_SUPERCALL_H
#define __KSU_UAPI_SUPERCALL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#include "uapi/app_profile.h"

// 2: allowlist v4 root profile flags
static const __u32 KERNEL_SU_UAPI_VERSION = 2;

/* Magic numbers for reboot hook to install fd */
static const __u32 KSU_INSTALL_MAGIC1 = 0xDEADBEEF;
static const __u32 KSU_INSTALL_MAGIC2 = 0xCAFEBABE;
static const __u32 KSU_FULL_VERSION_STRING = 255;

struct ksu_become_daemon_cmd {
    __u8 token[65]; /* Input: daemon token (null-terminated) */
};

static const __u32 EVENT_POST_FS_DATA = 1;
static const __u32 EVENT_BOOT_COMPLETED = 2;
static const __u32 EVENT_MODULE_MOUNTED = 3;

static const __u32 KSU_GET_INFO_FLAG_LKM = (1U << 0);
static const __u32 KSU_GET_INFO_FLAG_MANAGER = (1U << 1);
static const __u32 KSU_GET_INFO_FLAG_LATE_LOAD = (1U << 2);
static const __u32 KSU_GET_INFO_FLAG_PR_BUILD = (1U << 3);

struct ksu_get_info_cmd {
    __u32 version; /* Output: KERNEL_SU_VERSION */
    __u32 flags; /* Output: KSU_GET_INFO_FLAG_* bits */
    __u32 features; /* Output: max feature ID supported */
    __u32 uapi_version; /* Output: KERNEL_SU_UAPI_VERSION */
};

struct ksu_get_info_legacy_cmd {
    __u32 version; /* Output: KERNEL_SU_VERSION */
    __u32 flags; /* Output: KSU_GET_INFO_FLAG_* bits */
    __u32 features; /* Output: max feature ID supported */
};

struct ksu_report_event_cmd {
    __u32 event; /* Input: EVENT_POST_FS_DATA, EVENT_BOOT_COMPLETED, etc. */
};

struct ksu_set_sepolicy_cmd {
    __u64 data_len; /* Input: bytes of serialized command payload */
    __aligned_u64 data; /* Input: pointer to serialized payload */
};

struct ksu_sepolicy_cmd_hdr {
    __u32 cmd; /* Input: command type, CMD_* */
    __u32 subcmd; /* Input: command subtype */
};
/*
 * After each ksu_sepolicy_cmd_hdr, command arguments are encoded sequentially as:
 * [u32 len][len bytes][\0], where len excludes the trailing '\0'.
 * len == 0 represents ALL.
 * Argument count is derived from cmd:
 * KSU_SEPOLICY_CMD_NORMAL_PERM=4, KSU_SEPOLICY_CMD_XPERM=5,
 * KSU_SEPOLICY_CMD_TYPE_STATE=1, KSU_SEPOLICY_CMD_TYPE=2,
 * KSU_SEPOLICY_CMD_TYPE_ATTR=2, KSU_SEPOLICY_CMD_ATTR=1,
 * KSU_SEPOLICY_CMD_TYPE_TRANSITION=5, KSU_SEPOLICY_CMD_TYPE_CHANGE=4,
 * KSU_SEPOLICY_CMD_GENFSCON=3.
 */

struct ksu_check_safemode_cmd {
    __u8 in_safe_mode; /* Output: true if in safe mode, false otherwise */
};

/* deprecated */
struct ksu_get_allow_list_cmd {
    __u32 uids[128]; /* Output: array of allowed/denied UIDs */
    __u32 count; /* Output: number of UIDs in array */
    __u8 allow; /* Input: true for allow list, false for deny list */
};

struct ksu_new_get_allow_list_cmd {
    __u16 count; /* Input / Output: number of UIDs in array */
    __u16 total_count; /* Output: total number of UIDs in requested list */
    __u32 uids[0]; /* Output: array of allowed/denied UIDs */
};

struct ksu_uid_granted_root_cmd {
    __u32 uid; /* Input: target UID to check */
    __u8 granted; /* Output: true if granted, false otherwise */
};

struct ksu_uid_should_umount_cmd {
    __u32 uid; /* Input: target UID to check */
    __u8 should_umount; /* Output: true if should umount, false otherwise */
};

struct ksu_get_manager_appid_cmd {
    __u32 appid; /* Output: manager app id */
};

struct ksu_get_app_profile_cmd {
    struct app_profile profile; /* Input/Output: app profile structure */
};

struct ksu_set_app_profile_cmd {
    struct app_profile profile; /* Input: app profile structure */
};

struct ksu_get_feature_cmd {
    __u32 feature_id; /* Input: feature ID (enum ksu_feature_id) */
    __u64 value; /* Output: feature value/state */
    __u8 supported; /* Output: true if feature is supported, false otherwise */
};

struct ksu_set_feature_cmd {
    __u32 feature_id; /* Input: feature ID (enum ksu_feature_id) */
    __u64 value; /* Input: feature value/state to set */
};

struct ksu_get_wrapper_fd_cmd {
    __u32 fd; /* Input: userspace fd */
    __u32 flags; /* Input: flags of userspace fd */
};

struct ksu_manage_mark_cmd {
    __u32 operation; /* Input: KSU_MARK_* */
    __s32 pid; /* Input: target pid (0 for all processes) */
    __u32 result; /* Output: for get operation - mark status or reg_count */
};

static const __u32 KSU_MARK_GET = 1;
static const __u32 KSU_MARK_MARK = 2;
static const __u32 KSU_MARK_UNMARK = 3;
static const __u32 KSU_MARK_REFRESH = 4;

struct ksu_nuke_ext4_sysfs_cmd {
    __aligned_u64 arg; /* Input: mnt pointer */
};

struct ksu_add_try_umount_cmd {
    __aligned_u64 arg; /* char ptr, this is the mountpoint */
    __u32 flags; /* this is the flag we use for it */
    __u8 mode; /* denotes what to do with it 0:wipe_list 1:add_to_list 2:delete_entry */
};

struct ksu_get_sulog_fd_cmd {
    __u32 flags; /* Input: reserved for future use, must be 0 */
};

struct ksu_set_spoof_version_cmd {
    __u8 release[65]; /* Input: e.g., "5.10.115-android12-9-g00000000" */
    __u8 version[65]; /* Input: e.g., "#1 SMP PREEMPT Thu Jan 1 00:00:00 UTC 2026" */
};

// List current umount entries
struct ksu_list_try_umount_cmd {
    __aligned_u64 arg; // User buffer
    __u32 buf_size; // Buffer size provided by userspace
};

static const __u8 KSU_UMOUNT_WIPE = 0; /* ignore everything and wipe list */
static const __u8 KSU_UMOUNT_ADD = 1; /* add entry (path + flags) */
static const __u8 KSU_UMOUNT_DEL = 2; /* delete entry, strcmp */

// Other command structures
struct ksu_get_full_version_cmd {
    char version_full[255]; // Output: full version string
};

struct ksu_hook_type_cmd {
    char hook_type[32]; // Output: hook type string
};

struct ksu_enable_kpm_cmd {
    __u8 enabled; // Output: true if KPM is enabled
};

static const __u32 SUKISU_KPM_LOAD = 1;
static const __u32 SUKISU_KPM_UNLOAD = 2;
static const __u32 SUKISU_KPM_NUM = 3;
static const __u32 SUKISU_KPM_LIST = 4;
static const __u32 SUKISU_KPM_INFO = 5;
static const __u32 SUKISU_KPM_CONTROL = 6;
static const __u32 SUKISU_KPM_VERSION = 7;

struct ksu_kpm_cmd {
    __aligned_u64 __user control_code;
    __aligned_u64 __user arg1;
    __aligned_u64 __user arg2;
    __aligned_u64 __user result_code;
};

/* IOCTL command definitions */
static const __u32 KSU_IOCTL_GRANT_ROOT = _IOC(_IOC_NONE, 'K', 1, 0);
static const __u32 KSU_IOCTL_GET_INFO = _IOR('K', 2, struct ksu_get_info_cmd);
/* deprecated */
static const __u32 KSU_IOCTL_GET_INFO_LEGACY = _IOC(_IOC_READ, 'K', 2, 0);
static const __u32 KSU_IOCTL_REPORT_EVENT = _IOC(_IOC_WRITE, 'K', 3, 0);
static const __u32 KSU_IOCTL_SET_SEPOLICY = _IOC(_IOC_READ | _IOC_WRITE, 'K', 4, 0);
static const __u32 KSU_IOCTL_CHECK_SAFEMODE = _IOC(_IOC_READ, 'K', 5, 0);
/* deprecated */
static const __u32 KSU_IOCTL_GET_ALLOW_LIST = _IOC(_IOC_READ | _IOC_WRITE, 'K', 6, 0);
/* deprecated */
static const __u32 KSU_IOCTL_GET_DENY_LIST = _IOC(_IOC_READ | _IOC_WRITE, 'K', 7, 0);
static const __u32 KSU_IOCTL_NEW_GET_ALLOW_LIST = _IOWR('K', 6, struct ksu_new_get_allow_list_cmd);
static const __u32 KSU_IOCTL_NEW_GET_DENY_LIST = _IOWR('K', 7, struct ksu_new_get_allow_list_cmd);
static const __u32 KSU_IOCTL_UID_GRANTED_ROOT = _IOC(_IOC_READ | _IOC_WRITE, 'K', 8, 0);
static const __u32 KSU_IOCTL_UID_SHOULD_UMOUNT = _IOC(_IOC_READ | _IOC_WRITE, 'K', 9, 0);
static const __u32 KSU_IOCTL_GET_MANAGER_APPID = _IOC(_IOC_READ, 'K', 10, 0);
static const __u32 KSU_IOCTL_GET_APP_PROFILE = _IOC(_IOC_READ | _IOC_WRITE, 'K', 11, 0);
static const __u32 KSU_IOCTL_SET_APP_PROFILE = _IOC(_IOC_WRITE, 'K', 12, 0);
static const __u32 KSU_IOCTL_GET_FEATURE = _IOC(_IOC_READ | _IOC_WRITE, 'K', 13, 0);
static const __u32 KSU_IOCTL_SET_FEATURE = _IOC(_IOC_WRITE, 'K', 14, 0);
static const __u32 KSU_IOCTL_GET_WRAPPER_FD = _IOC(_IOC_WRITE, 'K', 15, 0);
static const __u32 KSU_IOCTL_MANAGE_MARK = _IOC(_IOC_READ | _IOC_WRITE, 'K', 16, 0);
static const __u32 KSU_IOCTL_NUKE_EXT4_SYSFS = _IOC(_IOC_WRITE, 'K', 17, 0);
static const __u32 KSU_IOCTL_ADD_TRY_UMOUNT = _IOC(_IOC_WRITE, 'K', 18, 0);
static const __u32 KSU_IOCTL_SET_INIT_PGRP = _IO('K', 19);
static const __u32 KSU_IOCTL_GET_SULOG_FD = _IOW('K', 20, struct ksu_get_sulog_fd_cmd);
static const __u32 KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT = _IO('K', 21);
// Other IOCTL command definitions
static const __u32 KSU_IOCTL_GET_FULL_VERSION = _IOC(_IOC_READ, 'K', 100, 0);
static const __u32 KSU_IOCTL_HOOK_TYPE = _IOC(_IOC_READ, 'K', 101, 0);
static const __u32 KSU_IOCTL_ENABLE_KPM = _IOC(_IOC_READ, 'K', 102, 0);
static const __u32 KSU_IOCTL_LIST_TRY_UMOUNT = _IOC(_IOC_READ | _IOC_WRITE, 'K', 103, 0);
static const __u32 KSU_IOCTL_SET_SPOOF_VERSION = _IOC(_IOC_WRITE, 'K', 104, 0);
static const __u32 KSU_IOCTL_KPM = _IOC(_IOC_READ | _IOC_WRITE, 'K', 200, 0);

/* ---------------------------------------------------------------------------
 * uhook - general kernel-mediated userspace instrumentation via uprobes.
 */
enum ksu_uhook_op {
    KSU_UHOOK_ADD   = 1, /* install a hook -> ret = hook id (>= 0) */
    KSU_UHOOK_DEL   = 2, /* remove hook `id` */
    KSU_UHOOK_CLEAR = 3, /* remove every hook */
    KSU_UHOOK_LIST  = 4, /* ret = number of active hooks */
    KSU_UHOOK_READ  = 5, /* drain the capture ring into uptr(len); ret = bytes, arg1 = records */
};

enum ksu_uhook_site {
    KSU_UHOOK_ON_ENTRY = 0, /* fire when the probed instruction is reached */
    KSU_UHOOK_ON_RET   = 1, /* fire when the function returns (uretprobe) */
};

enum ksu_uhook_action {
    KSU_UHOOK_OBSERVE   = 0, /* record registers into the capture ring (no side effect) */
    KSU_UHOOK_SETREG    = 1, /* regs[act_reg] = act_val (e.g. x0 at a return = forged result) */
    KSU_UHOOK_FORCE_RET = 2, /* return immediately from the function: pc = lr (entry site) */
    KSU_UHOOK_JUMP      = 3, /* pc = act_val (detour) */
    KSU_UHOOK_SKIP      = 4, /* pc += act_val (step over act_val bytes) */
    KSU_UHOOK_POKE      = 5, /* write the ADD-supplied bytes to *(regs[act_reg]) + act_off */
};

enum ksu_uhook_cond {
    KSU_UHOOK_COND_NONE = 0, /* always fire */
    KSU_UHOOK_COND_REG  = 1, /* fire iff regs[cond_reg] <cmp> cond_val */
    KSU_UHOOK_COND_MEM  = 2, /* fire iff the cond_len-byte value at regs[cond_reg]+cond_off <cmp> cond_val */
};

enum ksu_uhook_cmp {
    KSU_UHOOK_EQ  = 0,
    KSU_UHOOK_NE  = 1,
    KSU_UHOOK_LT  = 2,
    KSU_UHOOK_GT  = 3,
    KSU_UHOOK_AND = 4, /* (value & cond_val) != 0 */
};

struct ksu_uhook_cmd {
    __u32 op;             /* Input: enum ksu_uhook_op */
    __u32 id;             /* Input: hook id (DEL); ADD returns the id via ret */
    /* --- where --- */
    __aligned_u64 path;   /* Input(ADD): user ptr to a NUL-terminated file path */
    __u64 offset;         /* Input(ADD): file offset of the probed instruction */
    __u32 site;           /* Input(ADD): enum ksu_uhook_site */
    /* --- when --- */
    __u32 cond;           /* Input(ADD): enum ksu_uhook_cond */
    __u32 cond_reg;       /* Input(ADD): register index used by the condition */
    __u32 cond_cmp;       /* Input(ADD): enum ksu_uhook_cmp */
    __u32 cond_len;       /* Input(ADD): mem condition width: 1/2/4/8 */
    __s64 cond_off;       /* Input(ADD): mem condition byte offset from *cond_reg */
    __u64 cond_val;       /* Input(ADD): value to compare against */
    /* --- what --- */
    __u32 action;         /* Input(ADD): enum ksu_uhook_action */
    __u32 act_reg;        /* Input(ADD): SETREG/POKE register index */
    __s64 act_off;        /* Input(ADD): POKE byte offset from *act_reg */
    __u64 act_val;        /* Input(ADD): SETREG value / JUMP addr / SKIP byte count */
    /* --- capture / IO --- */
    __aligned_u64 uptr;   /* Input(ADD POKE): bytes to write; Output(READ): packed records */
    __u64 len;            /* Input: uptr byte length */
    __u32 cap_regs;       /* Input(ADD OBSERVE): number of leading registers to record (0..34) */
    __s64 ret;            /* Output: op result (ADD: hook id; READ: bytes; LIST: count) */
    __u64 arg1;           /* Output: op-specific (READ: number of records) */
};

/* One capture record produced by KSU_UHOOK_OBSERVE and read back by KSU_UHOOK_READ. */
struct ksu_uhook_record {
    __u32 id;             /* hook id that fired */
    __s32 tid;            /* thread id that hit the probe */
    __u64 ts_ns;          /* monotonic timestamp */
    __u64 regs[34];       /* x0..x30, sp, pc, pstate (first cap_regs are meaningful) */
};

static const __u32 KSU_IOCTL_UHOOK = _IOWR('K', 51, struct ksu_uhook_cmd);

#endif