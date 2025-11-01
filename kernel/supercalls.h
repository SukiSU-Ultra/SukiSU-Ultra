#ifndef __KSU_H_SUPERCALLS
#define __KSU_H_SUPERCALLS

#include <linux/types.h>
#include <linux/ioctl.h>
#include "ksu.h"

// Magic numbers for reboot hook to install fd
#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE

// Command structures for ioctl

struct ksu_become_daemon_cmd {
    __u8 token[65]; // Input: daemon token (null-terminated)
};

struct ksu_get_info_cmd {
    __u32 version; // Output: KERNEL_SU_VERSION
    __u32 flags; // Output: flags (bit 0: MODULE mode)
};

struct ksu_report_event_cmd {
    __u32 event; // Input: EVENT_POST_FS_DATA, EVENT_BOOT_COMPLETED, etc.
};

struct ksu_set_sepolicy_cmd {
    __u64 cmd; // Input: sepolicy command
    __aligned_u64 arg; // Input: sepolicy argument pointer
};

struct ksu_check_safemode_cmd {
    __u8 in_safe_mode; // Output: true if in safe mode, false otherwise
};

struct ksu_get_allow_list_cmd {
    __u32 uids[128]; // Output: array of allowed/denied UIDs
    __u32 count; // Output: number of UIDs in array
    __u8 allow; // Input: true for allow list, false for deny list
};

struct ksu_uid_granted_root_cmd {
    __u32 uid; // Input: target UID to check
    __u8 granted; // Output: true if granted, false otherwise
};

struct ksu_uid_should_umount_cmd {
    __u32 uid; // Input: target UID to check
    __u8 should_umount; // Output: true if should umount, false otherwise
};

struct ksu_get_manager_uid_cmd {
    __u32 uid; // Output: manager UID
};

struct ksu_get_app_profile_cmd {
    struct app_profile profile; // Input/Output: app profile structure
};

struct ksu_set_app_profile_cmd {
    struct app_profile profile; // Input: app profile structure
};

struct ksu_is_su_enabled_cmd {
    __u8 enabled; // Output: true if su compat enabled
};

struct ksu_enable_su_cmd {
    __u8 enable; // Input: true to enable, false to disable
};

// Other command structures
struct ksu_get_full_version_cmd {
    char version_full[KSU_FULL_VERSION_STRING]; // Output: full version string
};

struct ksu_hook_type_cmd {
    char hook_type[32]; // Output: hook type string
};

struct ksu_enable_kpm_cmd {
    __u8 enabled; // Output: true if KPM is enabled
};

struct ksu_dynamic_manager_cmd {
    struct dynamic_manager_user_config config; // Input/Output: dynamic manager config
};

struct ksu_get_managers_cmd {
    struct manager_list_info manager_info; // Output: manager list information
};

struct ksu_enable_uid_scanner_cmd {
    __u32 operation; // Input: operation type (UID_SCANNER_OP_GET_STATUS, UID_SCANNER_OP_TOGGLE, UID_SCANNER_OP_CLEAR_ENV)
    __u32 enabled; // Input: enable or disable (for UID_SCANNER_OP_TOGGLE)
    void __user *status_ptr; // Input: pointer to store status (for UID_SCANNER_OP_GET_STATUS)
};

// IOCTL command definitions
#define KSU_IOCTL_GRANT_ROOT _IO('K', 1)
#define KSU_IOCTL_GET_INFO _IOR('K', 2, struct ksu_get_info_cmd)
#define KSU_IOCTL_REPORT_EVENT _IOW('K', 3, struct ksu_report_event_cmd)
#define KSU_IOCTL_SET_SEPOLICY _IOWR('K', 4, struct ksu_set_sepolicy_cmd)
#define KSU_IOCTL_CHECK_SAFEMODE _IOR('K', 5, struct ksu_check_safemode_cmd)
#define KSU_IOCTL_GET_ALLOW_LIST _IOWR('K', 6, struct ksu_get_allow_list_cmd)
#define KSU_IOCTL_GET_DENY_LIST _IOWR('K', 7, struct ksu_get_allow_list_cmd)
#define KSU_IOCTL_UID_GRANTED_ROOT _IOWR('K', 8, struct ksu_uid_granted_root_cmd)
#define KSU_IOCTL_UID_SHOULD_UMOUNT _IOWR('K', 9, struct ksu_uid_should_umount_cmd)
#define KSU_IOCTL_GET_MANAGER_UID _IOR('K', 10, struct ksu_get_manager_uid_cmd)
#define KSU_IOCTL_GET_APP_PROFILE _IOWR('K', 11, struct ksu_get_app_profile_cmd)
#define KSU_IOCTL_SET_APP_PROFILE _IOW('K', 12, struct ksu_set_app_profile_cmd)
#define KSU_IOCTL_IS_SU_ENABLED _IOR('K', 13, struct ksu_is_su_enabled_cmd)
#define KSU_IOCTL_ENABLE_SU _IOW('K', 14, struct ksu_enable_su_cmd)
// Other IOCTL command definitions
#define KSU_IOCTL_GET_FULL_VERSION _IOR('K', 100, struct ksu_get_full_version_cmd)
#define KSU_IOCTL_HOOK_TYPE _IOR('K', 101, struct ksu_hook_type_cmd)
#define KSU_IOCTL_ENABLE_KPM _IOR('K', 102, struct ksu_enable_kpm_cmd)
#define KSU_IOCTL_DYNAMIC_MANAGER _IOWR('K', 103, struct ksu_dynamic_manager_cmd)
#define KSU_IOCTL_GET_MANAGERS _IOWR('K', 104, struct ksu_get_managers_cmd)
#define KSU_IOCTL_ENABLE_UID_SCANNER _IOWR('K', 105, struct ksu_enable_uid_scanner_cmd)

// IOCTL handler types
typedef int (*ksu_ioctl_handler_t)(void __user *arg);
typedef bool (*ksu_perm_check_t)(void);

// Permission check functions
bool perm_check_manager(void);
bool perm_check_root(void);
bool perm_check_basic(void);
bool perm_check_all(void);

// IOCTL command mapping
struct ksu_ioctl_cmd_map {
    unsigned int cmd;
    ksu_ioctl_handler_t handler;
    ksu_perm_check_t perm_check; // Permission check function
};

// Install KSU fd to current process
int ksu_install_fd(void);

#endif // __KSU_H_SUPERCALLS