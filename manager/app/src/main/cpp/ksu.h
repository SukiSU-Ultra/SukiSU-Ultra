//
// Created by weishu on 2022/12/9.
//

#ifndef KERNELSU_KSU_H
#define KERNELSU_KSU_H

#include "prelude.h"
#include <stdint.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#define KSU_FULL_VERSION_STRING 255

uint32_t get_version();

bool uid_should_umount(int uid);

bool is_safe_mode();

bool is_lkm_mode();

bool is_manager();

void get_full_version(char* buff);

#define KSU_APP_PROFILE_VER 2
#define KSU_MAX_PACKAGE_NAME 256
// NGROUPS_MAX for Linux is 65535 generally, but we only supports 32 groups.
#define KSU_MAX_GROUPS 32
#define KSU_SELINUX_DOMAIN 64

#define DYNAMIC_MANAGER_OP_SET 0
#define DYNAMIC_MANAGER_OP_GET 1
#define DYNAMIC_MANAGER_OP_CLEAR 2

#define UID_SCANNER_OP_GET_STATUS 0
#define UID_SCANNER_OP_TOGGLE 1
#define UID_SCANNER_OP_CLEAR_ENV 2

struct dynamic_manager_user_config {
	unsigned int operation;
	unsigned int size;
	char hash[65];
};


struct root_profile {
	int32_t uid;
	int32_t gid;

	int32_t groups_count;
	int32_t groups[KSU_MAX_GROUPS];

	// kernel_cap_t is u32[2] for capabilities v3
	struct {
		uint64_t effective;
		uint64_t permitted;
		uint64_t inheritable;
	} capabilities;

	char selinux_domain[KSU_SELINUX_DOMAIN];

	int32_t namespaces;
};

struct non_root_profile {
	bool umount_modules;
};

struct app_profile {
	// It may be utilized for backward compatibility, although we have never explicitly made any promises regarding this.
	uint32_t version;

	// this is usually the package of the app, but can be other value for special apps
	char key[KSU_MAX_PACKAGE_NAME];
	int32_t current_uid;
	bool allow_su;

	union {
		struct {
			bool use_default;
			char template_name[KSU_MAX_PACKAGE_NAME];

			struct root_profile profile;
		} rp_config;

		struct {
			bool use_default;

			struct non_root_profile profile;
		} nrp_config;
	};
};

struct manager_list_info {
	int count;
	struct {
		uid_t uid;
		int signature_index;
	} managers[2];
};

bool set_app_profile(const struct app_profile* profile);

int get_app_profile(struct app_profile* profile);

bool is_KPM_enable();

void get_hook_type(char* hook_type);

bool set_dynamic_manager(unsigned int size, const char* hash);

bool get_dynamic_manager(struct dynamic_manager_user_config* config);

bool clear_dynamic_manager();

bool get_managers_list(struct manager_list_info* info);

bool is_uid_scanner_enabled();

bool set_uid_scanner_enabled(bool enabled);

bool clear_uid_scanner_environment();

// Feature IDs
enum ksu_feature_id {
    KSU_FEATURE_SU_COMPAT = 0,
    KSU_FEATURE_KERNEL_UMOUNT = 1,
    KSU_FEATURE_ENHANCED_SECURITY = 2,
	KSU_FEATURE_SULOG = 3,
};

// Generic feature API
struct ksu_get_feature_cmd {
    uint32_t feature_id; // Input: feature ID
    uint64_t value;      // Output: feature value/state
    uint8_t supported;   // Output: whether the feature is supported
};

struct ksu_set_feature_cmd {
    uint32_t feature_id; // Input: feature ID
    uint64_t value;      // Input: feature value/state to set
};

struct ksu_become_daemon_cmd {
    uint8_t token[65]; // Input: daemon token (null-terminated)
};

struct ksu_get_info_cmd {
    uint32_t version; // Output: KERNEL_SU_VERSION
    uint32_t flags; // Output: flags (bit 0: MODULE mode)
    uint32_t features; // Output: max feature ID supported (KSU_FEATURE_MAX)
};

struct ksu_report_event_cmd {
    uint32_t event; // Input: EVENT_POST_FS_DATA, EVENT_BOOT_COMPLETED, etc.
};

struct ksu_set_sepolicy_cmd {
    uint64_t cmd; // Input: sepolicy command
    uint64_t arg; // Input: sepolicy argument pointer
};

struct ksu_check_safemode_cmd {
    uint8_t in_safe_mode; // Output: true if in safe mode, false otherwise
};

struct ksu_get_allow_list_cmd {
    uint32_t uids[128]; // Output: array of allowed/denied UIDs
    uint32_t count; // Output: number of UIDs in array
    uint8_t allow; // Input: true for allow list, false for deny list
};

struct ksu_uid_granted_root_cmd {
    uint32_t uid; // Input: target UID to check
    uint8_t granted; // Output: true if granted, false otherwise
};

struct ksu_uid_should_umount_cmd {
    uint32_t uid; // Input: target UID to check
    uint8_t should_umount; // Output: true if should umount, false otherwise
};

struct ksu_get_manager_appid_cmd {
    uint32_t appid; // Output: manager app id
};

struct ksu_get_app_profile_cmd {
	struct app_profile profile; // Input/Output: app profile structure
};

struct ksu_set_app_profile_cmd {
	struct app_profile profile; // Input: app profile structure
};

// Su compat
bool set_su_enabled(bool enabled);
bool is_su_enabled();

// Kernel umount
bool set_kernel_umount_enabled(bool enabled);
bool is_kernel_umount_enabled();

// Enhanced security
bool set_enhanced_security_enabled(bool enabled);
bool is_enhanced_security_enabled();

// Su log
bool set_sulog_enabled(bool enabled);
bool is_sulog_enabled();

// Other command structures
struct ksu_get_full_version_cmd {
	char version_full[KSU_FULL_VERSION_STRING]; // Output: full version string
};

struct ksu_hook_type_cmd {
	char hook_type[32]; // Output: hook type string
};

struct ksu_enable_kpm_cmd {
    uint8_t enabled; // Output: true if KPM is enabled
};

struct ksu_dynamic_manager_cmd {
	struct dynamic_manager_user_config config; // Input/Output: dynamic manager config
};

struct ksu_get_managers_cmd {
	struct manager_list_info manager_info; // Output: manager list information
};

struct ksu_enable_uid_scanner_cmd {
    uint32_t operation; // Input: operation type (UID_SCANNER_OP_GET_STATUS, UID_SCANNER_OP_TOGGLE, UID_SCANNER_OP_CLEAR_ENV)
    uint32_t enabled; // Input: enable or disable (for UID_SCANNER_OP_TOGGLE)
    uint64_t status_ptr; // Input: pointer to store status (for UID_SCANNER_OP_GET_STATUS)
};

// IOCTL command definitions
#define KSU_IOCTL_GRANT_ROOT _IOC(_IOC_NONE, 'K', 1, 0)
#define KSU_IOCTL_GET_INFO _IOC(_IOC_READ, 'K', 2, 0)
#define KSU_IOCTL_REPORT_EVENT _IOC(_IOC_WRITE, 'K', 3, 0)
#define KSU_IOCTL_SET_SEPOLICY _IOC(_IOC_READ|_IOC_WRITE, 'K', 4, 0)
#define KSU_IOCTL_CHECK_SAFEMODE _IOC(_IOC_READ, 'K', 5, 0)
#define KSU_IOCTL_GET_ALLOW_LIST _IOC(_IOC_READ|_IOC_WRITE, 'K', 6, 0)
#define KSU_IOCTL_GET_DENY_LIST _IOC(_IOC_READ|_IOC_WRITE, 'K', 7, 0)
#define KSU_IOCTL_UID_GRANTED_ROOT _IOC(_IOC_READ|_IOC_WRITE, 'K', 8, 0)
#define KSU_IOCTL_UID_SHOULD_UMOUNT _IOC(_IOC_READ|_IOC_WRITE, 'K', 9, 0)
#define KSU_IOCTL_GET_MANAGER_APPID _IOC(_IOC_READ, 'K', 10, 0)
#define KSU_IOCTL_GET_APP_PROFILE _IOC(_IOC_READ|_IOC_WRITE, 'K', 11, 0)
#define KSU_IOCTL_SET_APP_PROFILE _IOC(_IOC_WRITE, 'K', 12, 0)
#define KSU_IOCTL_GET_FEATURE _IOC(_IOC_READ|_IOC_WRITE, 'K', 13, 0)
#define KSU_IOCTL_SET_FEATURE _IOC(_IOC_WRITE, 'K', 14, 0)

// Other IOCTL command definitions
#define KSU_IOCTL_GET_FULL_VERSION _IOC(_IOC_READ, 'K', 100, 0)
#define KSU_IOCTL_HOOK_TYPE _IOC(_IOC_READ, 'K', 101, 0)
#define KSU_IOCTL_ENABLE_KPM _IOC(_IOC_READ, 'K', 102, 0)
#define KSU_IOCTL_DYNAMIC_MANAGER _IOC(_IOC_READ|_IOC_WRITE, 'K', 103, 0)
#define KSU_IOCTL_GET_MANAGERS _IOC(_IOC_READ|_IOC_WRITE, 'K', 104, 0)
#define KSU_IOCTL_ENABLE_UID_SCANNER _IOC(_IOC_READ|_IOC_WRITE, 'K', 105, 0)

bool get_allow_list(struct ksu_get_allow_list_cmd *);

// Legacy Compatible
struct ksu_version_info legacy_get_info();

struct ksu_version_info {
    int32_t version;
    int32_t flags;
};

bool legacy_get_allow_list(int *uids, int *size);
bool legacy_is_safe_mode();
bool legacy_uid_should_umount(int uid);
bool legacy_set_app_profile(const struct app_profile* profile);
bool legacy_get_app_profile(char* key, struct app_profile* profile);
bool legacy_set_su_enabled(bool enabled);
bool legacy_is_su_enabled();
bool legacy_is_KPM_enable();
bool legacy_get_hook_type(char* hook_type, size_t size);
void legacy_get_full_version(char* buff);
bool legacy_set_dynamic_manager(unsigned int size, const char* hash);
bool legacy_get_dynamic_manager(struct dynamic_manager_user_config* config);
bool legacy_clear_dynamic_manager();
bool legacy_get_managers_list(struct manager_list_info* info);
bool legacy_is_uid_scanner_enabled();
bool legacy_set_uid_scanner_enabled(bool enabled);
bool legacy_clear_uid_scanner_environment();

#endif //KERNELSU_KSU_H