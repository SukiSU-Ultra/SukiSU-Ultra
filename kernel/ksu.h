#ifndef __KSU_H_KSU
#define __KSU_H_KSU

#include <linux/types.h>
#include <linux/workqueue.h>

#define KERNEL_SU_VERSION KSU_VERSION
#define KERNEL_SU_OPTION 0xDEADBEEF

#define CMD_GRANT_ROOT 0
#define CMD_BECOME_MANAGER 1
#define CMD_GET_VERSION 2
#define CMD_ALLOW_SU 3
#define CMD_DENY_SU 4
#define CMD_GET_ALLOW_LIST 5
#define CMD_GET_DENY_LIST 6
#define CMD_REPORT_EVENT 7
#define CMD_SET_SEPOLICY 8
#define CMD_CHECK_SAFEMODE 9
#define CMD_GET_APP_PROFILE 10
#define CMD_SET_APP_PROFILE 11
#define CMD_UID_GRANTED_ROOT 12
#define CMD_UID_SHOULD_UMOUNT 13
#define CMD_IS_SU_ENABLED 14
#define CMD_ENABLE_SU 15

#define CMD_GET_FULL_VERSION 0xC0FFEE1A

#define CMD_ENABLE_KPM 100
#define CMD_HOOK_TYPE 101
#define CMD_GET_SUSFS_FEATURE_STATUS 102
#define CMD_DYNAMIC_SIGN 103
#define CMD_GET_MANAGERS 104

#define EVENT_POST_FS_DATA 1
#define EVENT_BOOT_COMPLETED 2
#define EVENT_MODULE_MOUNTED 3

#define KSU_APP_PROFILE_VER 2
#define KSU_MAX_PACKAGE_NAME 256
// NGROUPS_MAX for Linux is 65535 generally, but we only supports 32 groups.
#define KSU_MAX_GROUPS 32
#define KSU_SELINUX_DOMAIN 64

// SukiSU Ultra kernel su version full strings
#ifndef KSU_VERSION_FULL 
#define KSU_VERSION_FULL "v3.x-00000000@unknown"
#endif
#define KSU_FULL_VERSION_STRING 255

#define DYNAMIC_SIGN_OP_SET 0
#define DYNAMIC_SIGN_OP_GET 1
#define DYNAMIC_SIGN_OP_CLEAR 2

struct dynamic_sign_user_config {
    unsigned int operation;
    unsigned int size;
    char hash[65];
};

struct manager_list_info {
    int count;
    struct {
        uid_t uid;
        int signature_index;
    } managers[2];
};

// SUSFS Functional State Structures
struct susfs_feature_status {
	bool status_sus_path;
	bool status_sus_mount;
	bool status_auto_default_mount;
	bool status_auto_bind_mount;
	bool status_sus_kstat;
	bool status_try_umount;
	bool status_auto_try_umount_bind;
	bool status_spoof_uname;
	bool status_enable_log;
	bool status_hide_symbols;
	bool status_spoof_cmdline;
	bool status_open_redirect;
	bool status_magic_mount;
	bool status_overlayfs_auto_kstat;
	bool status_sus_su;
};

struct susfs_config_map {
    bool *status_field;
    bool is_enabled;
};

#define SUSFS_FEATURE_CHECK(config, field) \
    do { \
        status->field = IS_ENABLED(config); \
    } while(0)

static inline void init_susfs_feature_status(struct susfs_feature_status *status) 
{
    memset(status, 0, sizeof(*status));
    
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_SUS_PATH, status_sus_path);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_SUS_MOUNT, status_sus_mount);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT, status_auto_default_mount);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT, status_auto_bind_mount);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_SUS_KSTAT, status_sus_kstat);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_TRY_UMOUNT, status_try_umount);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT, status_auto_try_umount_bind);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_SPOOF_UNAME, status_spoof_uname);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_ENABLE_LOG, status_enable_log);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS, status_hide_symbols);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG, status_spoof_cmdline);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_OPEN_REDIRECT, status_open_redirect);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT, status_magic_mount);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_SUS_OVERLAYFS, status_overlayfs_auto_kstat);
    SUSFS_FEATURE_CHECK(CONFIG_KSU_SUSFS_SUS_SU, status_sus_su);
}

struct root_profile {
	int32_t uid;
	int32_t gid;

	int32_t groups_count;
	int32_t groups[KSU_MAX_GROUPS];

	// kernel_cap_t is u32[2] for capabilities v3
	struct {
		u64 effective;
		u64 permitted;
		u64 inheritable;
	} capabilities;

	char selinux_domain[KSU_SELINUX_DOMAIN];

	int32_t namespaces;
};

struct non_root_profile {
	bool umount_modules;
};

struct app_profile {
	// It may be utilized for backward compatibility, although we have never explicitly made any promises regarding this.
	u32 version;

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

bool ksu_queue_work(struct work_struct *work);

static inline int startswith(char *s, char *prefix)
{
	return strncmp(s, prefix, strlen(prefix));
}

static inline int endswith(const char *s, const char *t)
{
	size_t slen = strlen(s);
	size_t tlen = strlen(t);
	if (tlen > slen)
		return 1;
	return strcmp(s + slen - tlen, t);
}

#endif