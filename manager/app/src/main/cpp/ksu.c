//
// Created by weishu on 2022/12/9.
//

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <android/log.h>
#include <dirent.h>
#include <stdlib.h>
#include <limits.h>

#include "prelude.h"
#include "ksu.h"

static int fd = -1;

static inline int scan_driver_fd() {
	const char *kName = "[ksu_driver]";
	DIR *fd_dir = opendir("/proc/self/fd");
	if (!fd_dir) {
		return -1;
	}

	int found = -1;
	struct dirent *de;
	char path[64];
	char target[PATH_MAX];

	while ((de = readdir(fd_dir)) != NULL) {
		if (de->d_name[0] == '.') {
			continue;
		}

		char *endptr = nullptr;
		long fd_long = strtol(de->d_name, &endptr, 10);
		if (!de->d_name[0] || *endptr != '\0' || fd_long < 0 || fd_long > INT_MAX) {
			continue;
		}

		snprintf(path, sizeof(path), "/proc/self/fd/%s", de->d_name);
		ssize_t n = readlink(path, target, sizeof(target) - 1);
		if (n < 0) {
			continue;
		}
		target[n] = '\0';

		const char *base = strrchr(target, '/');
		base = base ? base + 1 : target;

		if (strstr(base, kName)) {
			found = (int)fd_long;
			break;
		}
	}

	closedir(fd_dir);
	return found;
}

static int ksuctl(unsigned long op, void* arg) {
	if (fd < 0) {
		fd = scan_driver_fd();
	}
	return ioctl(fd, op, arg);
}

static struct ksu_get_info_cmd g_version = {0};

struct ksu_get_info_cmd get_info() {
	if (!g_version.version) {
		ksuctl(KSU_IOCTL_GET_INFO, &g_version);
	}
	return g_version;
}

uint32_t get_version() {
	auto info = get_info();
	return info.version;
}

bool get_allow_list(struct ksu_get_allow_list_cmd *cmd) {
    if (ksuctl(KSU_IOCTL_GET_ALLOW_LIST, cmd) == 0) {
        return true;
    }

    // fallback to legacy
    int size = 0;
    int uids[1024];
    if (legacy_get_allow_list(uids, &size)) {
        cmd->count = size;
        memcpy(cmd->uids, uids, sizeof(int) * size);
        return true;
    }

    return false;
}

bool is_safe_mode() {
    struct ksu_check_safemode_cmd cmd = {};
    if (ksuctl(KSU_IOCTL_CHECK_SAFEMODE, &cmd) == 0) {
        return cmd.in_safe_mode;
    }
    // fallback
    return legacy_is_safe_mode();
}

bool is_lkm_mode() {
    auto info = get_info();
    if (info.version > 0) {
        return (info.flags & 0x1) != 0;
    }
    // Legacy Compatible
    return (legacy_get_info().flags & 0x1) != 0;
}

bool is_manager() {
    auto info = get_info();
    if (info.version > 0) {
        return (info.flags & 0x2) != 0;
    }
    // Legacy Compatible
    return legacy_get_info().version > 0;
}

bool uid_should_umount(int uid) {
    struct ksu_uid_should_umount_cmd cmd = {};
    cmd.uid = uid;
    if (ksuctl(KSU_IOCTL_UID_SHOULD_UMOUNT, &cmd) == 0) {
        return cmd.should_umount;
    }
    return legacy_uid_should_umount(uid);
}

bool set_app_profile(const struct app_profile *profile) {
    struct ksu_set_app_profile_cmd cmd = {};
    cmd.profile = *profile;
    if (ksuctl(KSU_IOCTL_SET_APP_PROFILE, &cmd) == 0) {
        return true;
    }
    return legacy_set_app_profile(profile);
}

int get_app_profile(struct app_profile *profile) {
    struct ksu_get_app_profile_cmd cmd = {.profile = *profile};
    int ret = ksuctl(KSU_IOCTL_GET_APP_PROFILE, &cmd);
    if (ret == 0) {
        *profile = cmd.profile;
        return 0;
    }
    return legacy_get_app_profile(profile->key, profile) ? 0 : -1;
}

bool set_su_enabled(bool enabled) {
    struct ksu_set_feature_cmd cmd = {};
    cmd.feature_id = KSU_FEATURE_SU_COMPAT;
    cmd.value = enabled ? 1 : 0;
    if (ksuctl(KSU_IOCTL_SET_FEATURE, &cmd) == 0) {
        return true;
    }
    return legacy_set_su_enabled(enabled);
}

bool is_su_enabled() {
    struct ksu_get_feature_cmd cmd = {};
    cmd.feature_id = KSU_FEATURE_SU_COMPAT;
    if (ksuctl(KSU_IOCTL_GET_FEATURE, &cmd) == 0 && cmd.supported) {
        return cmd.value != 0;
    }
    return legacy_is_su_enabled();
}

static inline bool get_feature(uint32_t feature_id, uint64_t *out_value, bool *out_supported) {
    struct ksu_get_feature_cmd cmd = {};
    cmd.feature_id = feature_id;
    if (ksuctl(KSU_IOCTL_GET_FEATURE, &cmd) != 0) {
        return false;
    }
    if (out_value) *out_value = cmd.value;
    if (out_supported) *out_supported = cmd.supported;
    return true;
}

static inline bool set_feature(uint32_t feature_id, uint64_t value) {
    struct ksu_set_feature_cmd cmd = {};
    cmd.feature_id = feature_id;
    cmd.value = value;
    return ksuctl(KSU_IOCTL_SET_FEATURE, &cmd) == 0;
}

bool set_kernel_umount_enabled(bool enabled) {
    return set_feature(KSU_FEATURE_KERNEL_UMOUNT, enabled ? 1 : 0);
}

bool is_kernel_umount_enabled() {
    uint64_t value = 0;
    bool supported = false;
    if (!get_feature(KSU_FEATURE_KERNEL_UMOUNT, &value, &supported)) {
        return false;
    }
    if (!supported) {
        return false;
    }
    return value != 0;
}

bool set_enhanced_security_enabled(bool enabled) {
    return set_feature(KSU_FEATURE_ENHANCED_SECURITY, enabled ? 1 : 0);
}

bool is_enhanced_security_enabled() {
    uint64_t value = 0;
    bool supported = false;
    if (!get_feature(KSU_FEATURE_ENHANCED_SECURITY, &value, &supported)) {
        return false;
    }
    if (!supported) {
        return false;
    }
    return value != 0;
}

bool set_sulog_enabled(bool enabled) {
    return set_feature(KSU_FEATURE_SULOG, enabled ? 1 : 0);
}

bool is_sulog_enabled() {
    uint64_t value = 0;
    bool supported = false;
    if (!get_feature(KSU_FEATURE_SULOG, &value, &supported)) {
        return false;
    }
    if (!supported) {
        return false;
    }
    return value != 0;
}

void get_full_version(char* buff) {
	struct ksu_get_full_version_cmd cmd = {0};
	if (ksuctl(KSU_IOCTL_GET_FULL_VERSION, &cmd) == 0) {
		strncpy(buff, cmd.version_full, KSU_FULL_VERSION_STRING - 1);
		buff[KSU_FULL_VERSION_STRING - 1] = '\0';
	} else {
        return legacy_get_full_version(buff);
	}
}

bool is_KPM_enable(void) {
    struct ksu_enable_kpm_cmd cmd = {};
    if (ksuctl(KSU_IOCTL_ENABLE_KPM, &cmd) == 0 && cmd.enabled) {
        return true;
    }
    return legacy_is_KPM_enable();
}

void get_hook_type(char *buff) {
    struct ksu_hook_type_cmd cmd = {0};
    if (ksuctl(KSU_IOCTL_HOOK_TYPE, &cmd) == 0) {
        strncpy(buff, cmd.hook_type, 32 - 1);
        buff[32 - 1] = '\0';
    } else {
        legacy_get_hook_type(buff, 32);
    }
}

bool set_dynamic_manager(unsigned int size, const char *hash)
{
	struct ksu_dynamic_manager_cmd cmd = {0};
	cmd.config.operation = DYNAMIC_MANAGER_OP_SET;
	cmd.config.size	  = size;
	strlcpy(cmd.config.hash, hash, sizeof(cmd.config.hash));

	return ksuctl(KSU_IOCTL_DYNAMIC_MANAGER, &cmd) == 0;
}

bool get_dynamic_manager(struct dynamic_manager_user_config *cfg)
{
	if (!cfg) 
		return false;

	struct ksu_dynamic_manager_cmd cmd = {0};
	cmd.config.operation = DYNAMIC_MANAGER_OP_GET;

	if (ksuctl(KSU_IOCTL_DYNAMIC_MANAGER, &cmd) != 0)
		return false;

	*cfg = cmd.config;
	return true;
}

bool clear_dynamic_manager(void)
{
	struct ksu_dynamic_manager_cmd cmd = {0};
	cmd.config.operation = DYNAMIC_MANAGER_OP_CLEAR;
	return ksuctl(KSU_IOCTL_DYNAMIC_MANAGER, &cmd) == 0;
}

bool get_managers_list(struct manager_list_info *info)
{
	if (!info)
		return false;
	struct ksu_get_managers_cmd cmd = {0};
	if (ksuctl(KSU_IOCTL_GET_MANAGERS, &cmd) != 0)
		return false;

	*info = cmd.manager_info;
	return true;
}

bool is_uid_scanner_enabled(void)
{
	bool status = false;

	struct ksu_enable_uid_scanner_cmd cmd = {
			.operation  = UID_SCANNER_OP_GET_STATUS,
			.status_ptr = (__u64)(uintptr_t)&status
	};

	return ksuctl(KSU_IOCTL_ENABLE_UID_SCANNER, &cmd) == 0 != 0 && status;
}

bool set_uid_scanner_enabled(bool enabled)
{
	struct ksu_enable_uid_scanner_cmd cmd = {
			.operation = UID_SCANNER_OP_TOGGLE,
			.enabled   = enabled
	};
	return ksuctl(KSU_IOCTL_ENABLE_UID_SCANNER, &cmd);
}

bool clear_uid_scanner_environment(void)
{
	struct ksu_enable_uid_scanner_cmd cmd = {
			.operation = UID_SCANNER_OP_CLEAR_ENV
	};
	return ksuctl(KSU_IOCTL_ENABLE_UID_SCANNER, &cmd);
}