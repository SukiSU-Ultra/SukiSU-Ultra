//
// Created by weishu on 2022/12/9.
//

#include <sys/prctl.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <android/log.h>
#include <dirent.h>
#include <stdlib.h>

#include <sys/syscall.h>

#include "prelude.h"
#include "ksu.h"

#if defined(__aarch64__) || defined(_M_ARM64) || defined(__arm__) || defined(_M_ARM)

// Zako extern declarations
#define ZAKO_ESV_IMPORTANT_ERROR 1 << 31
extern int zako_sys_file_open(const char* path);
extern uint32_t zako_file_verify_esig(int fd, uint32_t flags);
extern const char* zako_file_verrcidx2str(uint8_t index);

#endif // __aarch64__ || _M_ARM64 || __arm__ || _M_ARM

static int fd = -1;

static inline int scan_driver_fd() {
	const char *kName = "[ksu_driver]";
	DIR *dir = opendir("/proc/self/fd");
	if (!dir) {
		return -1;
	}

	int found = -1;
	struct dirent *de;
	char path[64];
	char target[PATH_MAX];

	while ((de = readdir(dir)) != NULL) {
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

	closedir(dir);
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
	return ksuctl(KSU_IOCTL_GET_ALLOW_LIST, cmd) == 0;
}

bool is_safe_mode() {
	struct ksu_check_safemode_cmd cmd = {};
	ksuctl(KSU_IOCTL_CHECK_SAFEMODE, &cmd);
	return cmd.in_safe_mode;
}

bool is_lkm_mode() {
	auto info = get_info();
	return (info.flags & 0x1) != 0;
}

bool is_manager() {
	auto info = get_info();
	return (info.flags & 0x2) != 0;
}

bool uid_should_umount(int uid) {
	struct ksu_uid_should_umount_cmd cmd = {};
	cmd.uid = uid;
	ksuctl(KSU_IOCTL_UID_SHOULD_UMOUNT, &cmd);
	return cmd.should_umount;
}

bool set_app_profile(const struct app_profile *profile) {
	struct ksu_set_app_profile_cmd cmd = {};
	cmd.profile = *profile;
	return ksuctl(KSU_IOCTL_SET_APP_PROFILE, &cmd) == 0;
}

int get_app_profile(struct app_profile *profile) {
	struct ksu_get_app_profile_cmd cmd = {.profile = *profile};
	int ret = ksuctl(KSU_IOCTL_GET_APP_PROFILE, &cmd);
	*profile = cmd.profile;
	return ret;
}

bool set_su_enabled(bool enabled) {
	struct ksu_enable_su_cmd cmd = {.enable = enabled};
	return ksuctl(KSU_IOCTL_ENABLE_SU, &cmd) == 0;
}

bool is_su_enabled() {
	struct ksu_is_su_enabled_cmd cmd = {};
	return ksuctl(KSU_IOCTL_IS_SU_ENABLED, &cmd) == 0 && cmd.enabled;
}

void get_full_version(char* buff) {
	struct ksu_get_full_version_cmd cmd = {0};
	if (ksuctl(KSU_IOCTL_GET_FULL_VERSION, &cmd) == 0) {
		strncpy(buff, cmd.version_full, KSU_FULL_VERSION_STRING - 1);
		buff[KSU_FULL_VERSION_STRING - 1] = '\0';
	} else {
		buff[0] = '\0';
	}
}

bool is_KPM_enable(void)
{
	struct ksu_enable_kpm_cmd cmd = {};
    return ksuctl(KSU_IOCTL_ENABLE_KPM, &cmd) == 0 && cmd.enabled;
}

void get_hook_type(char* buff)
{
	struct ksu_hook_type_cmd cmd = {0};
	if (ksuctl(KSU_IOCTL_HOOK_TYPE, &cmd) == 0) {
		strncpy(buff, cmd.hook_type, 32 - 1);
		buff[32 - 1] = '\0';
	} else {
		buff[0] = '\0';
	}
}

bool set_dynamic_manager(unsigned int size, const char *hash)
{
	struct ksu_dynamic_manager_cmd cmd = {
			.config = {
					.operation = DYNAMIC_MANAGER_OP_SET,
					.size	  = size
			}
	};
	strlcpy(cmd.config.hash, hash, sizeof(cmd.config.hash));
	return ksuctl(KSU_IOCTL_DYNAMIC_MANAGER, &cmd);
}

bool get_dynamic_manager(struct dynamic_manager_user_config *cfg)
{
	if (!cfg) return false;
	struct ksu_dynamic_manager_cmd cmd = {
			.config = { .operation = DYNAMIC_MANAGER_OP_GET }
	};
	if (!ksuctl(KSU_IOCTL_DYNAMIC_MANAGER, &cmd)) return false;
	memcpy(cfg, &cmd.config, sizeof(*cfg));
	return true;
}

bool clear_dynamic_manager(void)
{
	struct ksu_dynamic_manager_cmd cmd = {
			.config = { .operation = DYNAMIC_MANAGER_OP_CLEAR }
	};
	return ksuctl(KSU_IOCTL_DYNAMIC_MANAGER, &cmd);
}

bool get_managers_list(struct manager_list_info *info)
{
	struct ksu_get_managers_cmd cmd = {0};
	if (!ksuctl(KSU_IOCTL_GET_MANAGERS, &cmd)) return false;
	memcpy(info, &cmd.manager_info, sizeof(*info));
	return true;
}


bool verify_module_signature(const char* input) {
#if defined(__aarch64__) || defined(_M_ARM64) || defined(__arm__) || defined(_M_ARM)
	if (input == NULL) {
		LogDebug("verify_module_signature: input path is null");
		return false;
	}

	int file_fd = zako_sys_file_open(input);
	if (file_fd < 0) {
		LogDebug("verify_module_signature: failed to open file: %s", input);
		return false;
	}

	uint32_t results = zako_file_verify_esig(file_fd, 0);

	if (results != 0) {
		/* If important error occured, verification process should
		   be considered as failed due to unexpected modification
		   potentially happened. */
		if ((results & ZAKO_ESV_IMPORTANT_ERROR) != 0) {
			LogDebug("verify_module_signature: Verification failed! (important error)");
		} else {
			/* This is for manager that doesn't want to do certificate checks */
			LogDebug("verify_module_signature: Verification partially passed");
		}
	} else {
		LogDebug("verify_module_signature: Verification passed!");
		goto exit;
	}

	/* Go through all bit fields */
	for (size_t i = 0; i < sizeof(uint32_t) * 8; i++) {
		if ((results & (1 << i)) == 0) {
			continue;
		}

		/* Convert error bit field index into human readable string */
		const char* message = zako_file_verrcidx2str((uint8_t)i);
		// Error message: message
		if (message != NULL) {
			LogDebug("verify_module_signature: Error bit %zu: %s", i, message);
		} else {
			LogDebug("verify_module_signature: Error bit %zu: Unknown error", i);
		}
	}

	exit:
	close(file_fd);
	LogDebug("verify_module_signature: path=%s, results=0x%x, success=%s",
			 input, results, (results == 0) ? "true" : "false");
	return results == 0;
#else
	LogDebug("verify_module_signature: not supported on non-ARM architecture, path=%s", input ? input : "null");
	return false;
#endif
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