//
// Created by weishu on 2022/12/9.
//

#include <sys/prctl.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "prelude.h"
#include "ksu.h"

#if defined(__aarch64__) || defined(_M_ARM64)

// Zako extern declarations
#define ZAKO_ESV_IMPORTANT_ERROR 1 << 31
extern int zako_file_open_rw(const char* path);
extern uint32_t zako_file_verify_esig(int fd, uint32_t flags);
extern const char* zako_esign_verrcidx2str(uint8_t index);

#endif // __aarch64__ || _M_ARM64

#define KERNEL_SU_OPTION 0xDEADBEEF

#define CMD_GRANT_ROOT 0

#define CMD_BECOME_MANAGER 1
#define CMD_GET_VERSION 2
#define CMD_ALLOW_SU 3
#define CMD_DENY_SU 4
#define CMD_GET_SU_LIST 5
#define CMD_GET_DENY_LIST 6
#define CMD_CHECK_SAFEMODE 9

#define CMD_GET_APP_PROFILE 10
#define CMD_SET_APP_PROFILE 11

#define CMD_IS_UID_GRANTED_ROOT 12
#define CMD_IS_UID_SHOULD_UMOUNT 13
#define CMD_IS_SU_ENABLED 14
#define CMD_ENABLE_SU 15

#define CMD_GET_VERSION_FULL 0xC0FFEE1A

#define CMD_ENABLE_KPM 100
#define CMD_HOOK_TYPE 101
#define CMD_GET_SUSFS_FEATURE_STATUS 102
#define CMD_DYNAMIC_SIGN 103
#define CMD_GET_MANAGERS 104

#define DYNAMIC_SIGN_OP_SET 0
#define DYNAMIC_SIGN_OP_GET 1
#define DYNAMIC_SIGN_OP_CLEAR 2

static bool ksuctl(int cmd, void* arg1, void* arg2) {
    int32_t result = 0;
    int32_t rtn = prctl(KERNEL_SU_OPTION, cmd, arg1, arg2, &result);

    return result == KERNEL_SU_OPTION && rtn == -1;
}

bool become_manager(const char* pkg) {
    char param[128];
    uid_t uid = getuid();
    uint32_t userId = uid / 100000;
    if (userId == 0) {
        sprintf(param, "/data/data/%s", pkg);
    } else {
        snprintf(param, sizeof(param), "/data/user/%d/%s", userId, pkg);
    }

    return ksuctl(CMD_BECOME_MANAGER, param, NULL);
}

// cache the result to avoid unnecessary syscall
static bool is_lkm;
int get_version() {
    int32_t version = -1;
    int32_t flags = 0;
    ksuctl(CMD_GET_VERSION, &version, &flags);
    if (!is_lkm && (flags & 0x1)) {
        is_lkm = true;
    }
    return version;
}

void get_full_version(char* buff) {
    ksuctl(CMD_GET_VERSION_FULL, buff, NULL);
}

bool get_allow_list(int *uids, int *size) {
    return ksuctl(CMD_GET_SU_LIST, uids, size);
}

bool is_safe_mode() {
    return ksuctl(CMD_CHECK_SAFEMODE, NULL, NULL);
}

bool is_lkm_mode() {
    // you should call get_version first!
    return is_lkm;
}

bool uid_should_umount(int uid) {
    int should;
    return ksuctl(CMD_IS_UID_SHOULD_UMOUNT, (void*) ((size_t) uid), &should) && should;
}

bool set_app_profile(const struct app_profile* profile) {
    return ksuctl(CMD_SET_APP_PROFILE, (void*) profile, NULL);
}

bool get_app_profile(char* key, struct app_profile* profile) {
    return ksuctl(CMD_GET_APP_PROFILE, profile, NULL);
}

bool set_su_enabled(bool enabled) {
    return ksuctl(CMD_ENABLE_SU, (void*) enabled, NULL);
}

bool is_su_enabled() {
    int enabled = true;
    // if ksuctl failed, we assume su is enabled, and it cannot be disabled.
    ksuctl(CMD_IS_SU_ENABLED, &enabled, NULL);
    return enabled;
}

bool is_KPM_enable() {
    int enabled = false;
    ksuctl(CMD_ENABLE_KPM, &enabled, NULL);
    return enabled;
}

bool get_hook_type(char* hook_type, size_t size) {
    if (hook_type == NULL || size == 0) {
        return false;
    }

    static char cached_hook_type[16] = {0};
    if (cached_hook_type[0] == '\0') {
        if (!ksuctl(CMD_HOOK_TYPE, cached_hook_type, NULL)) {
            strcpy(cached_hook_type, "Unknown");
        }
    }

    strncpy(hook_type, cached_hook_type, size);
    hook_type[size - 1] = '\0';
    return true;
}

bool get_susfs_feature_status(struct susfs_feature_status* status) {
    if (status == NULL) {
        return false;
    }

    return ksuctl(CMD_GET_SUSFS_FEATURE_STATUS, status, NULL);
}

bool set_dynamic_sign(unsigned int size, const char* hash) {
    if (hash == NULL) {
        return false;
    }

    struct dynamic_sign_user_config config;
    config.operation = DYNAMIC_SIGN_OP_SET;
    config.size = size;
    strncpy(config.hash, hash, sizeof(config.hash) - 1);
    config.hash[sizeof(config.hash) - 1] = '\0';

    return ksuctl(CMD_DYNAMIC_SIGN, &config, NULL);
}

bool get_dynamic_sign(struct dynamic_sign_user_config* config) {
    if (config == NULL) {
        return false;
    }

    config->operation = DYNAMIC_SIGN_OP_GET;
    return ksuctl(CMD_DYNAMIC_SIGN, config, NULL);
}

bool clear_dynamic_sign() {
    struct dynamic_sign_user_config config;
    config.operation = DYNAMIC_SIGN_OP_CLEAR;
    return ksuctl(CMD_DYNAMIC_SIGN, &config, NULL);
}

bool get_managers_list(struct manager_list_info* info) {
    if (info == NULL) {
        return false;
    }

    return ksuctl(CMD_GET_MANAGERS, info, NULL);
}

bool verify_module_signature(const char* input) {
#if defined(__aarch64__) || defined(_M_ARM64)
    if (input == NULL) {
        return false;
    }

    int fd = zako_file_open_rw(input);
    uint32_t results = zako_file_verify_esig(fd, 0);

    if (results != 0) {
        if ((results & ZAKO_ESV_IMPORTANT_ERROR) != 0) {
        } else {
        }
    } else {
        goto exit;
    }

    /* Go through all bit fields */
    for (uint8_t i = 0; i < sizeof(uint32_t) * 8; i++) {
        if ((results & (1 << i)) == 0) {
            continue;
        }

        /* Convert error bit field index into human readable string */
        const char* message = zako_esign_verrcidx2str(i);
        // Error message: message
    }

    exit:
    close(fd);
    return results == 0;
#else
    // 非arm64-v8a架构不支持模块签名验证
    return false;
#endif
}