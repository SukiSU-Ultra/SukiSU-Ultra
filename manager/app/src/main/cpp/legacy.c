//
// Created by shirkneko on 2025/11/3.
//
// Legacy Compatible
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
#define CMD_DYNAMIC_MANAGER 103
#define CMD_GET_MANAGERS 104
#define CMD_ENABLE_UID_SCANNER 105

static bool ksuctl(int cmd, void* arg1, void* arg2) {
    int32_t result = 0;
    int32_t rtn = prctl(KERNEL_SU_OPTION, cmd, arg1, arg2, &result);
    return result == KERNEL_SU_OPTION && rtn == -1;
}

struct ksu_version_info legacy_get_info()
{
    int32_t version = 0;
    int32_t flags = 0;
    ksuctl(CMD_GET_VERSION, &version, &flags);
    return (struct ksu_version_info){version, flags};
}

bool legacy_get_allow_list(int *uids, int *size) {
    return ksuctl(CMD_GET_SU_LIST, uids, size);
}

bool legacy_is_safe_mode() {
    return ksuctl(CMD_CHECK_SAFEMODE, NULL, NULL);
}

bool legacy_uid_should_umount(int uid) {
    int should;
    return ksuctl(CMD_IS_UID_SHOULD_UMOUNT, (void*) ((size_t) uid), &should) && should;
}

bool legacy_set_app_profile(const struct app_profile* profile) {
    return ksuctl(CMD_SET_APP_PROFILE, (void*) profile, NULL);
}

bool legacy_get_app_profile(char* key, struct app_profile* profile) {
    return ksuctl(CMD_GET_APP_PROFILE, profile, NULL);
}

bool legacy_set_su_enabled(bool enabled) {
    return ksuctl(CMD_ENABLE_SU, (void*) enabled, NULL);
}

bool legacy_is_su_enabled() {
    int enabled = true;
    // if ksuctl failed, we assume su is enabled, and it cannot be disabled.
    ksuctl(CMD_IS_SU_ENABLED, &enabled, NULL);
    return enabled;
}

bool legacy_is_KPM_enable() {
    int enabled = false;
    ksuctl(CMD_ENABLE_KPM, &enabled, NULL);
    return enabled;
}

bool legacy_get_hook_type(char* hook_type, size_t size) {
    if (hook_type == NULL || size == 0) {
        return false;
    }

    static char cached_hook_type[16] = {0};
    if (cached_hook_type[0] == '\0') {
        if (!ksuctl(CMD_HOOK_TYPE, cached_hook_type, NULL)) {
            strcpy(cached_hook_type, "Unknown");
        }
    }

    strncpy(hook_type, cached_hook_type, size - 1);
    hook_type[size - 1] = '\0';
    return true;
}

void legacy_get_full_version(char* buff) {
    ksuctl(CMD_GET_VERSION_FULL, buff, NULL);
}

bool legacy_set_dynamic_manager(unsigned int size, const char* hash) {
    if (hash == NULL) {
        return false;
    }
    struct dynamic_manager_user_config config;
    config.operation = DYNAMIC_MANAGER_OP_SET;
    config.size = size;
    strncpy(config.hash, hash, sizeof(config.hash) - 1);
    config.hash[sizeof(config.hash) - 1] = '\0';
    return ksuctl(CMD_DYNAMIC_MANAGER, &config, NULL);
}

bool legacy_get_dynamic_manager(struct dynamic_manager_user_config* config) {
    if (config == NULL) {
        return false;
    }
    config->operation = DYNAMIC_MANAGER_OP_GET;
    return ksuctl(CMD_DYNAMIC_MANAGER, config, NULL);
}

bool legacy_clear_dynamic_manager() {
    struct dynamic_manager_user_config config;
    config.operation = DYNAMIC_MANAGER_OP_CLEAR;
    return ksuctl(CMD_DYNAMIC_MANAGER, &config, NULL);
}

bool legacy_get_managers_list(struct manager_list_info* info) {
    if (info == NULL) {
        return false;
    }
    return ksuctl(CMD_GET_MANAGERS, info, NULL);
}

bool legacy_is_uid_scanner_enabled() {
    bool status = false;
    ksuctl(CMD_ENABLE_UID_SCANNER, (void*)0, &status);
    return status;
}

bool legacy_set_uid_scanner_enabled(bool enabled) {
    return ksuctl(CMD_ENABLE_UID_SCANNER, (void*)1, (void*)enabled);
}

bool legacy_clear_uid_scanner_environment() {
    return ksuctl(CMD_ENABLE_UID_SCANNER, (void*)2, NULL);
}