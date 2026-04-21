//
// Created by weishu on 2022/12/9.
//

#ifndef KERNELSU_KSU_H
#define KERNELSU_KSU_H

#include <cstdint>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <utility>

#include "uapi/ksu.h"

uint32_t get_version();

bool uid_should_umount(int uid);

bool is_safe_mode();

bool is_lkm_mode();

bool is_late_load_mode();

bool is_manager();

bool is_pr_build();

using p_key_t = char[KSU_MAX_PACKAGE_NAME];

bool set_app_profile(const app_profile *profile);

int get_app_profile(app_profile *profile);

// Su compat
bool set_su_enabled(bool enabled);

bool is_su_enabled();

// Kernel umount
bool set_kernel_umount_enabled(bool enabled);

bool is_kernel_umount_enabled();

bool get_allow_list(struct ksu_new_get_allow_list_cmd *);

bool get_full_version(char* buff);
bool get_hook_type(char *buff);

inline std::pair<int, int> legacy_get_info() {
    int32_t version = -1;
    int32_t flags = 0;
    int32_t result = 0;
    prctl(static_cast<int>(0xDEADBEEF), 2, &version, &flags, &result);
    return {version, flags};
}

#define DEFINE_CACHED_GETTER(name, ioctl, cmd_type, field, size) \
    static char g_##name[size] = {0}; \
    bool get_##name(char *buff) { \
        if (g_##name[0] == '\0') { \
            struct cmd_type cmd = {0}; \
            if (ksuctl(ioctl, &cmd) == 0) { \
                strncpy(g_##name, cmd.field, sizeof(g_##name) - 1); \
                g_##name[sizeof(g_##name) - 1] = '\0'; \
            } \
        } \
        if (g_##name[0] != '\0') { \
            strncpy(buff, g_##name, size - 1); \
            buff[size - 1] = '\0'; \
            return true; \
        } \
        return false; \
    }

#endif //KERNELSU_KSU_H
