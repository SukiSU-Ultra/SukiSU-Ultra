//
// Created by weishu on 2022/12/9.
//

#ifndef KERNELSU_KSU_H
#define KERNELSU_KSU_H

#include "prelude.h"
#include <linux/capability.h>
#include <sys/types.h>

bool become_manager(const char *);

void get_full_version(char* buff);

int get_version();

bool get_allow_list(int *uids, int *size);

bool uid_should_umount(int uid);

bool is_safe_mode();

bool is_lkm_mode();

#define KSU_APP_PROFILE_VER 2
#define KSU_MAX_PACKAGE_NAME 256
// NGROUPS_MAX for Linux is 65535 generally, but we only supports 32 groups.
#define KSU_MAX_GROUPS 32
#define KSU_SELINUX_DOMAIN 64

#define DYNAMIC_MANAGER_OP_SET 0
#define DYNAMIC_MANAGER_OP_GET 1
#define DYNAMIC_MANAGER_OP_CLEAR 2

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

bool get_app_profile(char* key, struct app_profile* profile);

bool set_su_enabled(bool enabled);

bool is_su_enabled();

bool is_KPM_enable();

bool get_hook_type(char* hook_type, size_t size);


bool set_dynamic_manager(unsigned int size, const char* hash);

bool get_dynamic_manager(struct dynamic_manager_user_config* config);

bool clear_dynamic_manager();

bool get_managers_list(struct manager_list_info* info);

bool verify_module_signature(const char* input);

bool is_uid_scanner_enabled();

bool set_uid_scanner_enabled(bool enabled);

bool clear_uid_scanner_environment();

#endif //KERNELSU_KSU_H