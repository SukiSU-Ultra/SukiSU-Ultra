#ifndef __KSU_H_DYNAMIC_SIGN
#define __KSU_H_DYNAMIC_SIGN

#include <linux/types.h>
#include "ksu.h"

#define DYNAMIC_SIGN_FILE_MAGIC 0x7f445347 // 'DSG', u32
#define DYNAMIC_SIGN_FILE_VERSION 1 // u32
#define KERNEL_SU_DYNAMIC_SIGN "/data/adb/ksu/.dynamic_sign"

struct dynamic_sign_config {
    unsigned int size;
    char hash[65];
    int is_set;
};

struct manager_info {
    uid_t uid;
    int signature_index;
    bool is_active;
};

// Dynamic sign operations
int ksu_handle_dynamic_sign(struct dynamic_sign_user_config *config);
void ksu_dynamic_sign_init(void);
void ksu_dynamic_sign_exit(void);
bool ksu_load_dynamic_sign(void);
bool ksu_is_dynamic_sign_enabled(void);

// Multi-manager operations
void ksu_add_manager(uid_t uid, int signature_index);
void ksu_remove_manager(uid_t uid);
bool ksu_is_any_manager(uid_t uid);
int ksu_get_manager_signature_index(uid_t uid);
int ksu_get_active_managers(struct manager_list_info *info);

// Multi-manager APK verification
bool ksu_is_multi_manager_apk(char *path, int *signature_index);

// Get dynamic sign configuration for signature verification
bool ksu_get_dynamic_sign_config(unsigned int *size, const char **hash);

#endif