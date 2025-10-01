#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>
#include "ksu.h"
#include "manager.h"

bool ksu_is_manager_apk(char *path);

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

bool ksu_is_multi_manager_apk(char *path, int *signature_index);
void ksu_add_manager(uid_t uid, int signature_index);
void ksu_remove_manager(uid_t uid);
bool ksu_is_any_manager(uid_t uid);
int ksu_get_manager_signature_index(uid_t uid);
int ksu_get_active_managers(struct manager_list_info *info);

int ksu_handle_dynamic_sign(struct dynamic_sign_user_config *config);
void ksu_dynamic_sign_init(void);
void ksu_dynamic_sign_exit(void);
bool ksu_load_dynamic_sign(void);

#endif