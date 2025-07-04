#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>
#include "ksu.h"

bool ksu_is_manager_apk(char *path);

struct dynamic_sign_config {
    unsigned int size;
    char hash[65];
    int is_set;
};

int ksu_set_dynamic_sign(unsigned int size, const char *hash);
int ksu_get_dynamic_sign(unsigned int *size, char *hash, int hash_size);
int ksu_load_dynamic_sign_config(void);
int ksu_save_dynamic_sign_config(void);
int ksu_clear_dynamic_sign_config(void);

#define DYNAMIC_SIGN_CONFIG_PATH "/data/adb/ksu/.dynamic_sign"

#endif