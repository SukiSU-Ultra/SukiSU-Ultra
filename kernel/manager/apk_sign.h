// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>

bool is_manager_apk(char *path);
bool ksu_check_apk_signature(char *path, unsigned int size, const char *hash);
int get_pkg_from_apk_dir_path(char *pkg, const char *path);

#endif
