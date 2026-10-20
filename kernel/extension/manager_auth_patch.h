// SPDX-License-Identifier: GPL-2.0
/*
 * Manager-Auth: 第三方管理器签名降级支持
 */

#ifndef __KSU_H_MANAGER_AUTH_PATCH
#define __KSU_H_MANAGER_AUTH_PATCH

#include <linux/types.h>

int install_manager_auth_patch(void);
void remove_manager_auth_patch(void);

#endif /* __KSU_H_MANAGER_AUTH_PATCH */
