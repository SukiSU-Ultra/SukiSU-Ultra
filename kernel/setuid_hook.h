#ifndef __KSU_H_KSU_CORE
#define __KSU_H_KSU_CORE

#include <linux/init.h>
#include <linux/types.h>
#include "apk_sign.h"
#include <linux/thread_info.h>

void ksu_setuid_hook_init(void);
void ksu_setuid_hook_exit(void);

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);

#endif
