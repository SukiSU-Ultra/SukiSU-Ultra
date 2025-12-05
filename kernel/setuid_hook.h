#ifndef __KSU_H_KSU_SETUID_HOOK
#define __KSU_H_KSU_SETUID_HOOK

#include <linux/init.h>
#include <linux/types.h>

void ksu_setuid_hook_init(void);
void ksu_setuid_hook_exit(void);

int ksu_handle_setuid_common(uid_t new_uid, uid_t old_uid, uid_t new_euid,
			     uid_t old_euid);

#endif
