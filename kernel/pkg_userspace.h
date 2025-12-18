#ifndef __KSU_H_THRONE_COMM
#define __KSU_H_THRONE_COMM

#include <linux/types.h>

extern bool ksu_uid_scanner_enabled;

typedef bool (*uid_list_callback_t)(uid_t uid, const char *package_name);

void ksu_register_uid_scanner_daemon(pid_t pid);
void ksu_request_userspace_scan(void);
int ksu_update_uid_list(void __user *entries_ptr, u32 count);
bool ksu_uid_exists_in_list(uid_t uid, char *package);
int ksu_iterate_uid_list(uid_list_callback_t callback);

void ksu_pkg_userspace_init(void);
void ksu_pkg_userspace_exit(void);

#endif