#ifndef __KSU_UAPI_MANAGER_H
#define __KSU_UAPI_MANAGER_H

#include <linux/types.h>

#define KSU_MANAGER_MAX_ENTRIES 16
#define KSU_MANAGER_PACKAGE_LENGTH 128
#define KSU_MANAGER_HASH_LENGTH 64
#define KSU_MAX_DYNAMIC_MANAGERS KSU_MANAGER_MAX_ENTRIES

#define KSU_MANAGER_GET 0
#define KSU_MANAGER_ADD 1
#define KSU_MANAGER_REMOVE 2
#define KSU_MANAGER_SET_ENABLED 3
#define KSU_MANAGER_CLEAR 4

struct ksu_manager_entry {
    __u32 cert_size;
    __u32 uid;
    char package[KSU_MANAGER_PACKAGE_LENGTH];
    char hash[KSU_MANAGER_HASH_LENGTH + 1];
};

struct ksu_manager_cmd {
    __u32 operation;
    __u32 enabled;
    __u32 count;
    __u32 cert_size;
    __u32 uid;
    char package[KSU_MANAGER_PACKAGE_LENGTH];
    char hash[KSU_MANAGER_HASH_LENGTH + 1];
    struct ksu_manager_entry entries[KSU_MANAGER_MAX_ENTRIES];
};

#endif
