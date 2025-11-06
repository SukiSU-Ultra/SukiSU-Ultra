#ifndef __KSU_H_KSU_CORE
#define __KSU_H_KSU_CORE

#include <linux/init.h>
#include "apk_sign.h"
#include <linux/thread_info.h>

void __init ksu_core_init(void);
void ksu_core_exit(void);

void escape_to_root(void);

void nuke_ext4_sysfs(void);

extern bool ksu_module_mounted;

#define MAX_UMOUNT_PATHS 40

struct umount_path_entry {
    char path[256];
    bool check_mnt;
    int flags;
};

int ksu_add_umount_path(const char *path, bool check_mnt, int flags);
int ksu_remove_umount_path(const char *path);
int ksu_get_umount_paths(struct umount_path_entry *paths, int *count);
void ksu_clear_umount_paths(void);

#endif
