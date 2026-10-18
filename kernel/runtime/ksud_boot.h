#ifndef __KSU_H_KSUD_BOOT
#define __KSU_H_KSUD_BOOT

void on_post_fs_data(void);
void on_module_mounted(void);
void on_boot_completed(void);

bool ksu_is_safe_mode(void);

int nuke_ext4_sysfs(const char* mnt);

static bool ksu_module_mounted __read_mostly;
static bool ksu_boot_completed __read_mostly;

#endif
