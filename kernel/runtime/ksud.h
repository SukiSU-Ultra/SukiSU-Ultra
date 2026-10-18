#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#define KSUD_PATH "/data/adb/ksud"

void ksu_ksud_init();
void ksu_ksud_exit();

void on_post_fs_data(void);
void on_module_mounted(void);
void on_boot_completed(void);

bool ksu_is_safe_mode(void);

int nuke_ext4_sysfs(const char* mnt);

static noinline void ksu_install_rc_hook(struct file *file);

extern u32 ksu_file_sid;

static bool ksu_module_mounted __read_mostly;
static bool ksu_boot_completed __read_mostly;
static bool ksu_vfs_read_hook __read_mostly;
static bool ksu_input_hook __read_mostly;

#endif
