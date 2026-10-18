#ifndef __KSU_H_KSUD
#define __KSU_H_KSUD

#define KSUD_PATH "/data/adb/ksud"

void ksu_ksud_init();
void ksu_ksud_exit();

static void ksu_stop_input_hook_runtime();

static bool ksu_vfs_read_hook __read_mostly;
static bool ksu_input_hook __read_mostly;

#endif
