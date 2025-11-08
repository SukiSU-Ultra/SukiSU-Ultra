#ifndef __KSU_H_KSU_KBROBES_HOOK_MANAGER
#define __KSU_H_KSU_KBROBES_HOOK_MANAGER

#include <linux/init.h>
#include <linux/version.h>

void __init ksu_kprobe_hook_init(void);
void ksu_kprobe_hook_exit(void);

#endif