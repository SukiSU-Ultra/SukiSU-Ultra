#ifndef __KSU_H_KSU_CORE
#define __KSU_H_KSU_CORE

#include <linux/init.h>
#include "apk_sign.h"
#include <linux/thread_info.h>

void __init ksu_core_init(void);
void ksu_core_exit(void);

#define KSU_PROC_UMOUNT 50

static inline bool ksu_is_current_proc_umounted(void) {
	return test_ti_thread_flag(&current->thread_info, KSU_PROC_UMOUNT);
}

static inline void ksu_set_current_proc_umounted(void) {
	set_ti_thread_flag(&current->thread_info, KSU_PROC_UMOUNT);
}

#endif
