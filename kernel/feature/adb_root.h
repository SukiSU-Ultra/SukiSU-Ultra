#ifndef __KSU_H_ADB_ROOT
#define __KSU_H_ADB_ROOT

#ifdef CONFIG_KSU_FEATURE_ADBROOT
void ksu_adb_root_init(void);
void ksu_adb_root_exit(void);
#else
void ksu_adb_root_init(void) { } // no-op
void ksu_adb_root_exit(void) { } // no-op
#endif

#endif
