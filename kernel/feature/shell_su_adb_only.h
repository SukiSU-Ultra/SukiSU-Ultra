#ifndef __KSU_H_SHELL_SU_ADB_ONLY
#define __KSU_H_SHELL_SU_ADB_ONLY

// Extra check for current running as shell, it never grants root by itself:
// shell still has to be allowed by the allowlist. Always true when the feature
// is disabled; otherwise current must descend from adbd or a ksu domain process.
static inline bool ksu_shell_su_allowed_for_current(void);

void ksu_shell_su_adb_only_init(void);

void ksu_shell_su_adb_only_exit(void);

#endif
