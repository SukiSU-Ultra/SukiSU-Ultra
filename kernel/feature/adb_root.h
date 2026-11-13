#ifndef __KSU_H_ADB_ROOT
#define __KSU_H_ADB_ROOT

#ifdef CONFIG_KSU_FEATURE_ADBROOT
void ksu_adb_root_init(void);
void ksu_adb_root_exit(void);

#ifdef CONFIG_KSU_SUSFS
// Called from the SUSFS fs/exec.c inline hook with a kernel filename and the
// raw envp array pointer from do_execveat_common().
long ksu_adb_root_handle_execveat(const char *filename, void ***envp_user_ptr);
#endif
#else

#define ksu_adb_root_execve_user(...) do { } while (0)
#define ksu_adb_root_execve_kernel(...) do { } while (0)

#ifdef CONFIG_KSU_SUSFS
static inline long ksu_adb_root_handle_execveat(const char *filename, void ***envp_user_ptr)
{
	return 0;
}
#endif
#endif

#endif
