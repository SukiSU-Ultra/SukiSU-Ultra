#ifndef __KSU_H_APP_PROFILE
#define __KSU_H_APP_PROFILE

// Escalate current process to root with the appropriate profile
int escape_with_root_profile(void);

void escape_to_root_for_init(void);

void escape_to_root_for_cmd_su(uid_t target_uid, pid_t target_pid);

#endif
