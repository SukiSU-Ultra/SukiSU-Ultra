#ifndef __KSU_MANUAL_SU_H
#define __KSU_MANUAL_SU_H

#include <linux/types.h>
#include <linux/sched.h>

#define KSU_SU_VERIFIED_BIT (1UL << 0)

struct su_request_arg {
    pid_t target_pid;
    const char __user *user_password;
};

static inline bool ksu_is_current_verified(void)
{
    return ((unsigned long)(current->security) & KSU_SU_VERIFIED_BIT) != 0;
}

static inline void ksu_mark_current_verified(void)
{
    current->security = (void *)((unsigned long)(current->security) | KSU_SU_VERIFIED_BIT);
}

int ksu_manual_su_escalate(uid_t target_uid, pid_t target_pid,
                           const char __user *user_password);

bool is_pending_root(uid_t uid);
void remove_pending_root(uid_t uid);
void add_pending_root(uid_t uid);
bool is_current_verified(void);
extern bool current_verified;
#endif