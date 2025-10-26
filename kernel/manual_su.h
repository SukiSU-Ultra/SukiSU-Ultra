#ifndef __KSU_MANUAL_SU_H
#define __KSU_MANUAL_SU_H

#include <linux/types.h>
#include <linux/sched.h>

#define KSU_SU_VERIFIED_BIT (1UL << 0)
#define KSU_TOKEN_LENGTH 32
#define KSU_TOKEN_ENV_NAME "KSU_AUTH_TOKEN"
#define KSU_TOKEN_EXPIRE_TIME 30

struct ksu_token_entry {
    char token[KSU_TOKEN_LENGTH + 1];
    unsigned long expire_time;
    bool used;
};

int ksu_manual_su_escalate(uid_t target_uid, pid_t target_pid);

bool is_pending_root(uid_t uid);
void remove_pending_root(uid_t uid);
void add_pending_root(uid_t uid);
bool is_current_verified(void);
char* ksu_generate_auth_token(void);
bool ksu_verify_auth_token(const char *token);
void ksu_cleanup_expired_tokens(void);
extern bool current_verified;
#endif