#ifndef __KSU_MANUAL_SU_H
#define __KSU_MANUAL_SU_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/list.h>

#include "uapi/app_profile.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define mmap_lock mmap_sem
#endif

#define ksu_task_is_dead(t) ((t)->exit_state != 0)
#define KSU_MANUAL_SU_TOKEN_LENGTH 32
#define KSU_MANUAL_SU_TOKEN_EXPIRE_SECS 150
#define KSU_MANUAL_SU_MAX_TOKENS 10
#define KSU_MANUAL_SU_MAX_PENDING_UIDS 16
#define KSU_MANUAL_SU_REMOVE_DELAY_CALLS 150
#define KSU_MANUAL_SU_TOKEN_ENV_NAME "KSU_AUTH_TOKEN"
#define MANUAL_SU_OP_GENERATE_TOKEN 0
#define MANUAL_SU_OP_ESCALATE 1
#define MANUAL_SU_OP_ADD_PENDING 2
#define KSU_MANUAL_SU_VERIFIED_MAGIC 0x4B535530 // "KSU0"

struct ksu_manual_su_request {
    uid_t target_uid;
    pid_t target_pid;
    char token_buffer[KSU_MANUAL_SU_TOKEN_LENGTH + 1];
};

/*
 * Token Management
 */
struct ksu_manual_su_token {
    char token[KSU_MANUAL_SU_TOKEN_LENGTH + 1];
    unsigned long expire_jiffies;
    bool used;
    bool verified;
};

/*
 * Pending UID Entry
 * Tracks UIDs that have been temporarily granted root access
 */
struct ksu_manual_su_pending_uid {
    struct list_head list;
    uid_t uid;
    u32 magic;
    atomic_t use_count;
    atomic_t remove_calls;
    unsigned long add_time;
};

int ksu_handle_manual_su_request(int option, struct ksu_manual_su_request *request);
void ksu_try_escalate_for_uid(uid_t uid);

#endif
