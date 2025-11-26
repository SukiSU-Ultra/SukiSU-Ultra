#ifndef __KSU_MANUAL_SU_H
#define __KSU_MANUAL_SU_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#define mmap_lock mmap_sem
#endif

#define ksu_task_is_dead(t) ((t)->exit_state != 0)

#define MAX_PENDING 16
#define REMOVE_DELAY_CALLS 150
#define MAX_TOKENS 10

#define KSU_SU_VERIFIED_BIT (1UL << 0)
#define KSU_TOKEN_LENGTH 32
#define KSU_TOKEN_ENV_NAME "KSU_AUTH_TOKEN"
#define KSU_TOKEN_EXPIRE_TIME 150

#define MANUAL_SU_OP_GENERATE_TOKEN 0
#define MANUAL_SU_OP_ESCALATE 1
#define MANUAL_SU_OP_ADD_PENDING 2

struct pending_uid {
	uid_t uid;
	int use_count;
	int remove_calls;
};

struct manual_su_request {
	uid_t target_uid;
	pid_t target_pid;
	char token_buffer[KSU_TOKEN_LENGTH + 1];
};

struct ksu_token_entry {
	char token[KSU_TOKEN_LENGTH + 1];
	unsigned long expire_time;
	bool used;
};

int ksu_handle_manual_su_request(int option, struct manual_su_request *request);
bool is_pending_root(uid_t uid);
void remove_pending_root(uid_t uid);
void ksu_try_escalate_for_uid(uid_t uid);
#endif
