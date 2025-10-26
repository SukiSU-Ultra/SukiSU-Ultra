#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/binfmts.h>
#include "kernel_compat.h"
#include "manual_su.h"
#include "ksu.h"
#include "allowlist.h"
#include "manager.h"

extern void escape_to_root_for_cmd_su(uid_t, pid_t);
#define MAX_PENDING 16
#define REMOVE_DELAY_CALLS 150
#define MAX_TOKENS 10

struct pending_uid {
    uid_t uid;
    int use_count;
    int remove_calls;
};

static struct pending_uid pending_uids[MAX_PENDING] = {0};
static int pending_cnt = 0;
static struct ksu_token_entry auth_tokens[MAX_TOKENS] = {0};
static int token_count = 0;
static DEFINE_SPINLOCK(token_lock);

bool current_verified = false;

static char* get_token_from_envp(void)
{
    struct mm_struct *mm;
    char *envp_start, *envp_end;
    char *env_ptr, *token = NULL;
    unsigned long env_len;
    char *env_copy = NULL;
    
    if (!current->mm)
        return NULL;
        
    mm = current->mm;
    
    down_read(&mm->mmap_lock);
    
    envp_start = (char *)mm->env_start;
    envp_end = (char *)mm->env_end;
    env_len = envp_end - envp_start;
    
    if (env_len <= 0 || env_len > PAGE_SIZE * 32) {
        up_read(&mm->mmap_lock);
        return NULL;
    }
    
    env_copy = kmalloc(env_len + 1, GFP_KERNEL);
    if (!env_copy) {
        up_read(&mm->mmap_lock);
        return NULL;
    }
    
    if (copy_from_user(env_copy, envp_start, env_len)) {
        kfree(env_copy);
        up_read(&mm->mmap_lock);
        return NULL;
    }
    
    up_read(&mm->mmap_lock);
    
    env_copy[env_len] = '\0';
    env_ptr = env_copy;
    
    while (env_ptr < env_copy + env_len) {
        if (strncmp(env_ptr, KSU_TOKEN_ENV_NAME "=", strlen(KSU_TOKEN_ENV_NAME) + 1) == 0) {
            char *token_start = env_ptr + strlen(KSU_TOKEN_ENV_NAME) + 1;
            char *token_end = strchr(token_start, '\0');
            
            if (token_end && (token_end - token_start) == KSU_TOKEN_LENGTH) {
                token = kmalloc(KSU_TOKEN_LENGTH + 1, GFP_KERNEL);
                if (token) {
                    memcpy(token, token_start, KSU_TOKEN_LENGTH);
                    token[KSU_TOKEN_LENGTH] = '\0';
                    pr_info("manual_su: found auth token in environment\n");
                }
            }
            break;
        }
        
        env_ptr += strlen(env_ptr) + 1;
    }
    
    kfree(env_copy);
    return token;
}

char* ksu_generate_auth_token(void)
{
    static char token_buffer[KSU_TOKEN_LENGTH + 1];
    unsigned long flags;
    int i;
    
    ksu_cleanup_expired_tokens();
    
    spin_lock_irqsave(&token_lock, flags);
    
    if (token_count >= MAX_TOKENS) {
        for (i = 0; i < MAX_TOKENS - 1; i++) {
            auth_tokens[i] = auth_tokens[i + 1];
        }
        token_count = MAX_TOKENS - 1;
    }
    
    for (i = 0; i < KSU_TOKEN_LENGTH; i++) {
        u8 rand_byte;
        get_random_bytes(&rand_byte, 1);
        int char_type = rand_byte % 3;
        if (char_type == 0) {
            token_buffer[i] = 'A' + (rand_byte % 26);
        } else if (char_type == 1) {
            token_buffer[i] = 'a' + (rand_byte % 26);
        } else {
            token_buffer[i] = '0' + (rand_byte % 10);
        }
    }
    token_buffer[KSU_TOKEN_LENGTH] = '\0';
    
    strncpy(auth_tokens[token_count].token, token_buffer, KSU_TOKEN_LENGTH + 1);
    auth_tokens[token_count].expire_time = jiffies + KSU_TOKEN_EXPIRE_TIME * HZ;
    auth_tokens[token_count].used = false;
    token_count++;
    
    spin_unlock_irqrestore(&token_lock, flags);
    
    pr_info("manual_su: generated new auth token (expires in %d seconds)\n", KSU_TOKEN_EXPIRE_TIME);
    return token_buffer;
}

bool ksu_verify_auth_token(const char *token)
{
    unsigned long flags;
    bool valid = false;
    int i;
    
    if (!token || strlen(token) != KSU_TOKEN_LENGTH) {
        return false;
    }
    
    spin_lock_irqsave(&token_lock, flags);
    
    for (i = 0; i < token_count; i++) {
        if (!auth_tokens[i].used && 
            time_before(jiffies, auth_tokens[i].expire_time) &&
            strcmp(auth_tokens[i].token, token) == 0) {
            
            auth_tokens[i].used = true;
            valid = true;
            pr_info("manual_su: auth token verified successfully\n");
            break;
        }
    }
    
    spin_unlock_irqrestore(&token_lock, flags);
    
    if (!valid) {
        pr_warn("manual_su: invalid or expired auth token\n");
    }
    
    return valid;
}

void ksu_cleanup_expired_tokens(void)
{
    unsigned long flags;
    int i, j;
    
    spin_lock_irqsave(&token_lock, flags);
    
    for (i = 0; i < token_count; ) {
        if (time_after(jiffies, auth_tokens[i].expire_time) || auth_tokens[i].used) {
            for (j = i; j < token_count - 1; j++) {
                auth_tokens[j] = auth_tokens[j + 1];
            }
            token_count--;
            pr_debug("manual_su: cleaned up expired/used token\n");
        } else {
            i++;
        }
    }
    
    spin_unlock_irqrestore(&token_lock, flags);
}

int ksu_manual_su_escalate(uid_t target_uid, pid_t target_pid)
{
    if (current_uid().val == 0 || is_manager() || ksu_is_allow_uid(current_uid().val))
        goto allowed;

    char *env_token = get_token_from_envp();
    if (!env_token) {
        pr_warn("manual_su: no auth token found in environment\n");
        return -EACCES;
    }
    
    bool token_valid = ksu_verify_auth_token(env_token);
    kfree(env_token);
    
    if (!token_valid) {
        pr_warn("manual_su: token verification failed\n");
        return -EACCES;
    }

allowed:
    current_verified = true;
    escape_to_root_for_cmd_su(target_uid, target_pid);
    return 0;
}

bool is_current_verified(void)
{
    return current_verified;
}

bool is_pending_root(uid_t uid)
{
    for (int i = 0; i < pending_cnt; i++) {
        if (pending_uids[i].uid == uid) {
            pending_uids[i].use_count++;
            pending_uids[i].remove_calls++;
            return true;
        }
    }
    return false;
}

void remove_pending_root(uid_t uid)
{
    for (int i = 0; i < pending_cnt; i++) {
        if (pending_uids[i].uid == uid) {
            pending_uids[i].remove_calls++;

            if (pending_uids[i].remove_calls >= REMOVE_DELAY_CALLS) {
                pending_uids[i] = pending_uids[--pending_cnt];
                pr_info("pending_root: removed UID %d after %d calls\n", uid, REMOVE_DELAY_CALLS);
                ksu_temp_revoke_root_once(uid);
            } else {
                pr_info("pending_root: UID %d remove_call=%d (<%d)\n",
                        uid, pending_uids[i].remove_calls, REMOVE_DELAY_CALLS);
            }
            return;
        }
    }
}

void add_pending_root(uid_t uid)
{
    if (pending_cnt >= MAX_PENDING) {
        pr_warn("pending_root: cache full\n");
        return;
    }
    for (int i = 0; i < pending_cnt; i++) {
        if (pending_uids[i].uid == uid) {
            pending_uids[i].use_count = 0;
            pending_uids[i].remove_calls = 0;
            return;
        }
    }
    pending_uids[pending_cnt++] = (struct pending_uid){uid, 0};
    ksu_temp_grant_root_once(uid);
    pr_info("pending_root: cached UID %d\n", uid);
}
