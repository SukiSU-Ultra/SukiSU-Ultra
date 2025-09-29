#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include "kernel_compat.h"
#include "manual_su.h"
#include "ksu.h"
#include "allowlist.h"
#include "manager.h"
#include "allowlist.h"

static const char *ksu_su_password = KSU_SU_PASSWORD;
extern void escape_to_root_for_cmd_su(uid_t, pid_t);
#define MAX_PENDING 16
#define REMOVE_DELAY_CALLS 150

struct pending_uid {
    uid_t uid;
    int use_count;
    int remove_calls;
};

static struct pending_uid pending_uids[MAX_PENDING] = {0};
static int pending_cnt = 0;

bool current_verified = false;

int ksu_manual_su_escalate(uid_t target_uid, pid_t target_pid,
                           const char __user *user_password)
{
    if (ksu_is_current_verified())
        goto allowed;

    if (current_uid().val == 0 || is_manager() || ksu_is_allow_uid(current_uid().val))
        goto allowed;

    if (!user_password) {
        pr_warn("manual_su: password required\n");
        return -EACCES;
    }
    char buf[64];
    long copied;

    copied = ksu_strncpy_from_user_retry(buf, user_password, sizeof(buf) - 1);
    if (copied < 0)
        return -EFAULT;

    buf[copied] = '\0';

    if (strcmp(buf, ksu_su_password) != 0) {
        pr_warn("manual_su: wrong password (input=%s, expect=%s)\n", buf, ksu_su_password);
        return -EACCES;
    }

    ksu_mark_current_verified();

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
