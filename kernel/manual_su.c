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

static const char *ksu_su_password = "zakozako";
extern void escape_to_root_for_cmd_su(uid_t, pid_t);

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
    if (strncpy_from_user(buf, user_password, sizeof(buf) - 1) < 0)
        return -EFAULT;
    buf[sizeof(buf) - 1] = '\0';

    if (strcmp(buf, ksu_su_password) != 0) {
        pr_warn("manual_su: wrong password\n");
        return -EACCES;
    }

    ksu_mark_current_verified();

allowed:
    escape_to_root_for_cmd_su(target_uid, target_pid);
    return 0;
}