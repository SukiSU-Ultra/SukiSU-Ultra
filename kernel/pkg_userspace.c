#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/task_work.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/signal.h>
#include <linux/cred.h>
#include <linux/mm.h>
#include <linux/kstrtox.h>

#include "klog.h"
#include "pkg_userspace.h"
#include "ksu.h"

#define UID_SCANNER_STATE_FILE "/data/adb/ksu/user_uid/.state"
#define PID_FILE_PATH "/data/adb/ksu/user_uid/daemon.pid"

static void do_save_throne_state(struct callback_head *_cb)
{
    struct file *fp;
    char state_char = ksu_uid_scanner_enabled ? '1' : '0';
    loff_t off = 0;
    const struct cred *saved = override_creds(ksu_cred);

    fp = filp_open(UID_SCANNER_STATE_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(fp)) {
        pr_err("save_throne_state create file failed: %ld\n", PTR_ERR(fp));
        goto revert;
    }

    if (kernel_write(fp, &state_char, sizeof(state_char), &off) !=
        sizeof(state_char)) {
        pr_err("save_throne_state write failed\n");
        goto close_file;
    }

    pr_info("throne state saved: %s\n",
            ksu_uid_scanner_enabled ? "enabled" : "disabled");

close_file:
    filp_close(fp, 0);
revert:
    revert_creds(saved);
    kfree(_cb);
}

static void do_load_throne_state(struct callback_head *_cb)
{
    struct file *fp;
    char state_char;
    loff_t off = 0;
    ssize_t ret;
    const struct cred *saved = override_creds(ksu_cred);

    fp = filp_open(UID_SCANNER_STATE_FILE, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_info("throne state file not found, using default: disabled\n");
        ksu_uid_scanner_enabled = false;
        goto revert;
    }

    ret = kernel_read(fp, &state_char, sizeof(state_char), &off);
    if (ret != sizeof(state_char)) {
        pr_err("load_throne_state read err: %zd\n", ret);
        ksu_uid_scanner_enabled = false;
        goto close_file;
    }

    ksu_uid_scanner_enabled = (state_char == '1');
    pr_info("throne state loaded: %s\n",
            ksu_uid_scanner_enabled ? "enabled" : "disabled");

close_file:
    filp_close(fp, 0);
revert:
    revert_creds(saved);
    kfree(_cb);
}

bool ksu_throne_comm_load_state(void)
{
    struct task_struct *tsk;
    struct callback_head *cb;

    tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
    if (!tsk) {
        pr_err("load_throne_state find init task err\n");
        return false;
    }

    cb = kzalloc(sizeof(*cb), GFP_KERNEL);
    if (!cb) {
        pr_err("load_throne_state alloc cb err\n");
        goto put_task;
    }
    cb->func = do_load_throne_state;
    task_work_add(tsk, cb, TWA_RESUME);

put_task:
    put_task_struct(tsk);
    return true;
}

void ksu_throne_comm_save_state(void)
{
    struct task_struct *tsk;
    struct callback_head *cb;

    tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
    if (!tsk) {
        pr_err("save_throne_state find init task err\n");
        return;
    }

    cb = kzalloc(sizeof(*cb), GFP_KERNEL);
    if (!cb) {
        pr_err("save_throne_state alloc cb err\n");
        goto put_task;
    }
    cb->func = do_save_throne_state;
    task_work_add(tsk, cb, TWA_RESUME);

put_task:
    put_task_struct(tsk);
}

void ksu_request_userspace_scan(void)
{
    struct file *fp;
    char pid_buf[16];
    loff_t off = 0;
    ssize_t nr;
    pid_t daemon_pid = 0;
    struct pid *pid_struct;
    struct task_struct *target;
    const struct cred *saved = override_creds(ksu_cred);

    // Read PID from file
    fp = filp_open(PID_FILE_PATH, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_warn("uid_list: failed to open PID file: %ld\n",
                PTR_ERR(fp));
        revert_creds(saved);
        return;
    }

    nr = kernel_read(fp, pid_buf, sizeof(pid_buf) - 1, &off);
    filp_close(fp, 0);
    revert_creds(saved);

    if (nr <= 0) {
        pr_warn("uid_list: failed to read PID file\n");
        return;
    }

    pid_buf[nr] = '\0';
    if (kstrtoint(pid_buf, 10, &daemon_pid) != 0 || daemon_pid <= 0) {
        pr_warn("uid_list: invalid PID in file: %s\n",
                pid_buf);
        return;
    }

    pid_struct = find_get_pid(daemon_pid);
    if (!pid_struct) {
        pr_warn("uid_list: PID %d not found\n", daemon_pid);
        return;
    }

    target = pid_task(pid_struct, PIDTYPE_PID);
    if (target) {
        send_sig(SIGUSR1, target, 0);
        pr_info("uid_list: sent SIGUSR1 to daemon (pid=%d)\n",
                daemon_pid);
    } else {
        pr_warn("uid_list: task for PID %d not found\n",
                daemon_pid);
    }

    put_pid(pid_struct);
}
