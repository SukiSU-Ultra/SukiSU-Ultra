#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/task_work.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "klog.h"
#include "pkg_userspace.h"
#include "ksu.h"

#define UID_SCANNER_STATE_FILE "/data/adb/ksu/user_uid/.state"
#define UID_SCANNER_REQUEST_FILE "/data/adb/ksu/user_uid/scan_request"

static void ksu_write_file_async(const char *path, const char *buf, int len);

struct ksu_file_write_ctx {
    struct callback_head cb;
    char *path;
    char *buf;
    int len;
};

static void ksu_write_file_cb(struct callback_head *_cb)
{
    struct ksu_file_write_ctx *ctx =
        container_of(_cb, struct ksu_file_write_ctx, cb);
    struct file *fp;
    loff_t off = 0;
    const struct cred *saved = override_creds(ksu_cred);

    fp = filp_open(ctx->path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(fp)) {
        pr_err("ksu_write_file_cb open %s failed: %ld\n", ctx->path,
               PTR_ERR(fp));
        goto out;
    }

    if (kernel_write(fp, ctx->buf, ctx->len, &off) != ctx->len) {
        pr_err("ksu_write_file_cb write %s failed\n", ctx->path);
    }

    filp_close(fp, 0);

out:
    revert_creds(saved);
    kfree(ctx->path);
    kfree(ctx->buf);
    kfree(ctx);
}

static void ksu_write_file_async(const char *path, const char *buf, int len)
{
    struct task_struct *tsk;
    struct ksu_file_write_ctx *ctx;

    if (!path || !buf || len <= 0) {
        return;
    }

    tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
    if (!tsk) {
        pr_err("ksu_write_file_async find init task err\n");
        return;
    }

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) {
        pr_err("ksu_write_file_async alloc ctx err\n");
        goto put_task;
    }

    ctx->path = kstrdup(path, GFP_KERNEL);
    if (!ctx->path) {
        pr_err("ksu_write_file_async dup path err\n");
        goto free_ctx;
    }

    ctx->buf = kmemdup(buf, len, GFP_KERNEL);
    if (!ctx->buf) {
        pr_err("ksu_write_file_async dup buf err\n");
        goto free_path;
    }

    ctx->len = len;
    ctx->cb.func = ksu_write_file_cb;
    task_work_add(tsk, &ctx->cb, TWA_RESUME);
    goto put_task;

free_path:
    kfree(ctx->path);
free_ctx:
    kfree(ctx);
put_task:
    put_task_struct(tsk);
}

void ksu_request_userspace_scan(void)
{
    static const char msg[] = "RESCAN\n";
    ksu_write_file_async(UID_SCANNER_REQUEST_FILE, msg, sizeof(msg) - 1);
    pr_info("requested userspace uid rescan\n");
}

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