// SPDX-License-Identifier: GPL-2.0
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>

#include "app_context.h"
#include "extension.h"
#include "klog.h" // IWYU pragma: keep
#include "uapi/extension.h"

struct app_context {
    struct ksu_app_context_entry entry;
    struct list_head list;
};

static LIST_HEAD(app_context_list);
static DEFINE_MUTEX(app_context_lock);
static u32 app_context_count = 0;

static struct app_context *find_or_create_context_locked(uid_t uid)
{
    struct app_context *ctx;

    list_for_each_entry(ctx, &app_context_list, list) {
        if (ctx->entry.uid == uid)
            return ctx;
    }

    if (app_context_count >= KSU_APP_CONTEXT_MAX_ENTRIES)
        return ERR_PTR(-ENOSPC);

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return ERR_PTR(-ENOMEM);

    ctx->entry.uid = uid;
    ctx->entry.last_update_ns = ktime_get_ns();
    list_add(&ctx->list, &app_context_list);
    app_context_count++;

    return ctx;
}

static struct app_context *find_context_locked(uid_t uid)
{
    struct app_context *ctx;

    list_for_each_entry(ctx, &app_context_list, list) {
        if (ctx->entry.uid == uid)
            return ctx;
    }
    return NULL;
}

int ksu_app_context_query(uid_t uid, struct ksu_app_context_entry *out_ctx)
{
    struct app_context *ctx;
    int ret = 0;

    if (!out_ctx)
        return -EINVAL;

    mutex_lock(&app_context_lock);
    ctx = find_context_locked(uid);
    if (!ctx) {
        ret = -ENOENT;
        goto out;
    }

    *out_ctx = ctx->entry;

out:
    mutex_unlock(&app_context_lock);
    return ret;
}

int ksu_app_context_set_foreground(uid_t uid, bool foreground)
{
    struct app_context *ctx;
    int ret = 0;

    mutex_lock(&app_context_lock);
    ctx = find_or_create_context_locked(uid);
    if (IS_ERR(ctx)) {
        ret = PTR_ERR(ctx);
        goto out;
    }

    ctx->entry.foreground = foreground;
    ctx->entry.last_update_ns = ktime_get_ns();

out:
    mutex_unlock(&app_context_lock);
    return ret;
}

int ksu_app_context_set_profile(uid_t uid, u32 profile_id)
{
    struct app_context *ctx;
    int ret = 0;

    mutex_lock(&app_context_lock);
    ctx = find_or_create_context_locked(uid);
    if (IS_ERR(ctx)) {
        ret = PTR_ERR(ctx);
        goto out;
    }

    ctx->entry.profile_id = profile_id;
    ctx->entry.last_update_ns = ktime_get_ns();

out:
    mutex_unlock(&app_context_lock);
    return ret;
}

int ksu_app_context_set_tag(uid_t uid, u64 tag_mask)
{
    struct app_context *ctx;
    int ret = 0;

    mutex_lock(&app_context_lock);
    ctx = find_or_create_context_locked(uid);
    if (IS_ERR(ctx)) {
        ret = PTR_ERR(ctx);
        goto out;
    }

    ctx->entry.tags |= tag_mask;
    ctx->entry.last_update_ns = ktime_get_ns();

out:
    mutex_unlock(&app_context_lock);
    return ret;
}

int ksu_app_context_clear_tag(uid_t uid, u64 tag_mask)
{
    struct app_context *ctx;
    int ret = 0;

    mutex_lock(&app_context_lock);
    ctx = find_context_locked(uid);
    if (!ctx) {
        ret = -ENOENT;
        goto out;
    }

    ctx->entry.tags &= ~tag_mask;
    ctx->entry.last_update_ns = ktime_get_ns();

out:
    mutex_unlock(&app_context_lock);
    return ret;
}

int ksu_app_context_list(struct ksu_app_context_entry *buf, u32 max_count,
                         u32 *out_count)
{
    struct app_context *ctx;
    u32 count = 0;
    int ret = 0;

    if (!buf || !out_count || !max_count ||
        max_count > KSU_APP_CONTEXT_MAX_ENTRIES)
        return -EINVAL;

    mutex_lock(&app_context_lock);

    if (app_context_count > max_count) {
        *out_count = app_context_count;
        ret = -ENOSPC;
        goto out;
    }

    list_for_each_entry(ctx, &app_context_list, list) {
        buf[count] = ctx->entry;
        count++;
    }

    *out_count = count;
out:
    mutex_unlock(&app_context_lock);
    return ret;
}

int ksu_app_context_remove(uid_t uid)
{
    struct app_context *ctx;
    int ret = 0;

    mutex_lock(&app_context_lock);
    ctx = find_context_locked(uid);
    if (!ctx) {
        ret = -ENOENT;
        goto out;
    }

    list_del(&ctx->list);
    kfree(ctx);
    app_context_count--;

out:
    mutex_unlock(&app_context_lock);
    return ret;
}

static int handle_query(void __user *raw)
{
    struct ksu_app_context_query_cmd cmd;
    struct ksu_app_context_entry entry;
    int ret;

    if (copy_from_user(&cmd, raw, sizeof(cmd)))
        return -EFAULT;

    if (cmd.reserved)
        return -EINVAL;

    ret = ksu_app_context_query(cmd.uid, &entry);
    if (ret)
        return ret;

    cmd.entry = entry;

    if (copy_to_user(raw, &cmd, sizeof(cmd)))
        return -EFAULT;

    return 0;
}

static int handle_set_fg(void __user *raw)
{
    struct ksu_app_context_set_fg_cmd cmd;

    if (copy_from_user(&cmd, raw, sizeof(cmd)))
        return -EFAULT;

    if (cmd.foreground > 1)
        return -EINVAL;

    return ksu_app_context_set_foreground(cmd.uid, cmd.foreground != 0);
}

static int handle_set_profile(void __user *raw)
{
    struct ksu_app_context_set_profile_cmd cmd;

    if (copy_from_user(&cmd, raw, sizeof(cmd)))
        return -EFAULT;

    return ksu_app_context_set_profile(cmd.uid, cmd.profile_id);
}

static int handle_set_tag(void __user *raw)
{
    struct ksu_app_context_tag_cmd cmd;

    if (copy_from_user(&cmd, raw, sizeof(cmd)))
        return -EFAULT;

    if (cmd.reserved)
        return -EINVAL;

    return ksu_app_context_set_tag(cmd.uid, cmd.tag_mask);
}

static int handle_clear_tag(void __user *raw)
{
    struct ksu_app_context_tag_cmd cmd;

    if (copy_from_user(&cmd, raw, sizeof(cmd)))
        return -EFAULT;

    if (cmd.reserved)
        return -EINVAL;

    return ksu_app_context_clear_tag(cmd.uid, cmd.tag_mask);
}

static int handle_list(void __user *raw)
{
    struct ksu_app_context_list_cmd cmd;
    struct ksu_app_context_entry *kern_buf;
    struct ksu_app_context_entry __user *user_entries;
    u32 count;
    int ret;

    if (copy_from_user(&cmd, raw, sizeof(cmd)))
        return -EFAULT;

    if (!cmd.buffer || cmd.max_count == 0 ||
        cmd.max_count > KSU_APP_CONTEXT_MAX_ENTRIES)
        return -EINVAL;

    kern_buf = kcalloc(cmd.max_count, sizeof(*kern_buf), GFP_KERNEL);
    if (!kern_buf)
        return -ENOMEM;

    ret = ksu_app_context_list(kern_buf, cmd.max_count, &count);
    if (ret)
        goto out_free;

    user_entries = u64_to_user_ptr(cmd.buffer);
    if (copy_to_user(user_entries, kern_buf, count * sizeof(*kern_buf))) {
        ret = -EFAULT;
        goto out_free;
    }

    cmd.out_count = count;
    if (copy_to_user(raw, &cmd, sizeof(cmd))) {
        ret = -EFAULT;
        goto out_free;
    }

out_free:
    kfree(kern_buf);
    return ret;
}

static int handle_remove(void __user *raw)
{
    struct ksu_app_context_remove_cmd cmd;

    if (copy_from_user(&cmd, raw, sizeof(cmd)))
        return -EFAULT;

    if (cmd.reserved)
        return -EINVAL;

    return ksu_app_context_remove(cmd.uid);
}

int ksu_extension_app_context_io(u32 id, void __user *raw)
{
    struct ksu_app_context_cmd cmd;

    if (!raw)
        return -EINVAL;

    if (copy_from_user(&cmd, raw, sizeof(cmd.op) + sizeof(cmd.reserved)))
        return -EFAULT;

    if (cmd.reserved)
        return -EINVAL;

    switch (cmd.op) {
    case KSU_APP_CONTEXT_OP_QUERY:
        return handle_query(raw + offsetof(struct ksu_app_context_cmd, payload.query));
    case KSU_APP_CONTEXT_OP_SET_FG:
        return handle_set_fg(raw + offsetof(struct ksu_app_context_cmd, payload.set_fg));
    case KSU_APP_CONTEXT_OP_SET_PROFILE:
        return handle_set_profile(raw + offsetof(struct ksu_app_context_cmd, payload.set_profile));
    case KSU_APP_CONTEXT_OP_SET_TAG:
        return handle_set_tag(raw + offsetof(struct ksu_app_context_cmd, payload.tag));
    case KSU_APP_CONTEXT_OP_CLEAR_TAG:
        return handle_clear_tag(raw + offsetof(struct ksu_app_context_cmd, payload.tag));
    case KSU_APP_CONTEXT_OP_LIST:
        return handle_list(raw + offsetof(struct ksu_app_context_cmd, payload.list));
    case KSU_APP_CONTEXT_OP_REMOVE:
        return handle_remove(raw + offsetof(struct ksu_app_context_cmd, payload.remove));
    case KSU_APP_CONTEXT_OP_CLEAR_ALL:
        return ksu_app_context_clear_all(id);
    default:
        return -EINVAL;
    }
}

void ksu_app_context_init(void)
{
    pr_info("app_context: subsystem initialized\n");
}

int ksu_app_context_clear_all(u32 id)
{
    struct app_context *ctx, *tmp;

    mutex_lock(&app_context_lock);
    list_for_each_entry_safe(ctx, tmp, &app_context_list, list) {
        list_del(&ctx->list);
        kfree(ctx);
    }
    app_context_count = 0;
    mutex_unlock(&app_context_lock);

    return 0;
}

void ksu_app_context_exit(void)
{
    ksu_app_context_clear_all(KSU_EXTENSION_APP_CONTEXT);
    pr_info("app_context: subsystem cleaned up\n");
}
