// SPDX-License-Identifier: GPL-2.0
/*
 * sukisu_fs_dir.c - readdir implementation with per-uid filtering
 *
 * For a stacking filesystem the readdir callback is invoked once per
 * filldir. We let the underlying directory iterate and inspect every
 * dirent before it reaches userspace. If the dirent's reconstructed
 * full path matches a HIDE rule for the calling uid, we skip it.
 *
 * Filling the dirent buffer is also a side-effect of the callback;
 * we therefore rebuild the absolute path from the dentry chain at
 * iteration time.
 */

#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "klog.h"
#include "sukisu_fs.h"

struct sukisu_fs_dir_ctx {
    struct dir_context ctx;
    char *path_prefix;
    size_t path_prefix_len;
    char *scratch;
    size_t scratch_cap;
};

/* Internal re-export of the inode path-cacher. */
extern int sukisu_fs_open(struct inode *inode, struct file *file);
extern int sukisu_fs_release(struct inode *inode, struct file *file);

static bool sukisu_fs_dir_emit(struct dir_context *ctx,
                                const char *name, int namelen,
                                loff_t ino, unsigned int d_type)
{
    struct sukisu_fs_dir_ctx *udata =
        container_of(ctx, struct sukisu_fs_dir_ctx, ctx);

    if (udata->scratch_cap < udata->path_prefix_len + namelen + 2) {
        size_t need = udata->path_prefix_len + namelen + 2;
        char *new_buf = krealloc(udata->scratch, need, GFP_KERNEL);
        if (!new_buf)
            return true; /* skip rather than abort the iteration */
        udata->scratch = new_buf;
        udata->scratch_cap = need;
    }

    memcpy(udata->scratch, udata->path_prefix, udata->path_prefix_len);
    udata->scratch[udata->path_prefix_len] = '/';
    memcpy(udata->scratch + udata->path_prefix_len + 1, name, namelen);
    udata->scratch[udata->path_prefix_len + 1 + namelen] = '\0';

    if (sukisu_fs_should_hide_path(udata->scratch,
                                    udata->path_prefix_len + 1 + namelen))
        return true; /* keep iterating, just skip this entry */

    return udata->ctx.actor(&udata->ctx, name, namelen, ino, d_type);
}

static int sukisu_fs_iterate(struct file *file, struct dir_context *ctx)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(file->f_inode);
    struct sukisu_fs_dir_ctx udata;
    struct file *under_file;
    int ret;

    if (!info || !info->underlying || !info->cached_path)
        return -EIO;

    under_file = filp_open(info->cached_path, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(under_file))
        return PTR_ERR(under_file);

    udata.ctx.actor       = sukisu_fs_dir_emit;
    udata.ctx.pos         = ctx->pos;
    udata.path_prefix     = info->cached_path;
    udata.path_prefix_len = strlen(info->cached_path);
    udata.scratch         = kmalloc(udata.path_prefix_len + 256, GFP_KERNEL);
    udata.scratch_cap     = udata.path_prefix_len + 256;
    if (!udata.scratch) {
        fput(under_file);
        return -ENOMEM;
    }

    ret = iterate_dir(under_file, &udata.ctx);
    ctx->pos = udata.ctx.pos;

    kfree(udata.scratch);
    fput(under_file);
    return ret;
}

const struct file_operations sukisu_fs_dir_ops = {
    .owner      = THIS_MODULE,
    .open       = sukisu_fs_open,
    .release    = sukisu_fs_release,
    .iterate    = sukisu_fs_iterate,
    .llseek     = default_llseek,
};
