// SPDX-License-Identifier: GPL-2.0
/*
 * sukisu_fs.c - filesystem registration, mount, superblock
 *
 * sukisu-fs is implemented as a stacking filesystem on top of an
 * existing mount. We register a new file_system_type ("sukisu") and
 * drive the lifecycle through fill_super / kill_sb.
 *
 * A mounted sukisu-fs exposes a directory tree that is the same as
 * the underlying tree, except that readdir()/lookup()/getattr() are
 * filtered through sukisu_fs_should_hide_path().
 *
 * This file owns the superblock; the inode/file/dir operations live
 * in sukisu_fs_inode.c, sukisu_fs_file.c and sukisu_fs_dir.c.
 */

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/init.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#include "klog.h"
#include "sukisu_fs.h"

enum sukisu_fs_param {
    Opt_source,
    Opt_err,
};

static const struct fs_parameter_spec sukisu_fs_fs_parameters[] = {
    [Opt_source] = { .name = "source", .type = fs_parameter_is_string },
    {},
};

struct sukisu_fs_fs_context {
    /* Path of the underlying directory we layer over. */
    char *source;
};

/* Per-superblock state. */
struct sukisu_fs_sb_info {
    /* Reference to the underlying mount, kept while sb is alive. */
    struct path underlying;
    /* Path name of the underlying directory, for diagnostics. */
    char *source;
};

static inline struct sukisu_fs_sb_info *SUKISU_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

static int sukisu_fs_show_options(struct seq_file *m, struct dentry *root)
{
    struct sukisu_fs_sb_info *sbi = SUKISU_SB(root->d_sb);

    if (sbi && sbi->source)
        seq_printf(m, ",source=%s", sbi->source);

    return 0;
}

static int sukisu_fs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct sukisu_fs_sb_info *sbi = SUKISU_SB(dentry->d_sb);

    if (!sbi)
        return -EINVAL;

    return vfs_statfs(&sbi->underlying, buf);
}

static void sukisu_fs_free_inode(struct inode *inode)
{
    /* For a stacking fs each inode wraps an underlying inode; if we
     * ever store per-inode state, free it here. For v1, nothing. */
    kfree(inode->i_private);
    inode->i_private = NULL;
}

static void sukisu_fs_put_super(struct super_block *sb)
{
    struct sukisu_fs_sb_info *sbi = SUKISU_SB(sb);

    if (!sbi)
        return;

    path_put(&sbi->underlying);
    kfree(sbi->source);
    kfree(sbi);
    sb->s_fs_info = NULL;
}

static const struct super_operations sukisu_fs_super_ops = {
    .statfs   = sukisu_fs_statfs,
    .put_super = sukisu_fs_put_super,
    .free_inode = sukisu_fs_free_inode,
    .show_options = sukisu_fs_show_options,
};

static int sukisu_fs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct sukisu_fs_fs_context *ctx = fc->fs_private;
    struct sukisu_fs_sb_info *sbi;
    struct inode *root_inode;
    struct path underlying;
    int ret;

    if (!ctx || !ctx->source) {
        pr_err("sukisu_fs: missing source path\n");
        return -EINVAL;
    }

    ret = kern_path(ctx->source, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &underlying);
    if (ret) {
        pr_err("sukisu_fs: cannot resolve source %s: %d\n", ctx->source, ret);
        return ret;
    }

    sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
    if (!sbi) {
        path_put(&underlying);
        return -ENOMEM;
    }
    sbi->underlying = underlying;
    sbi->source = kstrdup(ctx->source, GFP_KERNEL);
    if (!sbi->source) {
        kfree(sbi);
        path_put(&underlying);
        return -ENOMEM;
    }

    sb->s_fs_info = sbi;
    sb->s_magic = SUKISU_FS_MAGIC;
    sb->s_op = &sukisu_fs_super_ops;
    /* We do not have our own backing inode; always use the
     * underlying inode for storage operations. */
    /* sukisu-fs is read-write capable as long as the underlying fs
     * is. We forward writes to it, so advertise the corresponding
     * capability flags. */
    sb->s_flags |= SB_POSIXACL;

    root_inode = sukisu_fs_get_inode(sb, d_inode(underlying.dentry));
    if (IS_ERR(root_inode)) {
        ret = PTR_ERR(root_inode);
        path_put(&underlying);
        kfree(sbi->source);
        kfree(sbi);
        sb->s_fs_info = NULL;
        return ret;
    }

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root) {
        ret = -ENOMEM;
        path_put(&underlying);
        kfree(sbi->source);
        kfree(sbi);
        sb->s_fs_info = NULL;
        return ret;
    }

    return 0;
}

static int sukisu_fs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    struct sukisu_fs_fs_context *ctx = fc->fs_private;
    struct fs_parse_result result;

    switch (fs_parse(fc, sukisu_fs_fs_parameters, param, &result)) {
    case Opt_source:
        kfree(ctx->source);
        ctx->source = kstrdup(param->string, GFP_KERNEL);
        if (!ctx->source)
            return -ENOMEM;
        param->string = NULL;
        return 0;
    default:
        return -EINVAL;
    }
}

static int sukisu_fs_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, sukisu_fs_fill_super);
}

static void sukisu_fs_free_fc(struct fs_context *fc)
{
    struct sukisu_fs_fs_context *ctx = fc->fs_private;

    if (ctx) {
        kfree(ctx->source);
        kfree(ctx);
    }
    fc->fs_private = NULL;
}

static const struct fs_context_operations sukisu_fs_context_ops = {
    .free        = sukisu_fs_free_fc,
    .parse_param = sukisu_fs_parse_param,
    .get_tree    = sukisu_fs_get_tree,
};

static int sukisu_fs_init_fs_context(struct fs_context *fc)
{
    struct sukisu_fs_fs_context *ctx;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    fc->fs_private = ctx;
    fc->ops = &sukisu_fs_context_ops;
    return 0;
}

static void sukisu_fs_kill_sb(struct super_block *sb)
{
    /* put_super (sukisu_fs_put_super) is invoked by generic_shutdown_super
     * after we return, which is what releases sbi and path_put()s the
     * underlying mount. */
    kill_anon_super(sb);
}

static struct file_system_type sukisu_fs_type = {
    .owner            = THIS_MODULE,
    .name             = "sukisu",
    .init_fs_context  = sukisu_fs_init_fs_context,
    .kill_sb          = sukisu_fs_kill_sb,
    .fs_flags         = FS_USERNS_MOUNT | FS_RENAME_DOES_D_MOVE,
};

static struct vfsmount *sukisu_fs_active_mnt;

bool sukisu_fs_is_active(void)
{
    return !!sukisu_fs_active_mnt;
}

struct super_block *sukisu_fs_get_sb(void)
{
    return sukisu_fs_active_mnt ? sukisu_fs_active_mnt->mnt.sb : NULL;
}

int sukisu_fs_do_mount(const char *source, const char *target)
{
    struct path target_path;
    int ret;

    if (!source || !target)
        return -EINVAL;

    ret = kern_path(target, LOOKUP_FOLLOW, &target_path);
    if (ret)
        return ret;
    path_put(&target_path);

    /* Ensure mountpoint exists. The mount step itself is performed
     * by userspace via mount(2); this helper exists so future
     * in-kernel code paths can trigger a mount. */

    return 0;
}

void __init sukisu_fs_init(void)
{
    int ret = register_filesystem(&sukisu_fs_type);
    if (ret) {
        pr_err("sukisu_fs: register_filesystem failed: %d\n", ret);
        return;
    }
    pr_info("sukisu_fs: registered (no backing image, stacking fs)\n");
}

void __exit sukisu_fs_exit(void)
{
    sukisu_fs_rule_clear();
    unregister_filesystem(&sukisu_fs_type);
    if (sukisu_fs_active_mnt) {
        mntput(sukisu_fs_active_mnt);
        sukisu_fs_active_mnt = NULL;
    }
    pr_info("sukisu_fs: unregistered\n");
}
