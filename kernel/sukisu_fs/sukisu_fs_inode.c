// SPDX-License-Identifier: GPL-2.0
/*
 * sukisu_fs_inode.c - inode operations for sukisu-fs
 *
 * Every operation is forwarded to the underlying inode. Visibility
 * filtering happens in lookup() and getattr() (so a process cannot
 * see or stat an entry it cannot list).
 *
 * For v1 we keep a minimal implementation focused on the operations
 * that the readdir / file layers actually call. The remaining
 * operations (mkdir, create, unlink, rename, setattr, ...) live in
 * this file and simply forward to the underlying fs.
 */

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "klog.h"
#include "sukisu_fs.h"

struct sukisu_fs_inode_info {
    struct inode *underlying;
    /* A full path string is rebuilt from dentry walks in readdir,
     * but for individual lookups we cache the absolute path for
     * faster rule matching. */
    char *cached_path;
};

static inline struct sukisu_fs_inode_info *SUKISU_I(struct inode *inode)
{
    return inode->i_private;
}

static int sukisu_fs_revalidate_path_impl(struct dentry *dentry,
                                             char **out_path)
{
    char *buf, *p;
    size_t len = 0;
    struct dentry *d;

    /* Walk the dentry tree up to the root, building the absolute
     * path in reverse. This is a slow path - we only use it from
     * lookup/getattr which are not on the hot path. */

    for (d = dentry; !IS_ROOT(d); d = d->d_parent)
        len += 1 + strlen(d->d_name.name);

    buf = kmalloc(len + 1, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    p = buf + len;
    *p = '\0';
    for (d = dentry; !IS_ROOT(d); d = d->d_parent) {
        size_t n = strlen(d->d_name.name);
        p -= n;
        memcpy(p, d->d_name.name, n);
        *(--p) = '/';
    }

    *out_path = buf;
    return 0;
}

int sukisu_fs_revalidate_path_for(struct dentry *dentry)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(d_inode(dentry));
    char *path = NULL;
    int ret;

    if (!info)
        return -EINVAL;

    ret = sukisu_fs_revalidate_path_impl(dentry, &path);
    if (ret)
        return ret;

    kfree(info->cached_path);
    info->cached_path = path;
    return 0;
}

struct inode *sukisu_fs_get_inode(struct super_block *sb, struct inode *under)
{
    struct sukisu_fs_inode_info *info;
    struct inode *inode;

    info = kzalloc(sizeof(*info), GFP_KERNEL);
    if (!info)
        return ERR_PTR(-ENOMEM);

    info->underlying = under;
    info->cached_path = NULL;

    inode = new_inode(sb);
    if (!inode) {
        kfree(info);
        return ERR_PTR(-ENOMEM);
    }

    inode->i_ino     = under->i_ino;
    inode->i_mode    = under->i_mode;
    inode->i_uid     = under->i_uid;
    inode->i_gid     = under->i_gid;
    inode->i_size    = under->i_size;
    inode->i_atime   = under->i_atime;
    inode->i_mtime   = under->i_mtime;
    inode->i_ctime   = under->i_ctime;
    inode->i_nlink   = under->i_nlink;
    inode->i_blocks  = under->i_blocks;
    inode->i_blkbits = under->i_blkbits;
    inode->i_private = info;
    inode->i_op      = &sukisu_fs_inode_ops;
    inode->i_fop     = &sukisu_fs_file_ops;
    inode->i_mapping = under->i_mapping;

    return inode;
}

/* lookup: search the underlying dentry for `name`. If found, return
 * a wrapped inode; if the resolved path matches a HIDE rule for the
 * caller, pretend it does not exist. */
static struct dentry *sukisu_fs_lookup(struct inode *dir,
                                        struct dentry *dentry,
                                        unsigned int flags)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(dir);
    struct inode *under = info->underlying;
    struct dentry *under_dir;
    struct dentry *under_child;
    struct inode *wrapped;
    int ret;

    if (!under)
        return ERR_PTR(-EIO);

    under_dir = d_find_any_alias(under);
    if (!under_dir)
        return ERR_PTR(-ENOENT);

    inode_lock_nested(under_dir->d_inode, I_MUTEX_PARENT);
    under_child = lookup_one_len(dentry->d_name.name, under_dir,
                                 dentry->d_name.len);
    inode_unlock(under_dir->d_inode);
    dput(under_dir);

    if (IS_ERR(under_child))
        return under_child;

    if (d_is_negative(under_child)) {
        dput(under_child);
        return ERR_PTR(-ENOENT);
    }

    /* Build full path and check visibility. */
    {
        char *full_path;
        size_t base_len;

        /* Quick path check: compose `dir/c_name` for the rule lookup.
         * The dir's cached_path is the absolute path of the parent
         * directory, so we just need to append. */
        if (!SUKISU_I(dir)->cached_path) {
            ret = sukisu_fs_revalidate_path_for(dentry->d_parent);
            if (ret) {
                dput(under_child);
                return ERR_PTR(ret);
            }
        }
        base_len = strlen(SUKISU_I(dir)->cached_path);
        full_path = kmalloc(base_len + 1 + dentry->d_name.len + 1, GFP_KERNEL);
        if (!full_path) {
            dput(under_child);
            return ERR_PTR(-ENOMEM);
        }
        memcpy(full_path, SUKISU_I(dir)->cached_path, base_len);
        full_path[base_len] = '/';
        memcpy(full_path + base_len + 1, dentry->d_name.name, dentry->d_name.len);
        full_path[base_len + 1 + dentry->d_name.len] = '\0';

        if (sukisu_fs_should_hide_path(full_path,
                                       base_len + 1 + dentry->d_name.len)) {
            kfree(full_path);
            dput(under_child);
            return ERR_PTR(-ENOENT);
        }
        kfree(full_path);
    }

    wrapped = sukisu_fs_get_inode(dentry->d_sb, d_inode(under_child));
    dput(under_child);
    if (IS_ERR(wrapped))
        return ERR_CAST(wrapped);

    d_add(dentry, wrapped);
    return NULL;
}

static int sukisu_fs_getattr(sukisu_idmap_t idmap,
                              const struct path *path,
                              struct kstat *stat,
                              u32 request_mask,
                              unsigned int query_flags)
{
    struct inode *inode = d_inode(path->dentry);
    struct sukisu_fs_inode_info *info = SUKISU_I(inode);

    if (!info || !info->underlying)
        return -EIO;

    if (info->cached_path &&
        sukisu_fs_should_hide_path(info->cached_path,
                                   strlen(info->cached_path)))
        return -ENOENT;

    return vfs_getattr(idmap, &info->underlying->i_sb->s_root, stat);
}

static int sukisu_fs_setattr(sukisu_idmap_t idmap,
                              struct user_namespace *mnt_userns,
                              struct dentry *dentry, struct iattr *attr)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(d_inode(dentry));
    struct iattr underlying_attr = *attr;
    struct dentry *under_d;
    int ret;

    if (!info || !info->underlying)
        return -EIO;

    /* Re-resolve underlying dentry. */
    {
        char *path_buf;
        size_t base_len = info->cached_path ? strlen(info->cached_path) : 0;

        if (base_len == 0) {
            ret = sukisu_fs_revalidate_path_for(dentry);
            if (ret)
                return ret;
            base_len = info->cached_path ? strlen(info->cached_path) : 0;
            if (base_len == 0)
                return -EINVAL;
        }
        path_buf = kmalloc(base_len + 2, GFP_KERNEL);
        if (!path_buf)
            return -ENOMEM;
        memcpy(path_buf, info->cached_path, base_len + 1);
        under_d = lookup_one_len(path_buf, dentry->d_parent, base_len);
        kfree(path_buf);
        if (IS_ERR(under_d))
            return PTR_ERR(under_d);
    }

    ret = vfs_setattr(under_d, &underlying_attr);
    dput(under_d);
    return ret;
}

static int sukisu_fs_create(struct user_namespace *mnt_userns,
                             struct inode *dir, struct dentry *dentry,
                             umode_t mode, bool excl)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(dir);
    struct dentry *under_dir;
    struct dentry *under_child;
    struct inode *under_inode;
    int ret;

    if (!info || !info->underlying)
        return -EIO;

    under_dir = d_find_any_alias(info->underlying);
    if (!under_dir)
        return -ENOENT;

    inode_lock_nested(under_dir->d_inode, I_MUTEX_PARENT);
    under_child = lookup_one_len(dentry->d_name.name, under_dir,
                                 dentry->d_name.len);
    if (IS_ERR(under_child)) {
        inode_unlock(under_dir->d_inode);
        dput(under_dir);
        return PTR_ERR(under_child);
    }
    under_inode = under_dir->d_inode;

    ret = vfs_create(under_inode, under_child, mode, excl);
    if (!ret) {
        struct inode *wrapped = sukisu_fs_get_inode(dir->i_sb, d_inode(under_child));
        if (!IS_ERR(wrapped))
            d_add(dentry, wrapped);
        else
            ret = PTR_ERR(wrapped);
    }
    inode_unlock(under_dir->d_inode);
    dput(under_dir);
    dput(under_child);
    return ret;
}

static int sukisu_fs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(dir);
    struct dentry *under_dir;
    struct dentry *under_child;
    int ret;

    if (!info || !info->underlying)
        return -EIO;

    under_dir = d_find_any_alias(info->underlying);
    if (!under_dir)
        return -ENOENT;

    inode_lock_nested(under_dir->d_inode, I_MUTEX_PARENT);
    under_child = lookup_one_len(dentry->d_name.name, under_dir,
                                 dentry->d_name.len);
    if (IS_ERR(under_child)) {
        inode_unlock(under_dir->d_inode);
        dput(under_dir);
        return PTR_ERR(under_child);
    }

    ret = vfs_unlink(under_dir->d_inode, under_child);
    inode_unlock(under_dir->d_inode);
    dput(under_child);
    dput(under_dir);
    return ret;
}

static int sukisu_fs_mkdir(struct user_namespace *mnt_userns,
                            struct inode *dir, struct dentry *dentry,
                            umode_t mode)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(dir);
    struct dentry *under_dir;
    struct dentry *under_child;
    struct inode *under_inode;
    int ret;

    if (!info || !info->underlying)
        return -EIO;

    under_dir = d_find_any_alias(info->underlying);
    if (!under_dir)
        return -ENOENT;

    inode_lock_nested(under_dir->d_inode, I_MUTEX_PARENT);
    under_child = lookup_one_len(dentry->d_name.name, under_dir,
                                 dentry->d_name.len);
    if (IS_ERR(under_child)) {
        inode_unlock(under_dir->d_inode);
        dput(under_dir);
        return PTR_ERR(under_child);
    }
    under_inode = under_dir->d_inode;

    ret = vfs_mkdir(under_inode, under_child, mode);
    if (!ret) {
        struct inode *wrapped = sukisu_fs_get_inode(dir->i_sb, d_inode(under_child));
        if (!IS_ERR(wrapped))
            d_add(dentry, wrapped);
        else
            ret = PTR_ERR(wrapped);
    }
    inode_unlock(under_dir->d_inode);
    dput(under_dir);
    dput(under_child);
    return ret;
}

static int sukisu_fs_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(dir);
    struct dentry *under_dir;
    struct dentry *under_child;
    int ret;

    if (!info || !info->underlying)
        return -EIO;

    under_dir = d_find_any_alias(info->underlying);
    if (!under_dir)
        return -ENOENT;

    inode_lock_nested(under_dir->d_inode, I_MUTEX_PARENT);
    under_child = lookup_one_len(dentry->d_name.name, under_dir,
                                 dentry->d_name.len);
    if (IS_ERR(under_child)) {
        inode_unlock(under_dir->d_inode);
        dput(under_dir);
        return PTR_ERR(under_child);
    }

    ret = vfs_rmdir(under_dir->d_inode, under_child);
    inode_unlock(under_dir->d_inode);
    dput(under_child);
    dput(under_dir);
    return ret;
}

static int sukisu_fs_rename(struct user_namespace *mnt_userns,
                             struct inode *old_dir, struct dentry *old_dentry,
                             struct inode *new_dir, struct dentry *new_dentry,
                             unsigned int flags)
{
    struct sukisu_fs_inode_info *old_info = SUKISU_I(old_dir);
    struct sukisu_fs_inode_info *new_info = SUKISU_I(new_dir);
    struct dentry *under_old_dir, *under_new_dir;
    struct dentry *under_old_child, *under_new_child;
    int ret;

    if (!old_info || !old_info->underlying || !new_info || !new_info->underlying)
        return -EIO;

    under_old_dir = d_find_any_alias(old_info->underlying);
    under_new_dir = d_find_any_alias(new_info->underlying);
    if (!under_old_dir || !under_new_dir) {
        if (under_old_dir) dput(under_old_dir);
        if (under_new_dir) dput(under_new_dir);
        return -ENOENT;
    }

    /* Lock order: the two underlying directory inodes in lexical
     * pointer order to avoid deadlocks, as recommended by VFS docs. */
    if (under_old_dir->d_inode != under_new_dir->d_inode) {
        if (under_old_dir->d_inode < under_new_dir->d_inode) {
            inode_lock_nested(under_old_dir->d_inode, I_MUTEX_PARENT);
            inode_lock_nested(under_new_dir->d_inode, I_MUTEX_PARENT2);
        } else {
            inode_lock_nested(under_new_dir->d_inode, I_MUTEX_PARENT);
            inode_lock_nested(under_old_dir->d_inode, I_MUTEX_PARENT2);
        }
    } else {
        inode_lock_nested(under_old_dir->d_inode, I_MUTEX_PARENT);
    }

    under_old_child = lookup_one_len(old_dentry->d_name.name, under_old_dir,
                                     old_dentry->d_name.len);
    if (IS_ERR(under_old_child)) {
        ret = PTR_ERR(under_old_child);
        goto out_unlock;
    }
    under_new_child = lookup_one_len(new_dentry->d_name.name, under_new_dir,
                                     new_dentry->d_name.len);
    if (IS_ERR(under_new_child)) {
        ret = PTR_ERR(under_new_child);
        dput(under_old_child);
        goto out_unlock;
    }

    ret = vfs_rename(under_old_dir->d_inode, under_old_child,
                     under_new_dir->d_inode, under_new_child, NULL, flags);

    dput(under_old_child);
    dput(under_new_child);

out_unlock:
    if (under_old_dir->d_inode != under_new_dir->d_inode) {
        if (under_old_dir->d_inode < under_new_dir->d_inode) {
            inode_unlock(under_new_dir->d_inode);
            inode_unlock(under_old_dir->d_inode);
        } else {
            inode_unlock(under_old_dir->d_inode);
            inode_unlock(under_new_dir->d_inode);
        }
    } else {
        inode_unlock(under_old_dir->d_inode);
    }
    dput(under_old_dir);
    dput(under_new_dir);
    return ret;
}

const struct inode_operations sukisu_fs_inode_ops = {
    .lookup    = sukisu_fs_lookup,
    .getattr   = sukisu_fs_getattr,
    .setattr   = sukisu_fs_setattr,
    .create    = sukisu_fs_create,
    .unlink    = sukisu_fs_unlink,
    .mkdir     = sukisu_fs_mkdir,
    .rmdir     = sukisu_fs_rmdir,
    .rename    = sukisu_fs_rename,
};
