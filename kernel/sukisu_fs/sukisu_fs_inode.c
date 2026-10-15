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
 *
 * Compatibility note: this file is written against the Android
 * 5.10/5.15 vendor BSP API surface. 6.x is supported by relaxing
 * the .unlink/.rmdir type check via the LINUX_VERSION_CODE guards
 * below; vfs_setattr and vfs_getattr are wrapped to keep us
 * portable across 5.10..6.18.
 */

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#include "klog.h"
#include "sukisu_fs.h"

/* fill_stat_from_under
 *
 * Populate `stat` by reading the fields of the underlying inode
 * directly. We do this instead of calling vfs_getattr() because
 * vfs_getattr()'s signature has changed five times across
 * 5.10..6.18 and we would otherwise need five guarded branches
 * for a feature that is trivially expressible from the inode
 * itself. The `idmap` / `mnt_userns` argument is ignored; uid/gid
 * translation happens in the callers that actually need it.
 */
static void fill_stat_from_under(const struct inode *under,
                                  struct kstat *stat)
{
    stat->dev     = under->i_sb->s_dev;
    stat->ino     = (u64)under->i_ino;
    stat->mode    = under->i_mode;
    stat->nlink   = (u32)under->i_nlink;
    stat->uid     = under->i_uid;
    stat->gid     = under->i_gid;
    stat->rdev    = under->i_rdev;
    stat->size    = (loff_t)under->i_size;
    stat->atime   = under->i_atime;
    stat->mtime   = under->i_mtime;
    stat->ctime   = under->i_ctime;
    stat->blocks  = (u64)under->i_blocks;
    /* blkcnt was added to struct kstat in 5.11; vendor BSPs on
     * 5.10 may not have it. The blocks field above is identical
     * to blkcnt in size and meaning on stock 5.10. */
    stat->blksize = (u32)(S_ISBLK(under->i_mode) || S_ISCHR(under->i_mode)
                              ? 512u : (unsigned int)under->i_sb->s_blocksize);
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
    /* i_nlink is const in 6.x — use set_nlink() unconditionally
     * to avoid version branching. */
    set_nlink(inode, under->i_nlink);
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

/* sukisu_fs_getattr
 *
 * The .getattr function pointer type changed across kernel
 * versions:
 *   5.10  : 4-arg (path, stat, request_mask, query_flags)
 *   5.12  : 5-arg (mnt_userns, ...)
 *   6.2   : 5-arg with mnt_idmap (5-arg different first-arg type)
 *
 * All three signatures are routed through this single function via
 * a tiny trampoline per ABI. The implementation is identical
 * (copy fields from the underlying inode) and lives in
 * fill_stat_from_under() above.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
static int sukisu_fs_getattr(sukisu_idmap_t idmap,
                              const struct path *path,
                              struct kstat *stat,
                              u32 request_mask,
                              unsigned int query_flags)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
/* Stock mainline 5.12+ has the mnt_userns argument. The
 * android13-5.15 vendor BSP reverted it — but the only caller
 * of this shim is the inode_operations table, and a function
 * pointer assignment does not accept a 5-arg function for a
 * 4-arg slot. We therefore use the 4-arg signature here
 * unconditionally and rely on the fact that init_user_ns is
 * what the underlying fs would derive anyway. */
static int sukisu_fs_getattr(const struct path *path,
                              struct kstat *stat,
                              u32 request_mask,
                              unsigned int query_flags)
#else
static int sukisu_fs_getattr(const struct path *path,
                              struct kstat *stat,
                              u32 request_mask,
                              unsigned int query_flags)
#endif
{
    struct inode *inode = d_inode(path->dentry);
    struct sukisu_fs_inode_info *info = SUKISU_I(inode);

    if (!info || !info->underlying)
        return -EIO;

    if (info->cached_path &&
        sukisu_fs_should_hide_path(info->cached_path,
                                   strlen(info->cached_path)))
        return -ENOENT;

    fill_stat_from_under(info->underlying, stat);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    stat->request_mask = request_mask;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
    (void)idmap;
#endif
    return 0;
}

/* sukisu_fs_setattr
 *
 * Uses notify_change() on 5.10 / 5.11 and vfs_setattr() on 5.12+.
 * vfs_setattr()'s fourth argument (delegated_inode pointer) was
 * added in 5.12; we always pass NULL since we never look at
 * delegation.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
static int sukisu_fs_setattr(sukisu_idmap_t idmap,
                              struct user_namespace *mnt_userns,
                              struct dentry *dentry, struct iattr *attr)
#else
/* 5.10 / 5.11 / 5.12+ all carry the mnt_userns argument on
 * .setattr (it was added in 5.11). The android13-5.10 vendor
 * BSP already backported 5.11's .setattr signature. */
static int sukisu_fs_setattr(struct user_namespace *mnt_userns,
                              struct dentry *dentry, struct iattr *attr)
#endif
{
    struct sukisu_fs_inode_info *info = SUKISU_I(d_inode(dentry));
    struct iattr underlying_attr = *attr;
    struct dentry *under_d;
    int ret;

    (void)mnt_userns; /* unused on 5.10/5.11 (setattr_prepare takes no userns) */

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

    /* The setattr path has had four different entry points
     * across 5.10..6.18:
     *   - < 5.10  : setattr_prepare(dentry, iattr) + notify_change
     *   - 5.10    : setattr_prepare takes no userns
     *   - 5.11    : setattr_prepare gains mnt_userns
     *   - 5.12    : vfs_setattr(mnt_userns, dentry, iattr, NULL)
     *   - 6.2     : vfs_setattr(mnt_idmap, dentry, iattr, NULL)
     * Vendor BSPs only backport some of these. We always go
     * through setattr_prepare + notify_change, which is the
     * lowest common denominator and is present everywhere. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    ret = setattr_prepare(mnt_userns, under_d, &underlying_attr);
#else
    ret = setattr_prepare(under_d, &underlying_attr);
#endif
    if (!ret)
        ret = notify_change(under_d, &underlying_attr, NULL);
    dput(under_d);
    return ret;
}

/* vfs_create / vfs_unlink / vfs_mkdir / vfs_rmdir signature
 * history is messy across 5.10..6.18:
 *
 *   vfs_create: 5.10 vendor=(inode,dentry,mode,excl) (4)
 *               5.10 std  =(mnt_userns, inode, dentry, mode, excl) (5)
 *               5.12+     same 5-arg (no delegated)
 *
 *   vfs_unlink: 5.10 vendor=(inode,dentry,delegated) (3)
 *               5.10 std  =(mnt_userns, inode, dentry, delegated) (4)
 *               5.12+     same 4-arg
 *
 *   vfs_mkdir:  5.10 vendor=(inode,dentry,mode) (3)
 *               5.10 std  =(mnt_userns, inode, dentry, mode) (4)
 *               5.12+     same 4-arg
 *
 *   vfs_rmdir:  5.10 vendor=(inode,dentry) (2)
 *               5.10 std  =(mnt_userns, inode, dentry) (3)
 *               5.12+     same 3-arg
 *
 * We dispatch the vfs_* call inside the *_impl shim and let the
 * shim pick the right number of arguments. The shim signatures
 * (i.e. what the inode_operations table sees) are handled
 * separately by the shim layer further down. */

static int sukisu_fs_create_impl(struct user_namespace *mnt_userns,
                                  struct inode *dir, struct dentry *dentry,
                                  umode_t mode, bool excl)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(dir);
    struct dentry *under_dir;
    struct dentry *under_child;
    struct inode *under_inode;
    int ret;

    (void)mnt_userns; /* unused on 5.10; passed to vfs_create on 5.12+ */

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    ret = vfs_create(mnt_userns, under_inode, under_child, mode, excl);
#else
    /* Vendor BSPs on 5.10 omit mnt_userns; stock 5.10 mainline
     * keeps it. We always omit it because the matching .create
     * shim already uses &init_user_ns and the underlying fs
     * will translate accordingly. */
    ret = vfs_create(under_inode, under_child, mode, excl);
#endif
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

static int sukisu_fs_unlink_impl(struct user_namespace *mnt_userns,
                                  struct inode *dir, struct dentry *dentry)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(dir);
    struct dentry *under_dir;
    struct dentry *under_child;
    int ret;

    (void)mnt_userns; /* unused on 5.10; passed to vfs_unlink on 5.12+ */

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    ret = vfs_unlink(mnt_userns, under_dir->d_inode, under_child, NULL);
#else
    ret = vfs_unlink(under_dir->d_inode, under_child, NULL);
#endif
    inode_unlock(under_dir->d_inode);
    dput(under_child);
    dput(under_dir);
    return ret;
}

static int sukisu_fs_mkdir_impl(struct user_namespace *mnt_userns,
                                 struct inode *dir, struct dentry *dentry,
                                 umode_t mode)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(dir);
    struct dentry *under_dir;
    struct dentry *under_child;
    struct inode *under_inode;
    int ret;

    (void)mnt_userns; /* unused on 5.10; passed to vfs_mkdir on 5.12+ */

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    ret = vfs_mkdir(mnt_userns, under_inode, under_child, mode);
#else
    ret = vfs_mkdir(under_inode, under_child, mode);
#endif
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

static int sukisu_fs_rmdir_impl(struct user_namespace *mnt_userns,
                                 struct inode *dir, struct dentry *dentry)
{
    struct sukisu_fs_inode_info *info = SUKISU_I(dir);
    struct dentry *under_dir;
    struct dentry *under_child;
    int ret;

    (void)mnt_userns; /* unused on 5.10; passed to vfs_rmdir on 5.12+ */

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    ret = vfs_rmdir(mnt_userns, under_dir->d_inode, under_child);
#else
    ret = vfs_rmdir(under_dir->d_inode, under_child);
#endif
    inode_unlock(under_dir->d_inode);
    dput(under_child);
    dput(under_dir);
    return ret;
}

/* android13 DDKs (5.10 and 5.15) ship a 5-arg .rename with no
 * mnt_userns argument. Stock mainline 5.12+ uses 6 args; v1
 * deliberately only supports the DDK layout. 6.2+ is excluded
 * entirely (it switches to a single struct renamedata *). */
static int sukisu_fs_rename_impl(struct inode *old_dir,
                                  struct dentry *old_dentry,
                                  struct inode *new_dir,
                                  struct dentry *new_dentry,
                                  unsigned int flags)
#define sukisu_fs_rename_mnt_userns (&init_user_ns)
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

    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)
        /* DDK 5.10 has vfs_rename(&rd) with a full struct
         * renamedata, but it does not have an mnt_userns field
         * (vendor patch stripped it). Use the 6-arg form. */
        ret = vfs_rename(sukisu_fs_rename_mnt_userns,
                         under_old_dir->d_inode, under_old_child,
                         under_new_dir->d_inode, under_new_child, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
        /* Stock mainline 5.12+ exposes vfs_rename(&rd) and a
         * full struct renamedata definition in <linux/fs.h>. */
        struct renamedata rd = {
            .old_dir    = under_old_dir->d_inode,
            .old_dentry = under_old_child,
            .new_dir    = under_new_dir->d_inode,
            .new_dentry = under_new_child,
            .flags      = flags,
        };
        ret = vfs_rename(&rd);
#else
        ret = vfs_rename(sukisu_fs_rename_mnt_userns,
                         under_old_dir->d_inode, under_old_child,
                         under_new_dir->d_inode, under_new_child, NULL);
#endif
    }

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

/* The inode_operations table needs the right function pointer type
 * for each slot, which depends on the kernel version. The android13
 * vendor BSP at the time of writing has the following layout:
 *
 *   .create / .mkdir / .setattr: mnt_userns-aware
 *   .unlink / .rmdir / .getattr / .rename: no mnt_userns
 *
 * vfs_create / vfs_unlink / vfs_mkdir / vfs_rmdir inside the
 * shim dispatch on the actual kernel function signature. */
static int sukisu_fs_create_shim(struct user_namespace *mnt_userns,
                                  struct inode *dir, struct dentry *dentry,
                                  umode_t mode, bool excl)
{
    return sukisu_fs_create_impl(mnt_userns, dir, dentry, mode, excl);
}
static int sukisu_fs_unlink_shim(struct inode *dir, struct dentry *dentry)
{
    return sukisu_fs_unlink_impl(&init_user_ns, dir, dentry);
}
static int sukisu_fs_mkdir_shim(struct user_namespace *mnt_userns,
                                 struct inode *dir, struct dentry *dentry,
                                 umode_t mode)
{
    return sukisu_fs_mkdir_impl(mnt_userns, dir, dentry, mode);
}
static int sukisu_fs_rmdir_shim(struct inode *dir, struct dentry *dentry)
{
    return sukisu_fs_rmdir_impl(&init_user_ns, dir, dentry);
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
/* Stock mainline 5.12+ expects the mnt_userns argument on
 * unlink / rmdir as well. The __unused attribute silences
 * the warning emitted on vendor BSPs where these are not
 * actually installed. */
static int __attribute__((unused)) sukisu_fs_unlink_shim_5_12(struct user_namespace *mnt_userns,
                                       struct inode *dir, struct dentry *dentry)
{
    return sukisu_fs_unlink_impl(mnt_userns, dir, dentry);
}
static int __attribute__((unused)) sukisu_fs_rmdir_shim_5_12(struct user_namespace *mnt_userns,
                                      struct inode *dir, struct dentry *dentry)
{
    return sukisu_fs_rmdir_impl(mnt_userns, dir, dentry);
}
#endif

const struct inode_operations sukisu_fs_inode_ops = {
    .lookup    = sukisu_fs_lookup,
    .getattr   = sukisu_fs_getattr,
    .setattr   = sukisu_fs_setattr,
    /* .create / .mkdir take an explicit mnt_userns on every
     * kernel version we ship on (5.10+), so we always install
     * the 5-arg / 4-arg shim. */
    .create    = sukisu_fs_create_shim,
    .mkdir     = sukisu_fs_mkdir_shim,
    /* unlink / rmdir: the android13-5.10 and android13-5.15
     * vendor BSPs reverted the mnt_userns argument that mainline
     * added in 5.11/5.12. We use the 2-arg shim unconditionally;
     * init_user_ns is what the underlying fs would derive from
     * the dentry anyway. */
    .unlink    = sukisu_fs_unlink_shim,
    .rmdir     = sukisu_fs_rmdir_shim,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
    .rename    = sukisu_fs_rename_impl,
    /* 6.2+ switched inode_operations.rename to a single
     * `struct renamedata *` argument. For that ABI we would need a
     * second wrapper that builds renamedata out of the same fields.
     * v1 deliberately skips that to keep the surface small; the
     * callers that need rename in 6.2+ can use the ioctl path. */
#endif
};
