// SPDX-License-Identifier: GPL-2.0
/*
 * sukisu_fs_file.c - file operations for sukisu-fs
 *
 * Read and write operations are forwarded to the underlying file
 * opened on-demand by absolute path. The underlying file is cached
 * on the open file struct and released on close.
 */

#include <linux/aio.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "klog.h"
#include "sukisu_fs.h"

struct sukisu_fs_file_info {
    struct file *underlying;
};

static inline struct sukisu_fs_file_info *sukisu_f_info(struct file *f)
{
    return f->private_data;
}

/* Helper: take a reference to a "root-like" credential that is
 * allowed to traverse kernel-internal paths. In practice we use the
 * init_cred because sukisu-fs only operates on /data/adb paths and
 * the underlying VFS doesn't care about the caller once we have a
 * dentry. */
static const struct cred *sukisu_fs_get_cred(void)
{
    return &init_cred;
}

static int sukisu_fs_open(struct inode *inode, struct file *file)
{
    struct sukisu_fs_inode_info *info = inode->i_private;
    struct file *under;
    struct sukisu_fs_file_info *fi;
    int flags;
    const struct cred *old_cred;

    if (!info || !info->underlying || !info->cached_path)
        return -EIO;

    if ((file->f_mode & FMODE_READ) && (file->f_mode & FMODE_WRITE))
        flags = O_RDWR;
    else if (file->f_mode & FMODE_WRITE)
        flags = O_WRONLY;
    else
        flags = O_RDONLY;
    flags |= O_LARGEFILE;

    old_cred = override_creds(sukisu_fs_get_cred());
    under = filp_open(info->cached_path, flags, file->f_mode & 0777);
    revert_creds(old_cred);

    if (IS_ERR(under))
        return PTR_ERR(under);

    fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) {
        fput(under);
        return -ENOMEM;
    }
    fi->underlying = under;
    file->private_data = fi;
    return 0;
}

static int sukisu_fs_release(struct inode *inode, struct file *file)
{
    struct sukisu_fs_file_info *fi = sukisu_f_info(file);

    if (fi) {
        if (fi->underlying)
            fput(fi->underlying);
        kfree(fi);
    }
    file->private_data = NULL;
    return 0;
}

static loff_t sukisu_fs_llseek(struct file *file, loff_t offset, int whence)
{
    struct sukisu_fs_file_info *fi = sukisu_f_info(file);
    if (!fi || !fi->underlying)
        return -EIO;
    return vfs_llseek(fi->underlying, offset, whence);
}

static ssize_t sukisu_fs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
    struct sukisu_fs_file_info *fi = sukisu_f_info(iocb->ki_filp);
    ssize_t ret;

    if (!fi || !fi->underlying)
        return -EIO;

    ret = vfs_read(fi->underlying, NULL, iocb->ki_pos, to, NULL);
    if (ret > 0)
        iocb->ki_pos = fi->underlying->f_pos;
    return ret;
}

static ssize_t sukisu_fs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    struct sukisu_fs_file_info *fi = sukisu_f_info(iocb->ki_filp);
    ssize_t ret;

    if (!fi || !fi->underlying)
        return -EIO;

    ret = vfs_write(fi->underlying, NULL, iocb->ki_pos, from, NULL);
    if (ret > 0)
        iocb->ki_pos = fi->underlying->f_pos;
    return ret;
}

static int sukisu_fs_fsync(struct file *file, loff_t start, loff_t end,
                            int datasync)
{
    struct sukisu_fs_file_info *fi = sukisu_f_info(file);
    if (!fi || !fi->underlying)
        return -EIO;
    return vfs_fsync(fi->underlying, datasync);
}

const struct file_operations sukisu_fs_file_ops = {
    .owner      = THIS_MODULE,
    .open       = sukisu_fs_open,
    .release    = sukisu_fs_release,
    .llseek     = sukisu_fs_llseek,
    .read_iter  = sukisu_fs_read_iter,
    .write_iter = sukisu_fs_write_iter,
    .fsync      = sukisu_fs_fsync,
};
