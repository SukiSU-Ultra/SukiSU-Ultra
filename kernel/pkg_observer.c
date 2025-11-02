// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/fsnotify.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/version.h>
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "throne_tracker.h"
#include "throne_comm.h"

#define MASK_SYSTEM (FS_CREATE | FS_MOVE | FS_EVENT_ON_CHILD)

struct watch_dir {
    const char *path;
    u32 mask;
    struct path kpath;
    struct inode *inode;
    struct fsnotify_mark *mark;
};

static struct fsnotify_group *g;

#include "pkg_observer_defs.h" // KSU_DECL_FSNOTIFY_OPS
static KSU_DECL_FSNOTIFY_OPS(ksu_handle_generic_event)
{
    if (!file_name || (mask & FS_ISDIR))
        return 0;

    if (ksu_fname_len(file_name) == 13 &&
        !memcmp(ksu_fname_arg(file_name), "packages.list", 13)) {
            pr_info("packages.list detected: %d\n", mask);
            if (ksu_uid_scanner_enabled) {
            ksu_request_userspace_scan();
        }
        track_throne();
    }
    return 0;
}

static const struct fsnotify_ops ksu_ops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    .handle_inode_event = ksu_handle_generic_event,
#else
    .handle_event = ksu_handle_generic_event,
#endif
};

static void __maybe_unused m_free(struct fsnotify_mark *m)
{
    if (m) {
        kfree(m);
    }
}

static int add_mark_on_inode(struct inode *inode, u32 mask,
                 struct fsnotify_mark **out)
{
    struct fsnotify_mark *m;
    int ret;

    m = kzalloc(sizeof(*m), GFP_KERNEL);
    if (!m)
        return -ENOMEM;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    fsnotify_init_mark(m, g);
    m->mask = mask;
    ret = fsnotify_add_inode_mark(m, inode, 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    fsnotify_init_mark(m, g);
    m->mask = mask;
    ret = fsnotify_add_mark(m, inode, NULL, 0);
#else
    fsnotify_init_mark(m, g, m_free);
    m->mask = mask;
    ret = fsnotify_add_mark(m, g, inode, NULL, 0);
#endif

    if (ret < 0) {
        fsnotify_put_mark(m);
        return ret;
    }

    *out = m;
    return 0;
}

static int watch_one_dir(struct watch_dir *wd)
{
    int ret = kern_path(wd->path, LOOKUP_FOLLOW, &wd->kpath);
    if (ret) {
        pr_info("path not ready: %s (%d)\n", wd->path, ret);
        return ret;
    }
    wd->inode = d_inode(wd->kpath.dentry);
    ihold(wd->inode);

    ret = add_mark_on_inode(wd->inode, wd->mask, &wd->mark);
    if (ret) {
        pr_err("Add mark failed for %s (%d)\n", wd->path, ret);
        path_put(&wd->kpath);
        iput(wd->inode);
        wd->inode = NULL;
        return ret;
    }
    pr_info("watching %s\n", wd->path);
    return 0;
}

static void unwatch_one_dir(struct watch_dir *wd)
{
    if (wd->mark) {
        fsnotify_destroy_mark(wd->mark, g);
        fsnotify_put_mark(wd->mark);
        wd->mark = NULL;
    }
    if (wd->inode) {
        iput(wd->inode);
        wd->inode = NULL;
    }
    if (wd->kpath.dentry) {
        path_put(&wd->kpath);
        memset(&wd->kpath, 0, sizeof(wd->kpath));
    }
}

static struct watch_dir g_watch = {
    .path = "/data/system",
    .mask = MASK_SYSTEM
};

int ksu_observer_init(void)
{
    int ret = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    g = fsnotify_alloc_group(&ksu_ops, 0);
#else
    g = fsnotify_alloc_group(&ksu_ops);
#endif
    if (IS_ERR(g))
        return PTR_ERR(g);

    ret = watch_one_dir(&g_watch);
    pr_info("%s done.\n", __func__);
    return 0;
}

void ksu_observer_exit(void)
{
    unwatch_one_dir(&g_watch);
    fsnotify_put_group(g);
    pr_info("%s: done.\n", __func__);
}