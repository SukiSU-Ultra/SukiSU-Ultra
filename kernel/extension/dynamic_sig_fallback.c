// SPDX-License-Identifier: GPL-2.0
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "util.h"
#include "uapi/app_profile.h"
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "dynamic_sig_fallback.h"

#define DATA_PATH_LEN 384

struct uid_data_mirror {
    struct list_head list;
    u32 uid;
    char package[KSU_MAX_PACKAGE_NAME];
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN_TYPE bool
#define FILLDIR_ACTOR_CONTINUE true
#define FILLDIR_ACTOR_STOP false
#else
#define FILLDIR_RETURN_TYPE int
#define FILLDIR_ACTOR_CONTINUE 0
#define FILLDIR_ACTOR_STOP -EINVAL
#endif

struct fb_path {
    char dirpath[DATA_PATH_LEN];
    int depth;
    struct list_head list;
};

struct fb_dir_ctx {
    struct dir_context ctx;
    struct list_head *path_list;
    char *parent_dir;
    int depth;
    bool matched;
};

static FILLDIR_RETURN_TYPE fb_actor(struct dir_context *ctx,
                                    const char *name, int namelen,
                                    loff_t off, u64 ino, unsigned int d_type)
{
    struct fb_dir_ctx *c = container_of(ctx, struct fb_dir_ctx, ctx);
    char dirpath[DATA_PATH_LEN];

    if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
        return FILLDIR_ACTOR_CONTINUE;

    /* Skip Android staging package dirs (vmdl*.tmp) */
    if (d_type == DT_DIR && namelen >= 8 && !strncmp(name, "vmdl", 4) &&
        !strncmp(name + namelen - 4, ".tmp", 4))
        return FILLDIR_ACTOR_CONTINUE;

    if (snprintf(dirpath, DATA_PATH_LEN, "%s/%.*s", c->parent_dir, namelen,
                 name) >= DATA_PATH_LEN)
        return FILLDIR_ACTOR_CONTINUE;

    if (d_type == DT_REG && namelen == 8 && !memcmp(name, "base.apk", 8)) {
        if (!c->matched && is_manager_apk(dirpath))
            c->matched = true;
        return FILLDIR_ACTOR_CONTINUE;
    }

    if (d_type == DT_DIR && c->depth > 0) {
        struct fb_path *p = kzalloc(sizeof(*p), GFP_KERNEL);
        if (!p)
            return FILLDIR_ACTOR_CONTINUE;
        strscpy(p->dirpath, dirpath, DATA_PATH_LEN);
        p->depth = c->depth - 1;
        list_add_tail(&p->list, c->path_list);
    }
    return FILLDIR_ACTOR_CONTINUE;
}

static void fb_scan_dir(struct fb_path *pos, struct list_head *path_list,
                        bool *matched)
{
    struct fb_dir_ctx ctx = {
        .ctx.actor = fb_actor,
        .path_list = path_list,
        .parent_dir = pos->dirpath,
        .depth = pos->depth,
        .matched = false,
    };
    struct file *file = ksu_filp_open_nonotify(pos->dirpath,
                                               O_RDONLY | O_NOFOLLOW |
                                                   O_NOATIME | O_DIRECTORY);
    if (IS_ERR(file)) {
        pr_err("sig_fallback: open %s: %ld\n", pos->dirpath, PTR_ERR(file));
        return;
    }
    iterate_dir(file, &ctx.ctx);
    filp_close(file, NULL);
    *matched = ctx.matched;
}

static bool fb_crown_by_pkg(const char *pkg, struct list_head *uid_data)
{
    struct uid_data_mirror *np;
    list_for_each_entry (np, uid_data, list) {
        if (strncmp(np->package, pkg, sizeof(np->package)) == 0) {
            pr_info("sig_fallback: crowning %s(uid=%u)\n", pkg, np->uid);
            ksu_set_manager_appid(np->uid);
            return true;
        }
    }
    return false;
}

bool track_throne_sig_fallback_hook(struct list_head *uid_data)
{
    struct list_head path_list;
    struct fb_path root;
    struct fb_path *pos, *n;
    bool crowned = false;

    INIT_LIST_HEAD(&path_list);
    memset(&root, 0, sizeof(root));
    strscpy(root.dirpath, "/data/app", DATA_PATH_LEN);
    root.depth = 2;
    list_add_tail(&root.list, &path_list);

    pr_info("Searching manager via signature fallback...\n");

    while (!crowned && !list_empty(&path_list)) {
        list_for_each_entry_safe (pos, n, &path_list, list) {
            bool matched = false;
            fb_scan_dir(pos, &path_list, &matched);
            if (matched) {
                char pkg[KSU_MAX_PACKAGE_NAME];
                if (get_pkg_from_apk_dir_path(pkg, pos->dirpath) >= 0 &&
                    fb_crown_by_pkg(pkg, uid_data))
                    crowned = true;
            }
            list_del(&pos->list);
            if (pos != &root)
                kfree(pos);
            if (crowned)
                break;
        }
    }
    return crowned;
}
