// SPDX-License-Identifier: GPL-2.0
/*
 * Signature-fallback manager crown.
 *
 * track_throne() only crowns KSU_PACKAGE_NAME. This file supplies the
 * second chance: re-scan /data/app and crown *any* APK signed with the
 * canonical built-in KernelSU signature, regardless of its package name.
 * It is reached through the ksu_sig_fallback static key (see
 * dynamic_sig_fallback.h) rather than a weak symbol, so the call site is
 * an indirect branch with a real default target and an uninstalled
 * fallback can never deref NULL.
 *
 * The scanner is deliberately self-contained: its own dir_context, its own
 * path list, and it caches nothing. It is an independent pass over
 * /data/app and must not touch track_throne()'s cached_manager_apk_path
 * or its KSU_PACKAGE_NAME bookkeeping.
 *
 * Security note: the s_magic pinning below is load-bearing, not an
 * optimisation. Without it an attacker able to bind-mount a filesystem
 * with a crafted <pkg>/base.apk inside /data/app could feed us an APK
 * that is not on the real data partition. Mirrors the identical check in
 * throne_tracker.c's search_manager().
 */
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#include "klog.h" // IWYU pragma: keep
#include "util.h"
#include "uapi/app_profile.h"
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "dynamic_sig_fallback.h"

#define DATA_PATH_LEN 384 // 384 is enough for /data/app/<package>/base.apk

#define SIG_FALLBACK_ROOT "/data/app"

#define SIG_FALLBACK_DEPTH 2

// https://docs.kernel.org/filesystems/porting.html
// filldir_t (readdir callbacks) returning bool since 6.1; see throne_tracker.c
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

static FILLDIR_RETURN_TYPE fb_actor(struct dir_context *ctx, const char *name, int namelen, loff_t off, u64 ino,
                                    unsigned int d_type)
{
    struct fb_dir_ctx *c = container_of(ctx, struct fb_dir_ctx, ctx);
    char dirpath[DATA_PATH_LEN];

    if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
        return FILLDIR_ACTOR_CONTINUE; // Skip "." and ".."

    if (d_type == DT_DIR && namelen >= 8 && !strncmp(name, "vmdl", 4) && !strncmp(name + namelen - 4, ".tmp", 4)) {
        pr_info("sig_fallback: skipping staging dir: %.*s\n", namelen, name);
        return FILLDIR_ACTOR_CONTINUE; // Skip staging package
    }

    if (snprintf(dirpath, DATA_PATH_LEN, "%s/%.*s", c->parent_dir, namelen, name) >= DATA_PATH_LEN) {
        pr_err("sig_fallback: path too long: %s/%.*s\n", c->parent_dir, namelen, name);
        return FILLDIR_ACTOR_CONTINUE;
    }

    if (d_type == DT_REG && namelen == 8 && !memcmp(name, "base.apk", 8)) {
        if (!c->matched && is_manager_apk(dirpath))
            c->matched = true;
        return FILLDIR_ACTOR_CONTINUE;
    }

    if (d_type == DT_DIR && c->depth > 0) {
        struct fb_path *p = kzalloc(sizeof(*p), GFP_KERNEL);

        if (!p) {
            pr_err("sig_fallback: out of memory queueing %s\n", dirpath);
            return FILLDIR_ACTOR_CONTINUE;
        }

        strscpy(p->dirpath, dirpath, DATA_PATH_LEN);
        p->depth = c->depth - 1;
        list_add_tail(&p->list, c->path_list);
    }

    return FILLDIR_ACTOR_CONTINUE;
}

static bool fb_crown_by_pkg(const char *pkg, struct list_head *uid_data)
{
    struct uid_data *np;

    list_for_each_entry (np, uid_data, list) {
        if (strncmp(np->package, pkg, KSU_MAX_PACKAGE_NAME) == 0) {
            pr_info("sig_fallback: crowning %s(uid=%u)\n", pkg, np->uid);
            ksu_set_manager_appid(np->uid);
            return true;
        }
    }

    pr_warn("sig_fallback: signed apk found but %s is not in packages.list\n", pkg);
    return false;
}

static bool fb_crown_by_signature(struct list_head *uid_data)
{
    struct list_head data_path_list;
    struct fb_path root;
    struct fb_path *pos, *n;
    unsigned long data_app_magic = 0;
    int i;
    bool crowned = false;

    INIT_LIST_HEAD(&data_path_list);
    memset(&root, 0, sizeof(root));
    strscpy(root.dirpath, SIG_FALLBACK_ROOT, DATA_PATH_LEN);
    root.depth = SIG_FALLBACK_DEPTH;
    list_add_tail(&root.list, &data_path_list);

    for (i = SIG_FALLBACK_DEPTH; i >= 0 && !crowned; i--) {
        list_for_each_entry_safe (pos, n, &data_path_list, list) {
            struct fb_dir_ctx ctx = {
                .ctx.actor = fb_actor,
                .path_list = &data_path_list,
                .parent_dir = pos->dirpath,
                .depth = pos->depth,
                .matched = false,
            };
            struct file *file;

            if (crowned)
                goto skip_iterate;

            file = ksu_filp_open_nonotify(pos->dirpath, O_RDONLY | O_NOFOLLOW | O_NOATIME | O_DIRECTORY);
            if (IS_ERR(file)) {
                pr_err("sig_fallback: open %s: %ld\n", pos->dirpath, PTR_ERR(file));
                goto skip_iterate;
            }

            if (!data_app_magic) {
                if (file->f_inode->i_sb->s_magic) {
                    data_app_magic = file->f_inode->i_sb->s_magic;
                    pr_info("sig_fallback: %s: magic 0x%lx\n", pos->dirpath, data_app_magic);
                } else {
                    filp_close(file, NULL);
                    goto skip_iterate;
                }
            }

            if (file->f_inode->i_sb->s_magic != data_app_magic) {
                pr_info("sig_fallback: skip %s: magic 0x%lx expected 0x%lx\n", pos->dirpath,
                        file->f_inode->i_sb->s_magic, data_app_magic);
                filp_close(file, NULL);
                goto skip_iterate;
            }

            iterate_dir(file, &ctx.ctx);
            filp_close(file, NULL);

            if (!ctx.matched)
                goto skip_iterate;

            pr_info("sig_fallback: signed apk found at %s\n", pos->dirpath);

            {
                char pkg[KSU_MAX_PACKAGE_NAME];

                if (get_pkg_from_apk_dir_path(pkg, pos->dirpath) >= 0)
                    crowned = fb_crown_by_pkg(pkg, uid_data);
            }

        skip_iterate:
            list_del(&pos->list);
            if (pos != &root)
                kfree(pos);
        }
    }

    if (crowned)
        pr_info("sig_fallback: crowned manager by signature\n");
    else
        pr_info("sig_fallback: no signed manager under " SIG_FALLBACK_ROOT "\n");

    return crowned;
}

DEFINE_STATIC_KEY_FALSE(ksu_sig_fallback_key);

ksu_sig_fallback_fn ksu_sig_fallback_current;

int ksu_sig_fallback_register(ksu_sig_fallback_fn fn)
{
    bool was_enabled;

    if (!fn)
        return -EINVAL;

    was_enabled = READ_ONCE(ksu_sig_fallback_current) != NULL;
    if (was_enabled && READ_ONCE(ksu_sig_fallback_current) == fn)
        return 0;

    if (was_enabled)
        static_branch_disable(&ksu_sig_fallback_key);

    WRITE_ONCE(ksu_sig_fallback_current, fn);
    static_branch_enable(&ksu_sig_fallback_key);
    pr_info("sig_fallback: registered %px\n", (void *)fn);
    return 0;
}

void ksu_sig_fallback_unregister(void)
{
    if (!READ_ONCE(ksu_sig_fallback_current))
        return;

    static_branch_disable(&ksu_sig_fallback_key);
    WRITE_ONCE(ksu_sig_fallback_current, NULL);
    pr_info("sig_fallback: unregistered, fallback disabled\n");
}

bool ksu_sig_fallback_registered(void)
{
    return READ_ONCE(ksu_sig_fallback_current) != NULL;
}

void __init ksu_sig_fallback_init(void)
{
    ksu_sig_fallback_register(fb_crown_by_signature);
}

void __exit ksu_sig_fallback_exit(void)
{
    ksu_sig_fallback_unregister();
}
