#include "ksu.h"
#include "linux/cred.h"
#include "linux/namei.h"
#include "util.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#include "policy/allowlist.h"
#include "manager/apk_sign.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "manager/dynamic_manager.h"
#include "manager/throne_tracker.h"

static DEFINE_MUTEX(throne_tracker_mutex);

uid_t ksu_manager_appid = KSU_INVALID_APPID;

#define DATA_PATH_LEN 384 // 384 is enough for /data/app/<package>/base.apk

static char cached_manager_apk_path[DATA_PATH_LEN];

#define SYSTEM_PACKAGES_LIST_PATH "/data/system/packages.list"

struct uid_data {
    struct list_head list;
    u32 uid;
    char package[KSU_MAX_PACKAGE_NAME];
};

static bool crown_manager(const char *apk, struct list_head *uid_data, bool builtin_already_crowned)
{
    struct list_head *list = (struct list_head *)uid_data;
    struct uid_data *np;
    bool builtin_crowned_this_call = false;

    list_for_each_entry (np, list, list) {
        if (strncmp(np->package, KSU_PACKAGE_NAME, KSU_MAX_PACKAGE_NAME) == 0) {
            /*
             * Built-in manager: highest-priority candidate, never
             * gated by dynamic_manager_enabled. is_manager_apk()
             * compares against EXPECTED_HASH/EXPECTED_SIZE compiled
             * in via Kbuild — that is the sole source of truth for
             * "is this APK the stock manager".
             */
            if (is_manager_apk((char *)apk)) {
                pr_info("Crowning manager: uid=%d\n", np->uid);
                ksu_set_manager_appid(np->uid);
                builtin_crowned_this_call = true;
            }
            break; /* KSU_PACKAGE_NAME appears at most once per uid list */
        }
    }
    /*
     * Built-in already holds the crown (either crowned earlier in
     * this scan, or just crowned above). Refuse to consider any
     * dynamic candidate on this or any subsequent APK in the same
     * scan. Without this, the very last APK visited could silently
     * demote the built-in to a user-added entry.
     */
    if (builtin_already_crowned || builtin_crowned_this_call)
        return true;

    /*
     * Dynamic managers are opt-in: the user explicitly added them
     * AND toggled the manager feature on (which, on this fork,
     * doubles as the dynamic-manager gate — ksu_manager_enabled()
     * returns the value of the static dynamic_manager_enabled in
     * dynamic_manager.c). When the feature is off, the in-memory
     * entry stays (so SET_ENABLED can re-enable without re-adding),
     * but it does not get crowned.
     */
    if (!ksu_manager_enabled())
        return false;

    list_for_each_entry (np, list, list) {
        if (strncmp(np->package, KSU_PACKAGE_NAME, KSU_MAX_PACKAGE_NAME) == 0)
            continue;
        /*
         * For dynamic managers the (package, uid) pair must match a
         * persisted entry AND the just-completed signature verification
         * before we crown it. The runtime scan already mutated
         * dynamic_manager_verified for this iteration; refuse to crown
         * anything that the scan did not just validate.
         */
        if (ksu_dynamic_manager_verify_apk((char *)apk, np->package, np->uid)) {
            pr_info("Crowning dynamic manager: package=%s, uid=%d\n", np->package, np->uid);
            ksu_set_manager_appid(np->uid);
        }
    }
    return false;
}

struct data_path {
    char dirpath[DATA_PATH_LEN];
    int depth;
    struct list_head list;
};

struct my_dir_context {
    struct dir_context ctx;
    struct list_head *data_path_list;
    char *parent_dir;
    void *private_data;
    int depth;
};
// https://docs.kernel.org/filesystems/porting.html
// filldir_t (readdir callbacks) calling conventions have changed. Instead of returning 0 or -E... it returns bool now. false means "no more" (as -E... used to) and true - "keep going" (as 0 in old calling convention). Rationale: callers never looked at specific -E... values anyway. -> iterate_shared() instances require no changes at all, all filldir_t ones in the tree converted.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN_TYPE bool
#define FILLDIR_ACTOR_CONTINUE true
#define FILLDIR_ACTOR_STOP false
#else
#define FILLDIR_RETURN_TYPE int
#define FILLDIR_ACTOR_CONTINUE 0
#define FILLDIR_ACTOR_STOP -EINVAL
#endif

static bool maybe_manager_apk_dir(const char *path)
{
    _Static_assert(sizeof(KSU_PACKAGE_NAME) < KSU_MAX_PACKAGE_NAME, "KSU_PACKAGE_NAME too long!");
    char pkg[KSU_MAX_PACKAGE_NAME];
    if (get_pkg_from_apk_dir_path(pkg, path) < 0) {
        pr_err("Failed to get package name from apk dir path: %s\n", path);
        return false;
    }

    /*
     * The pre-dynamic-manager version of this helper returned true
     * only for the built-in KSU_PACKAGE_NAME. We now also accept
     * user-added dynamic managers so their base.apk is picked up
     * by the scan. The crown step later in search_manager()
     * distinguishes the two via the (package, uid) match and the
     * built-in priority invariant — this filter is just "is the
     * package one we might care about?".
     */
    return strncmp(pkg, KSU_PACKAGE_NAME, sizeof(KSU_PACKAGE_NAME)) == 0 ||
           ksu_dynamic_manager_package_registered(pkg);
}

static FILLDIR_RETURN_TYPE my_actor(struct dir_context *ctx, const char *name, int namelen, loff_t off, u64 ino,
                                    unsigned int d_type)
{
    struct my_dir_context *my_ctx = container_of(ctx, struct my_dir_context, ctx);

    // we put the apk path we collected here
    char *candidate_path = (char *)my_ctx->private_data;

    char dirpath[DATA_PATH_LEN];

    if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
        return FILLDIR_ACTOR_CONTINUE; // Skip "." and ".."

    if (d_type == DT_DIR && namelen >= 8 && !strncmp(name, "vmdl", 4) && !strncmp(name + namelen - 4, ".tmp", 4)) {
        pr_info("Skipping directory: %.*s\n", namelen, name);
        return FILLDIR_ACTOR_CONTINUE; // Skip staging package
    }

    if (snprintf(dirpath, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir, namelen, name) >= DATA_PATH_LEN) {
        pr_err("Path too long: %s/%.*s\n", my_ctx->parent_dir, namelen, name);
        return FILLDIR_ACTOR_CONTINUE;
    }

    if (d_type == DT_DIR && my_ctx->depth > 0) {
        struct data_path *data = kzalloc(sizeof(struct data_path), GFP_KERNEL);

        if (!data) {
            pr_err("Failed to allocate memory for %s\n", dirpath);
            return FILLDIR_ACTOR_CONTINUE;
        }

        strscpy(data->dirpath, dirpath, DATA_PATH_LEN);
        data->depth = my_ctx->depth - 1;
        list_add_tail(&data->list, my_ctx->data_path_list);

        return FILLDIR_ACTOR_CONTINUE;
    }

    // now put this on candidate_path
    if (d_type == DT_REG && namelen == 8 && !memcmp(name, "base.apk", 8)) {
        if (maybe_manager_apk_dir(my_ctx->parent_dir)) {
            snprintf(candidate_path, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir, namelen, name);
            /*
             * Only cache the built-in's APK path. Dynamic packages
             * do not get a fast-skip path: when dynamic_manager_enabled
             * is on we always re-scan so we can re-verify their
             * signature on every boot.
             */
            char package[KSU_MAX_PACKAGE_NAME];
            if (get_pkg_from_apk_dir_path(package, my_ctx->parent_dir) == 0 &&
                !strcmp(package, KSU_PACKAGE_NAME))
                strscpy(cached_manager_apk_path, candidate_path, DATA_PATH_LEN);
        }
        // As soon as we met the base.apk, we can stop
        return FILLDIR_ACTOR_STOP;
    }

    return FILLDIR_ACTOR_CONTINUE;
}

static void search_manager(const char *path, int depth, struct list_head *uid_data)
{
    int i, stop = 0;
    struct list_head data_path_list;
    INIT_LIST_HEAD(&data_path_list);
    unsigned long data_app_magic = 0;
    /*
     * Once crown_manager() reports that the built-in was crowned
     * for *any* APK in this scan, every subsequent APK must skip
     * its dynamic-manager branch — otherwise a user-added dynamic
     * entry visited later would silently demote the built-in. This
     * is the priority invariant enforced from the search side.
     */
    bool builtin_crowned = false;

    // First depth
    struct data_path data;
    strscpy(data.dirpath, path, DATA_PATH_LEN);
    data.depth = depth;
    list_add_tail(&data.list, &data_path_list);

    // we put the apk path we collected here
    char candidate_path[DATA_PATH_LEN];
    candidate_path[0] = 0;
    ksu_dynamic_manager_reset_verification();

    for (i = depth; i >= 0; i--) {
        struct data_path *pos, *n;

        list_for_each_entry_safe (pos, n, &data_path_list, list) {
            if (stop)
                goto skip_iterate;
            struct my_dir_context ctx = { .ctx.actor = my_actor,
                                          .data_path_list = &data_path_list,
                                          .parent_dir = pos->dirpath,
                                          .private_data = candidate_path,
                                          .depth = pos->depth };
            struct file *file = ksu_filp_open_nonotify(pos->dirpath, O_RDONLY | O_NOFOLLOW | O_NOATIME | O_DIRECTORY);
            if (IS_ERR(file)) {
                pr_err("Failed to open directory: %s, err: %ld\n", pos->dirpath, PTR_ERR(file));
                goto skip_iterate;
            }

            // grab magic on first folder, which is /data/app
            if (!data_app_magic) {
                if (file->f_inode->i_sb->s_magic) {
                    data_app_magic = file->f_inode->i_sb->s_magic;
                    pr_info("%s: dir: %s got magic! 0x%lx\n", __func__, pos->dirpath, data_app_magic);
                } else {
                    filp_close(file, NULL);
                    goto skip_iterate;
                }
            }

            if (file->f_inode->i_sb->s_magic != data_app_magic) {
                pr_info("%s: skip: %s magic: 0x%lx expected: 0x%lx\n", __func__, pos->dirpath,
                        file->f_inode->i_sb->s_magic, data_app_magic);
                filp_close(file, NULL);
                goto skip_iterate;
            }

            iterate_dir(file, &ctx.ctx);
            filp_close(file, NULL);

            if (!candidate_path[0])
                goto skip_iterate;

            /*
             * Resolve which package this APK belongs to and whether
             * the install matches a known manager. We split the
             * decision into:
             *   - KSU_PACKAGE_NAME: must pass is_manager_apk() (pure
             *     EXPECTED_HASH/EXPECTED_SIZE check) — that is the
             *     built-in manager.
             *   - anything else: must be a registered dynamic
             *     manager AND its persisted UID must match what
             *     packages.list currently shows. We do not verify
             *     the signature here; crown_manager() does that as
             *     the single source of truth, which keeps the two
             *     classes of manager on independent code paths.
             */
            char package[KSU_MAX_PACKAGE_NAME] = {};
            uid_t package_uid = KSU_INVALID_APPID;
            struct uid_data *uid_entry;
            bool is_manager = false;

            if (get_pkg_from_apk_dir_path(package, pos->dirpath) == 0) {
                list_for_each_entry (uid_entry, (struct list_head *)uid_data, list) {
                    if (!strcmp(uid_entry->package, package)) {
                        package_uid = uid_entry->uid;
                        break;
                    }
                }
                if (package_uid != KSU_INVALID_APPID) {
                    if (!strcmp(package, KSU_PACKAGE_NAME)) {
                        is_manager = is_manager_apk(candidate_path);
                    } else if (ksu_dynamic_manager_package_registered(package)) {
                        uid_t expected_uid = KSU_INVALID_APPID;
                        is_manager = ksu_dynamic_manager_uid_for_package(package, &expected_uid) == 0 &&
                                     expected_uid == package_uid % KSU_PER_USER_RANGE;
                    }
                }
            }
            pr_info("Found manager base.apk at path: %s, package=%s, uid=%u, is_manager: %d\n", candidate_path,
                    package, package_uid, is_manager);

            if (unlikely(!is_manager))
                goto skip_iterate;

            stop = 1;
            if (crown_manager(candidate_path, uid_data, builtin_crowned))
                builtin_crowned = true;

        skip_iterate:
            list_del(&pos->list);
            if (pos != &data)
                kfree(pos);
        }
    }
}

static bool is_uid_exist(uid_t uid, char *package, void *data)
{
    struct list_head *list = (struct list_head *)data;
    struct uid_data *np;

    bool exist = false;
    list_for_each_entry (np, list, list) {
        if (np->uid == uid % PER_USER_RANGE && strncmp(np->package, package, KSU_MAX_PACKAGE_NAME) == 0) {
            exist = true;
            break;
        }
    }
    return exist;
}

void track_throne(bool prune_only)
{
    mutex_lock(&throne_tracker_mutex);
    const struct cred *old_cred = override_creds(ksu_cred);
    struct file *fp = filp_open(SYSTEM_PACKAGES_LIST_PATH, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_err("%s: open " SYSTEM_PACKAGES_LIST_PATH " failed: %ld\n", __func__, PTR_ERR(fp));
        goto out_revert_cred;
    }

    struct list_head uid_list;
    INIT_LIST_HEAD(&uid_list);

    char chr = 0;
    loff_t pos = 0;
    loff_t line_start = 0;
    char buf[KSU_MAX_PACKAGE_NAME];
    for (;;) {
        ssize_t count = kernel_read(fp, &chr, sizeof(chr), &pos);
        if (count != sizeof(chr))
            break;
        if (chr != '\n')
            continue;

        count = kernel_read(fp, buf, sizeof(buf) - 1, &line_start);
        if (count <= 0) {
            break;
        }
        buf[count] = '\0';

        struct uid_data *data = kzalloc(sizeof(struct uid_data), GFP_KERNEL);
        if (!data) {
            filp_close(fp, 0);
            goto out;
        }

        char *tmp = buf;
        const char *delim = " ";
        char *package = strsep(&tmp, delim);
        char *uid = strsep(&tmp, delim);
        if (!uid || !package) {
            kfree(data);
            pr_err("update_uid: package or uid is NULL!\n");
            break;
        }

        u32 res;
        if (kstrtou32(uid, 10, &res)) {
            kfree(data);
            pr_err("update_uid: uid parse err\n");
            break;
        }
        data->uid = res;
        strscpy(data->package, package, sizeof(data->package));
        list_add_tail(&data->list, &uid_list);
        // reset line start
        line_start = pos;
    }
    filp_close(fp, 0);

    // now update uid list
    struct uid_data *np;
    struct uid_data *n;

    if (prune_only)
        goto prune;

    // first, check if manager_uid exist!
    uid_t manager_package_uid = KSU_INVALID_APPID;
    bool need_rescan = false;
    list_for_each_entry (np, &uid_list, list) {
        if (strcmp(np->package, KSU_PACKAGE_NAME) == 0) {
            manager_package_uid = np->uid;
            break;
        }
    }

    if (manager_package_uid == KSU_INVALID_APPID) {
        cached_manager_apk_path[0] = 0;
        if (ksu_is_manager_appid_valid()) {
            pr_info("manager is uninstalled, invalidate it!\n");
            ksu_invalidate_manager_uid();
            goto prune;
        }
    } else {
        if (!ksu_is_manager_appid_valid()) {
            need_rescan = true;
        } else if (unlikely(np->uid != ksu_get_manager_appid())) {
            // this should not happen in normal android system
            pr_info("manager uid changed, invalidate it!\n");
            cached_manager_apk_path[0] = 0;
            ksu_invalidate_manager_uid();
            need_rescan = true;
        } else {
            // uid unchanged, skip search!
            pr_info("manager uid unchanged, skip search!\n");
        }
        /*
         * Whenever the user has dynamic managers enabled, we must
         * re-scan on every track_throne() call. Otherwise we would
         * only verify the built-in (which is gated by the cached
         * apk path fast-skip) and never check whether a user-added
         * dynamic entry has been added, removed, or replaced since
         * the last scan.
         */
        if (ksu_manager_enabled())
            need_rescan = true;
    }

    if (need_rescan) {
        // If the apk path still exists, the verification result won't be changed
        if (cached_manager_apk_path[0] && !ksu_manager_enabled()) {
            struct path p;
            int ret = kern_path(cached_manager_apk_path, 0, &p);
            if (ret == 0) {
                // skip search
                pr_info("manager apk path unchanged, skip search!\n");
                path_put(&p);
                goto prune;
            } else if (ret != -ENOENT) {
                pr_err("stat cached manager path failed: %d (path=%s)\n", ret, cached_manager_apk_path);
            }
        }
        pr_info("Searching manager " KSU_PACKAGE_NAME "...\n");
        search_manager("/data/app", 2, &uid_list);
        pr_info("Search manager finished\n");
    }

prune:
    // then prune the allowlist
    ksu_prune_allowlist(is_uid_exist, &uid_list);
out:
    // free uid_list
    list_for_each_entry_safe (np, n, &uid_list, list) {
        list_del(&np->list);
        kfree(np);
    }
out_revert_cred:
    revert_creds(old_cred);
    mutex_unlock(&throne_tracker_mutex);
}

void __init ksu_throne_tracker_init()
{
    // nothing to do
}

void __exit ksu_throne_tracker_exit()
{
    // nothing to do
}
