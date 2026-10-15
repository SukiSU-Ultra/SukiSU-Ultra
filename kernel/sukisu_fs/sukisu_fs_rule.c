// SPDX-License-Identifier: GPL-2.0
/*
 * sukisu_fs_rule.c - uid visibility rule table
 *
 * Rules are simple (path, view, uid range) tuples. The matcher walks
 * the table linearly; the table is bounded (SUKISU_FS_MAX_RULES) so
 * this is fine for a few hundred entries. For larger tables a hash
 * table keyed on path prefix would be the next step.
 *
 * Concurrency: protected by a single rwlock. Reads happen on every
 * readdir() / lookup() / getattr() so we prefer the read path.
 */

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "klog.h"
#include "uapi/sukisu_fs.h"
#include "sukisu_fs.h"

struct sukisu_fs_rule_entry {
    struct list_head list;
    struct sukisu_fs_rule rule;
};

static LIST_HEAD(sukisu_fs_rule_list);
static DEFINE_RWLOCK(sukisu_fs_rule_lock);
static u32 sukisu_fs_rule_count;

int sukisu_fs_rule_add(const struct sukisu_fs_rule *rule)
{
    struct sukisu_fs_rule_entry *entry;
    size_t path_len;

    if (!rule)
        return -EINVAL;

    path_len = strnlen(rule->path, SUKISU_FS_MAX_PATH);
    if (path_len == 0 || path_len >= SUKISU_FS_MAX_PATH)
        return -EINVAL;

    if (rule->uid_min > rule->uid_max)
        return -EINVAL;

    if (rule->view != SUKISU_FS_VIEW_HIDE && rule->view != SUKISU_FS_VIEW_SHOW)
        return -EINVAL;

    write_lock(&sukisu_fs_rule_lock);
    if (sukisu_fs_rule_count >= SUKISU_FS_MAX_RULES) {
        write_unlock(&sukisu_fs_rule_lock);
        return -ENOSPC;
    }
    write_unlock(&sukisu_fs_rule_lock);

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    memcpy(&entry->rule, rule, sizeof(entry->rule));

    write_lock(&sukisu_fs_rule_lock);
    if (sukisu_fs_rule_count >= SUKISU_FS_MAX_RULES) {
        write_unlock(&sukisu_fs_rule_lock);
        kfree(entry);
        return -ENOSPC;
    }
    list_add_tail(&entry->list, &sukisu_fs_rule_list);
    sukisu_fs_rule_count++;
    write_unlock(&sukisu_fs_rule_lock);

    return 0;
}

int sukisu_fs_rule_remove(const char *path)
{
    struct sukisu_fs_rule_entry *entry, *tmp;
    size_t target_len;
    bool found = false;

    if (!path)
        return -EINVAL;

    target_len = strnlen(path, SUKISU_FS_MAX_PATH);
    if (target_len == 0 || target_len >= SUKISU_FS_MAX_PATH)
        return -EINVAL;

    write_lock(&sukisu_fs_rule_lock);
    list_for_each_entry_safe(entry, tmp, &sukisu_fs_rule_list, list) {
        size_t entry_len = strnlen(entry->rule.path, SUKISU_FS_MAX_PATH);
        if (entry_len == target_len &&
            !strncmp(entry->rule.path, path, target_len)) {
            list_del(&entry->list);
            sukisu_fs_rule_count--;
            kfree(entry);
            found = true;
            break;
        }
    }
    write_unlock(&sukisu_fs_rule_lock);

    return found ? 0 : -ENOENT;
}

void sukisu_fs_rule_clear(void)
{
    struct sukisu_fs_rule_entry *entry, *tmp;

    write_lock(&sukisu_fs_rule_lock);
    list_for_each_entry_safe(entry, tmp, &sukisu_fs_rule_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    sukisu_fs_rule_count = 0;
    write_unlock(&sukisu_fs_rule_lock);
}

u32 sukisu_fs_rule_get_count(void)
{
    u32 count;

    read_lock(&sukisu_fs_rule_lock);
    count = sukisu_fs_rule_count;
    read_unlock(&sukisu_fs_rule_lock);

    return count;
}

int sukisu_fs_rule_get_at(u32 index, struct sukisu_fs_rule *out)
{
    struct sukisu_fs_rule_entry *entry;
    u32 i = 0;
    int ret = -ENOENT;

    if (!out)
        return -EINVAL;

    read_lock(&sukisu_fs_rule_lock);
    list_for_each_entry(entry, &sukisu_fs_rule_list, list) {
        if (i == index) {
            memcpy(out, &entry->rule, sizeof(*out));
            ret = 0;
            break;
        }
        i++;
    }
    read_unlock(&sukisu_fs_rule_lock);

    return ret;
}

/* Caller is responsible for prefix-checking the result. */
static bool path_matches(const char *rule_path, size_t rule_len,
                          const char *full_path, size_t full_len)
{
    /* Exact match. */
    if (rule_len == full_len &&
        !strncmp(rule_path, full_path, full_len))
        return true;

    /* Prefix match: rule must be a complete path component. */
    if (full_len > rule_len &&
        !strncmp(rule_path, full_path, rule_len) &&
        full_path[rule_len] == '/')
        return true;

    return false;
}

/*
 * Decide whether the (path, current uid) combination should be hidden.
 *
 * HIDE rules: hide the path from uids in [uid_min, uid_max]
 * SHOW rules: hide the path from uids *outside* [uid_min, uid_max]
 *
 * The first matching rule wins. If no rule matches, the entry is
 * visible.
 */
bool sukisu_fs_should_hide_path(const char *path, unsigned int path_len)
{
    struct sukisu_fs_rule_entry *entry;
    bool hidden = false;
    uid_t uid;

    if (!path || path_len == 0)
        return false;

    /* uid as seen inside the kernel, mod 100000 (per-user app id). */
    uid = from_kuid(&init_user_ns, current_uid()) % 100000U;

    read_lock(&sukisu_fs_rule_lock);
    list_for_each_entry(entry, &sukisu_fs_rule_list, list) {
        size_t rule_len = strnlen(entry->rule.path, SUKISU_FS_MAX_PATH);
        if (!path_matches(entry->rule.path, rule_len, path, path_len))
            continue;

        if (entry->rule.view == SUKISU_FS_VIEW_HIDE) {
            if (uid >= entry->rule.uid_min && uid <= entry->rule.uid_max)
                hidden = true;
        } else { /* SHOW */
            if (uid < entry->rule.uid_min || uid > entry->rule.uid_max)
                hidden = true;
        }
        break;
    }
    read_unlock(&sukisu_fs_rule_lock);

    return hidden;
}
