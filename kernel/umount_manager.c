#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/cred.h>

#include "klog.h"
#include "kernel_umount.h"
#include "umount_manager.h"

static struct umount_manager g_umount_mgr = {
    .entry_count = 0,
    .max_entries = 512,
};

static void try_umount_path(struct umount_entry *entry)
{
    try_umount(entry->path, entry->flags);
}

static struct umount_entry *find_entry_locked(const char *path)
{
    struct umount_entry *entry;

    list_for_each_entry(entry, &g_umount_mgr.entry_list, list) {
        if (strcmp(entry->path, path) == 0) {
            return entry;
        }
    }

    return NULL;
}

static bool is_path_in_mount_list(const char *path)
{
    struct mount_entry *entry;
    bool found = false;

    down_read(&mount_list_lock);
    list_for_each_entry(entry, &mount_list, list) {
        if (entry->umountable && strcmp(entry->umountable, path) == 0) {
            found = true;
            break;
        }
    }
    up_read(&mount_list_lock);

    return found;
}

static int copy_mount_entry_to_user(struct ksu_umount_entry_info __user *entries,
                                    u32 idx, const char *path, int flags)
{
    struct ksu_umount_entry_info info;

    memset(&info, 0, sizeof(info));
    strncpy(info.path, path, sizeof(info.path) - 1);
    info.path[sizeof(info.path) - 1] = '\0';
    info.flags = flags;
    info.is_default = 1;
    info.state = UMOUNT_STATE_IDLE;
    info.ref_count = 0;

    if (copy_to_user(&entries[idx], &info, sizeof(info))) {
        return -EFAULT;
    }

    return 0;
}

static int copy_umount_entry_to_user(struct ksu_umount_entry_info __user *entries,
                                      u32 idx, struct umount_entry *entry)
{
    struct ksu_umount_entry_info info;

    memset(&info, 0, sizeof(info));
    strncpy(info.path, entry->path, sizeof(info.path) - 1);
    info.path[sizeof(info.path) - 1] = '\0';
    info.flags = entry->flags;
    info.is_default = entry->is_default;
    info.state = entry->state;
    info.ref_count = entry->ref_count;

    if (copy_to_user(&entries[idx], &info, sizeof(info))) {
        return -EFAULT;
    }

    return 0;
}

static int collect_mount_list_entries(struct ksu_umount_entry_info __user *entries,
                                       u32 max_count, u32 *out_idx)
{
    struct mount_entry *mount_entry;
    u32 idx = 0;

    down_read(&mount_list_lock);
    list_for_each_entry(mount_entry, &mount_list, list) {
        if (idx >= max_count) {
            break;
        }

        if (!mount_entry->umountable) {
            continue;
        }

        if (copy_mount_entry_to_user(entries, idx, mount_entry->umountable,
                                      mount_entry->flags)) {
            up_read(&mount_list_lock);
            return -EFAULT;
        }

        idx++;
    }
    up_read(&mount_list_lock);

    *out_idx = idx;
    return 0;
}

static int collect_umount_manager_entries(struct ksu_umount_entry_info __user *entries,
                                          u32 start_idx, u32 max_count, u32 *out_idx)
{
    struct umount_entry *entry;
    unsigned long flags;
    u32 idx = start_idx;

    spin_lock_irqsave(&g_umount_mgr.lock, flags);

    list_for_each_entry(entry, &g_umount_mgr.entry_list, list) {
        if (idx >= max_count) {
            break;
        }

        if (is_path_in_mount_list(entry->path)) {
            continue;
        }

        spin_unlock_irqrestore(&g_umount_mgr.lock, flags);

        if (copy_umount_entry_to_user(entries, idx, entry)) {
            return -EFAULT;
        }

        idx++;
        spin_lock_irqsave(&g_umount_mgr.lock, flags);
    }

    spin_unlock_irqrestore(&g_umount_mgr.lock, flags);
    *out_idx = idx;
    return 0;
}

int ksu_umount_manager_init(void)
{
    INIT_LIST_HEAD(&g_umount_mgr.entry_list);
    spin_lock_init(&g_umount_mgr.lock);

    return 0;
}

void ksu_umount_manager_exit(void)
{
    struct umount_entry *entry, *tmp;
    unsigned long flags;

    spin_lock_irqsave(&g_umount_mgr.lock, flags);

    list_for_each_entry_safe(entry, tmp, &g_umount_mgr.entry_list, list) {
        list_del(&entry->list);
        kfree(entry);
        g_umount_mgr.entry_count--;
    }

    spin_unlock_irqrestore(&g_umount_mgr.lock, flags);

    pr_info("Umount manager cleaned up\n");
}

int ksu_umount_manager_add(const char *path, int flags, bool is_default)
{
    struct umount_entry *entry;
    unsigned long irqflags;
    int ret = 0;

    if (flags == -1)
        flags = MNT_DETACH;

    if (!path || strlen(path) == 0 || strlen(path) >= 256) {
        return -EINVAL;
    }

    if (is_path_in_mount_list(path)) {
        pr_warn("Umount manager: path already exists in mount_list: %s\n", path);
        return -EEXIST;
    }

    spin_lock_irqsave(&g_umount_mgr.lock, irqflags);

    if (g_umount_mgr.entry_count >= g_umount_mgr.max_entries) {
        pr_err("Umount manager: max entries reached\n");
        ret = -ENOMEM;
        goto out;
    }

    if (find_entry_locked(path)) {
        pr_warn("Umount manager: path already exists: %s\n", path);
        ret = -EEXIST;
        goto out;
    }

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        ret = -ENOMEM;
        goto out;
    }

    strncpy(entry->path, path, sizeof(entry->path) - 1);
    entry->flags = flags;
    entry->state = UMOUNT_STATE_IDLE;
    entry->is_default = is_default;
    entry->ref_count = 0;

    list_add_tail(&entry->list, &g_umount_mgr.entry_list);
    g_umount_mgr.entry_count++;

    pr_info("Umount manager: added %s entry: %s\n",
            is_default ? "default" : "custom", path);

out:
    spin_unlock_irqrestore(&g_umount_mgr.lock, irqflags);
    return ret;
}

int ksu_umount_manager_remove(const char *path)
{
    struct umount_entry *entry;
    unsigned long flags;
    int ret = 0;

    if (!path) {
        return -EINVAL;
    }

    spin_lock_irqsave(&g_umount_mgr.lock, flags);

    entry = find_entry_locked(path);
    if (!entry) {
        ret = -ENOENT;
        goto out;
    }

    if (entry->is_default) {
        pr_err("Umount manager: cannot remove default entry: %s\n", path);
        ret = -EPERM;
        goto out;
    }

    if (entry->state == UMOUNT_STATE_BUSY || entry->ref_count > 0) {
        pr_err("Umount manager: entry is busy: %s\n", path);
        ret = -EBUSY;
        goto out;
    }

    list_del(&entry->list);
    g_umount_mgr.entry_count--;
    kfree(entry);

    pr_info("Umount manager: removed entry: %s\n", path);

out:
    spin_unlock_irqrestore(&g_umount_mgr.lock, flags);
    return ret;
}

void ksu_umount_manager_execute_all(const struct cred *cred)
{
    struct umount_entry *entry;
    unsigned long flags;

    spin_lock_irqsave(&g_umount_mgr.lock, flags);

    list_for_each_entry(entry, &g_umount_mgr.entry_list, list) {
        if (entry->state == UMOUNT_STATE_IDLE) {
            entry->ref_count++;
        }
    }

    spin_unlock_irqrestore(&g_umount_mgr.lock, flags);

    list_for_each_entry(entry, &g_umount_mgr.entry_list, list) {
        if (entry->ref_count > 0 && entry->state == UMOUNT_STATE_IDLE) {
            try_umount_path(entry);
        }
    }

    spin_lock_irqsave(&g_umount_mgr.lock, flags);

    list_for_each_entry(entry, &g_umount_mgr.entry_list, list) {
        if (entry->ref_count > 0) {
            entry->ref_count--;
        }
    }

    spin_unlock_irqrestore(&g_umount_mgr.lock, flags);
}

int ksu_umount_manager_get_entries(struct ksu_umount_entry_info __user *entries, u32 *count)
{
    u32 max_count = *count;
    u32 idx;
    int ret;

    ret = collect_mount_list_entries(entries, max_count, &idx);
    if (ret) {
        return ret;
    }

    if (idx < max_count) {
        ret = collect_umount_manager_entries(entries, idx, max_count, &idx);
        if (ret) {
            return ret;
        }
    }

    *count = idx;
    return 0;
}

int ksu_umount_manager_clear_custom(void)
{
    struct umount_entry *entry, *tmp;
    unsigned long flags;
    u32 cleared = 0;

    spin_lock_irqsave(&g_umount_mgr.lock, flags);

    list_for_each_entry_safe(entry, tmp, &g_umount_mgr.entry_list, list) {
        if (!entry->is_default && entry->state == UMOUNT_STATE_IDLE && entry->ref_count == 0) {
            list_del(&entry->list);
            kfree(entry);
            g_umount_mgr.entry_count--;
            cleared++;
        }
    }

    spin_unlock_irqrestore(&g_umount_mgr.lock, flags);

    pr_info("Umount manager: cleared %u custom entries\n", cleared);
    return 0;
}