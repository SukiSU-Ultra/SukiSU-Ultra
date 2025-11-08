#include "umount_manager.h"
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/cred.h>
#include "klog.h"

static struct umount_manager g_umount_mgr = {
    .entry_count = 0,
    .max_entries = 64,
};

extern int path_umount(struct path *path, int flags);

static bool check_path_busy(const char *path)
{
    struct path kpath;
    int err;

    err = kern_path(path, 0, &kpath);
    if (err) {
        return false;
    }

    bool busy = (kpath.mnt->mnt_root != kpath.dentry);
    path_put(&kpath);

    return busy;
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

static int init_default_entries(void)
{
    int ret;

    const struct {
        const char *path;
        bool check_mnt;
        int flags;
    } defaults[] = {
        { "/odm", true, 0 },
        { "/system", true, 0 },
        { "/vendor", true, 0 },
        { "/product", true, 0 },
        { "/system_ext", true, 0 },
        { "/data/adb/modules", false, MNT_DETACH },
        { "/debug_ramdisk", false, MNT_DETACH },
    };

    for (int i = 0; i < ARRAY_SIZE(defaults); i++) {
        ret = ksu_umount_manager_add(defaults[i].path, 
                                     defaults[i].check_mnt,
                                     defaults[i].flags,
                                     true); // is_default = true
        if (ret) {
            pr_err("Failed to add default entry: %s, ret=%d\n",
                   defaults[i].path, ret);
            return ret;
        }
    }

    pr_info("Initialized %zu default umount entries\n", ARRAY_SIZE(defaults));
    return 0;
}

int ksu_umount_manager_init(void)
{
    INIT_LIST_HEAD(&g_umount_mgr.entry_list);
    spin_lock_init(&g_umount_mgr.lock);

    return init_default_entries();
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

int ksu_umount_manager_add(const char *path, bool check_mnt, int flags, bool is_default)
{
    struct umount_entry *entry;
    unsigned long irqflags;
    int ret = 0;

    if (flags == -1)
        flags = MNT_DETACH;

    if (!path || strlen(path) == 0 || strlen(path) >= 256) {
        return -EINVAL;
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
    entry->check_mnt = check_mnt;
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

bool ksu_umount_path_is_busy(const char *path)
{
    return check_path_busy(path);
}

static void try_umount_path(struct umount_entry *entry)
{
    struct path kpath;
    int err;

    err = kern_path(entry->path, 0, &kpath);
    if (err) {
        return;
    }

    if (kpath.dentry != kpath.mnt->mnt_root) {
        path_put(&kpath);
        return;
    }

    if (entry->check_mnt) {
        if (kpath.mnt && kpath.mnt->mnt_sb && kpath.mnt->mnt_sb->s_type) {
            const char *fstype = kpath.mnt->mnt_sb->s_type->name;
            if (strcmp(fstype, "overlay") != 0) {
                path_put(&kpath);
                return;
            }
        }
    }

    err = path_umount(&kpath, entry->flags);
    if (err) {
        pr_info("umount %s failed: %d\n", entry->path, err);
    }

    path_put(&kpath);
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
    struct umount_entry *entry;
    struct ksu_umount_entry_info info;
    unsigned long flags;
    u32 idx = 0;
    u32 max_count = *count;

    spin_lock_irqsave(&g_umount_mgr.lock, flags);

    list_for_each_entry(entry, &g_umount_mgr.entry_list, list) {
        if (idx >= max_count) {
            break;
        }

        memset(&info, 0, sizeof(info));
        strncpy(info.path, entry->path, sizeof(info.path) - 1);
        info.check_mnt = entry->check_mnt;
        info.flags = entry->flags;
        info.is_default = entry->is_default;
        info.state = entry->state;
        info.ref_count = entry->ref_count;

        if (copy_to_user(&entries[idx], &info, sizeof(info))) {
            spin_unlock_irqrestore(&g_umount_mgr.lock, flags);
            return -EFAULT;
        }

        idx++;
    }

    *count = idx;

    spin_unlock_irqrestore(&g_umount_mgr.lock, flags);
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
