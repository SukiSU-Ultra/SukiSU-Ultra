#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "feature/kernel_umount.h"
#include "klog.h" // IWYU pragma: keep
#include "policy/allowlist.h"
#include "selinux/selinux.h"
#include "policy/feature.h"
#include "runtime/ksud_boot.h"
#include "ksu.h"

static bool ksu_kernel_umount_enabled = true;

LIST_HEAD(umount_exclusion_list);
DECLARE_RWSEM(umount_exclusion_lock);

static int kernel_umount_feature_get(u64 *value)
{
    *value = ksu_kernel_umount_enabled ? 1 : 0;
    return 0;
}

static int kernel_umount_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_kernel_umount_enabled = enable;
    pr_info("kernel_umount: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
    .feature_id = KSU_FEATURE_KERNEL_UMOUNT,
    .name = "kernel_umount",
    .get_handler = kernel_umount_feature_get,
    .set_handler = kernel_umount_feature_set,
};

extern int path_umount(struct path *path, int flags);

static void ksu_umount_mnt(const char *mnt, struct path *path, int flags)
{
    int err = path_umount(path, flags);
    if (err) {
        pr_info("umount %s failed: %d\n", mnt, err);
    }
}

static void try_umount(const char *mnt, int flags)
{
    struct path path;
    int err = kern_path(mnt, 0, &path);
    if (err) {
        return;
    }

    if (path.dentry != path.mnt->mnt_root) {
        // it is not root mountpoint, maybe umounted by others already.
        path_put(&path);
        return;
    }

    ksu_umount_mnt(mnt, &path, flags);
}

// Check if mount point should be skipped due to exclusion prefix
// Returns true if mnt starts with any exclusion prefix
static bool should_skip_mount_for_exclusion(const char *mnt)
{
	struct umount_exclusion_entry *entry;
	bool skip = false;
	size_t prefix_len;

	down_read(&umount_exclusion_lock);
	list_for_each_entry (entry, &umount_exclusion_list, list) {
		prefix_len = strlen(entry->path_prefix);
		// Check if mount path starts with the exclusion prefix
		if (prefix_len > 0 && strncmp(mnt, entry->path_prefix, prefix_len) == 0) {
			skip = true;
			break;
		}
	}
	up_read(&umount_exclusion_lock);

	return skip;
}

struct umount_tw {
    struct callback_head cb;
};

int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
    // if there isn't any module mounted, just ignore it!
    if (!ksu_module_mounted) {
        return 0;
    }

    if (!ksu_kernel_umount_enabled) {
        return 0;
    }

    // There are 6 scenarios:
    // 1. Normal app: zygote -> appuid
    // 2. Isolated process forked from zygote: zygote -> isolated_process
    // 3. App zygote forked from zygote: zygote -> appuid
    // 4. Webview zygote forked from zygote: zygote -> WEBVIEW_ZYGOTE_UID (no need to handle, app cannot run custom code)
    // 5. Isolated process forked from app zygote: appuid -> isolated_process (already handled by 3)
    // 6. Isolated process forked from webview zygote (no need to handle, app cannot run custom code)
    if (!is_appuid(new_uid) && !is_isolated_process(new_uid)) {
        return 0;
    }

    if (!ksu_uid_should_umount(new_uid) && !is_isolated_process(new_uid)) {
        return 0;
    }

    // check old process's selinux context, if it is not zygote, ignore it!
    // because some su apps may setuid to untrusted_app but they are in global mount namespace
    // when we umount for such process, that is a disaster!
    // also handle case 4 and 5
    bool is_zygote_child = is_zygote(current_cred());
    if (!is_zygote_child) {
        pr_info("handle umount ignore non zygote child: %d\n", current->pid);
        return 0;
    }
    // umount the target mnt
    pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

    const struct cred *saved = override_creds(ksu_cred);

    struct mount_entry *entry;
    down_read(&mount_list_lock);
    list_for_each_entry (entry, &mount_list, list) {
        if (should_skip_mount_for_exclusion(entry->umountable)) {
            pr_info("%s: skipping excluded mount: %s\n", __func__, entry->umountable);
        } else {
            pr_info("%s: unmounting: %s flags: 0x%x\n", __func__, entry->umountable, entry->flags);
            try_umount(entry->umountable, entry->flags);
        }
    }
    up_read(&mount_list_lock);

    revert_creds(saved);

    return 0;
}

static struct umount_exclusion_entry *alloc_exclusion_entry(const char *path_prefix)
{
	struct umount_exclusion_entry *entry;
	size_t prefix_len;
	size_t alloc_len;
	char *normalized_prefix;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	prefix_len = strlen(path_prefix);
	// Allocate extra space for optional '/' and null terminator
	alloc_len = prefix_len + 3;
	normalized_prefix = kzalloc(alloc_len, GFP_KERNEL);
	if (!normalized_prefix) {
		kfree(entry);
		return NULL;
	}

	strscpy(normalized_prefix, path_prefix, alloc_len);
	// Ensure path ends with '/'
	if (prefix_len == 0 || normalized_prefix[prefix_len - 1] != '/') {
		normalized_prefix[prefix_len] = '/';
		normalized_prefix[prefix_len + 1] = '\0';
	}

	entry->path_prefix = normalized_prefix;
	return entry;
}

static void free_exclusion_entry(struct umount_exclusion_entry *entry)
{
	if (entry) {
		kfree(entry->path_prefix);
		kfree(entry);
	}
}

int ksu_umount_exclusion_add(const char *path_prefix)
{
	struct umount_exclusion_entry *entry, *new_entry;

	if (!path_prefix || strlen(path_prefix) == 0)
		return -EINVAL;

	new_entry = alloc_exclusion_entry(path_prefix);
	if (!new_entry)
		return -ENOMEM;

	down_write(&umount_exclusion_lock);
	// Check for duplicates
	list_for_each_entry (entry, &umount_exclusion_list, list) {
		if (strcmp(entry->path_prefix, new_entry->path_prefix) == 0) {
			up_write(&umount_exclusion_lock);
			free_exclusion_entry(new_entry);
			return 0;
		}
	}
	list_add_tail(&new_entry->list, &umount_exclusion_list);
	up_write(&umount_exclusion_lock);

	pr_info("umount exclusion added: prefix=%s\n", new_entry->path_prefix);
	return 0;
}

int ksu_umount_exclusion_remove(const char *path_prefix)
{
	struct umount_exclusion_entry *entry, *tmp;
	int removed = 0;
	size_t prefix_len;

	if (!path_prefix)
		return -EINVAL;

	prefix_len = strlen(path_prefix);
	down_write(&umount_exclusion_lock);
	list_for_each_entry_safe (entry, tmp, &umount_exclusion_list, list) {
		// Match by exact path or if input is a prefix of stored path
		if (strcmp(entry->path_prefix, path_prefix) == 0 ||
		    (prefix_len > 0 && strncmp(entry->path_prefix, path_prefix, prefix_len) == 0 &&
		     entry->path_prefix[prefix_len] == '/')) {
			list_del(&entry->list);
			free_exclusion_entry(entry);
			removed++;
		}
	}
	up_write(&umount_exclusion_lock);

	pr_info("umount exclusion removed: prefix=%s, count=%d\n", path_prefix, removed);
	return removed;
}

int ksu_umount_exclusion_clear(void)
{
	struct umount_exclusion_entry *entry, *tmp;

	down_write(&umount_exclusion_lock);
	list_for_each_entry_safe (entry, tmp, &umount_exclusion_list, list) {
		list_del(&entry->list);
		free_exclusion_entry(entry);
	}
	up_write(&umount_exclusion_lock);

	pr_info("umount exclusion list cleared\n");
	return 0;
}

static int exclusion_list_copy_to_user(char __user *buf, size_t buf_size, size_t *out_len)
{
	struct umount_exclusion_entry *entry;
	size_t total_len = 0;
	char line_buffer[512];
	int len;

	down_read(&umount_exclusion_lock);
	list_for_each_entry (entry, &umount_exclusion_list, list) {
		len = snprintf(line_buffer, sizeof(line_buffer), "%s\n", entry->path_prefix);
		if (total_len + len < buf_size) {
			if (copy_to_user(buf + total_len, line_buffer, len)) {
				up_read(&umount_exclusion_lock);
				return -EFAULT;
			}
			total_len += len;
		} else {
			break;
		}
	}
	up_read(&umount_exclusion_lock);

	*out_len = total_len;
	return 0;
}

ssize_t ksu_umount_exclusion_list(char __user *buf, size_t buf_size)
{
	size_t len;
	int ret;

	ret = exclusion_list_copy_to_user(buf, buf_size, &len);
	if (ret)
		return ret;

	if (len < buf_size) {
		char term = '\0';
		if (copy_to_user(buf + len, &term, 1))
			return -EFAULT;
		len++;
	}

	return len;
}

void __init ksu_kernel_umount_init(void)
{
    if (ksu_register_feature_handler(&kernel_umount_handler)) {
        pr_err("Failed to register kernel_umount feature handler\n");
    }
}

void __exit ksu_kernel_umount_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
    ksu_umount_exclusion_clear();
}
