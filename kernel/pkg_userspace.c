#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/task_work.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/signal.h>
#include <linux/cred.h>
#include <linux/mm.h>
#include <linux/kstrtox.h>

#include "klog.h"
#include "pkg_userspace.h"
#include "feature.h"
#include "supercalls.h"

bool ksu_uid_scanner_enabled = false;
static pid_t uid_scanner_daemon_pid = 0;

// UID list management
struct uid_package_entry {
    struct list_head list;
    uid_t uid;
    char package_name[256];
};

static LIST_HEAD(uid_package_list);
static DEFINE_MUTEX(uid_list_mutex);

static int uid_scanner_feature_get(u64 *value)
{
    if (!value)
        return -EINVAL;
    
    *value = ksu_uid_scanner_enabled ? 1 : 0;
    return 0;
}

static int uid_scanner_feature_set(u64 value)
{
    bool new_state = (value != 0);
    
    if (new_state == ksu_uid_scanner_enabled) {
        return 0;
    }
    
    ksu_uid_scanner_enabled = new_state;
    
    pr_info("uid_scanner: feature set to %s\n",
            ksu_uid_scanner_enabled ? "enabled" : "disabled");
    
    return 0;
}

static const struct ksu_feature_handler uid_scanner_handler = {
    .feature_id = KSU_FEATURE_UID_SCANNER,
    .name = "uid_scanner",
    .get_handler = uid_scanner_feature_get,
    .set_handler = uid_scanner_feature_set,
};

void ksu_register_uid_scanner_daemon(pid_t pid)
{
    if (pid <= 0) {
        pr_info("uid_scanner: daemon unregistered (old pid=%d)\n",
                uid_scanner_daemon_pid);
        uid_scanner_daemon_pid = 0;
        return;
    }
    
    uid_scanner_daemon_pid = pid;
    pr_info("uid_scanner: daemon registered with pid=%d\n", pid);
}

void ksu_request_userspace_scan(void)
{
    struct pid *pid_struct;
    struct task_struct *target;

    if (uid_scanner_daemon_pid <= 0) {
        pr_debug("uid_scanner: no daemon registered, skipping scan request\n");
        return;
    }

    pid_struct = find_get_pid(uid_scanner_daemon_pid);
    if (!pid_struct) {
        pr_warn("uid_scanner: daemon PID %d not found, unregistering\n",
                uid_scanner_daemon_pid);
        uid_scanner_daemon_pid = 0;
        return;
    }

    target = pid_task(pid_struct, PIDTYPE_PID);
    if (target) {
        send_sig(SIGUSR1, target, 0);
        pr_info("uid_scanner: sent SIGUSR1 to daemon (pid=%d)\n",
                uid_scanner_daemon_pid);
    } else {
        pr_warn("uid_scanner: task for PID %d not found, unregistering\n",
                uid_scanner_daemon_pid);
        uid_scanner_daemon_pid = 0;
    }

    put_pid(pid_struct);
}

void ksu_pkg_userspace_init(void)
{
    int ret = ksu_register_feature_handler(&uid_scanner_handler);
    if (ret) {
        pr_err("uid_scanner: failed to register feature handler: %d\n", ret);
    } else {
        pr_info("uid_scanner: feature handler registered\n");
    }
}

int ksu_update_uid_list(void __user *entries_ptr, u32 count)
{
    struct ksu_uid_list_entry *entries = NULL;
    struct uid_package_entry *entry, *tmp;
    u32 i;
    int ret = 0;

    if (count == 0 || count > 10000) {
        pr_err("uid_list: invalid count %u\n", count);
        return -EINVAL;
    }

    // Allocate kernel buffer
    entries = kzalloc(count * sizeof(struct ksu_uid_list_entry), GFP_KERNEL);
    if (!entries) {
        pr_err("uid_list: failed to allocate memory for %u entries\n", count);
        return -ENOMEM;
    }

    // Copy from userspace
    if (copy_from_user(entries, entries_ptr, count * sizeof(struct ksu_uid_list_entry))) {
        pr_err("uid_list: failed to copy entries from userspace\n");
        ret = -EFAULT;
        goto out_free;
    }

    mutex_lock(&uid_list_mutex);

    // Clear old list
    list_for_each_entry_safe(entry, tmp, &uid_package_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }

    // Build new list
    for (i = 0; i < count; i++) {
        entry = kzalloc(sizeof(struct uid_package_entry), GFP_KERNEL);
        if (!entry) {
            pr_warn("uid_list: failed to allocate entry %u, stopping\n", i);
            break;
        }

        entry->uid = entries[i].uid;
        // Ensure null termination
        memcpy(entry->package_name, entries[i].package_name, sizeof(entry->package_name) - 1);
        entry->package_name[sizeof(entry->package_name) - 1] = '\0';

        list_add_tail(&entry->list, &uid_package_list);
    }

    mutex_unlock(&uid_list_mutex);

    pr_info("uid_list: updated with %u entries\n", i);

out_free:
    kfree(entries);
    return ret;
}

bool ksu_uid_exists_in_list(uid_t uid, char *package)
{
    struct uid_package_entry *entry;
    bool found = false;

    mutex_lock(&uid_list_mutex);
    
    list_for_each_entry(entry, &uid_package_list, list) {
        if (entry->uid == uid) {
            if (package) {
                strncpy(package, entry->package_name, 256);
            }
            found = true;
            break;
        }
    }
    
    mutex_unlock(&uid_list_mutex);
    
    return found;
}

int ksu_iterate_uid_list(bool (*callback)(uid_t uid, const char *package_name))
{
    struct uid_package_entry *entry;
    int count = 0;

    if (!callback) {
        return -EINVAL;
    }

    mutex_lock(&uid_list_mutex);
    
    list_for_each_entry(entry, &uid_package_list, list) {
        if (!callback(entry->uid, entry->package_name)) {
            break;
        }
        count++;
    }
    
    mutex_unlock(&uid_list_mutex);
    
    return count;
}

void ksu_pkg_userspace_exit(void)
{
    struct uid_package_entry *entry, *tmp;

    // Clean up UID list
    mutex_lock(&uid_list_mutex);
    list_for_each_entry_safe(entry, tmp, &uid_package_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    mutex_unlock(&uid_list_mutex);

    ksu_unregister_feature_handler(KSU_FEATURE_UID_SCANNER);
    pr_info("uid_scanner: feature handler unregistered\n");
}
