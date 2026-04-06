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
#include <linux/string.h>
#include <linux/dcache.h>

#include "feature/kernel_umount.h"
#include "klog.h" // IWYU pragma: keep
#include "policy/allowlist.h"
#include "selinux/selinux.h"
#include "policy/feature.h"
#include "runtime/ksud_boot.h"
#include "ksu.h"

static bool ksu_kernel_umount_enabled = true;

#define KSU_EXCLUDED_MODULES_MAX 64
#define KSU_EXCLUDED_MODULE_ID_LEN 128
static char excluded_modules[KSU_EXCLUDED_MODULES_MAX][KSU_EXCLUDED_MODULE_ID_LEN];
static int excluded_modules_count;

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

struct umount_tw {
    struct callback_head cb;
};

static bool ksu_is_module_excluded(const char *module_id)
{
    int i;
    if (!module_id || excluded_modules_count == 0)
        return false;

    for (i = 0; i < excluded_modules_count; i++) {
        if (strcmp(excluded_modules[i], module_id) == 0)
            return true;
    }
    return false;
}

static char g_module_id_buf[KSU_EXCLUDED_MODULE_ID_LEN];

static const char *ksu_extract_module_id_from_mount_path(const char *mount_path)
{
    const char *prefix = "/data/adb/modules/";
    size_t prefix_len = strlen(prefix);
    const char *p;
    const char *slash;
    size_t id_len;

    if (!mount_path || strncmp(mount_path, prefix, prefix_len) != 0)
        return NULL;

    p = mount_path + prefix_len;
    if (*p == '\0')
        return NULL;

    slash = strchr(p, '/');
    if (slash) {
        id_len = slash - p;
    } else {
        id_len = strlen(p);
    }

    if (id_len == 0 || id_len >= sizeof(g_module_id_buf))
        return NULL;

    strncpy(g_module_id_buf, p, id_len);
    g_module_id_buf[id_len] = '\0';
    return g_module_id_buf;
}

int ksu_set_excluded_modules(const char *const *module_ids, int count)
{
    int i;
    if (count < 0 || count > KSU_EXCLUDED_MODULES_MAX)
        return -EINVAL;

    excluded_modules_count = 0;

    for (i = 0; i < count; i++) {
        size_t len = strlen(module_ids[i]);
        if (len >= sizeof(excluded_modules[0]))
            len = sizeof(excluded_modules[0]) - 1;
        strncpy(excluded_modules[i], module_ids[i], sizeof(excluded_modules[0]) - 1);
        excluded_modules[i][sizeof(excluded_modules[0]) - 1] = '\0';
    }
    excluded_modules_count = count;

    pr_info("kernel_umount: excluded modules updated, count=%d\n", count);
    return 0;
}

int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
    // if there isn't any module mounted, just ignore it!
    if (!ksu_module_mounted) {
        return 0;
    }

    if (!ksu_kernel_umount_enabled) {
        return 0;
    }

    if (!ksu_cred) {
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
        if (excluded_modules_count > 0) {
            const char *module_id = ksu_extract_module_id_from_mount_path(entry->umountable);
            if (module_id && ksu_is_module_excluded(module_id)) {
                pr_info("ksu: skipping umount for excluded module: %s\n", module_id);
                continue;
            }
        }
        pr_info("%s: unmounting: %s flags: 0x%x\n", __func__, entry->umountable, entry->flags);
        try_umount(entry->umountable, entry->flags);
    }
    up_read(&mount_list_lock);

    revert_creds(saved);

    return 0;
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
}
