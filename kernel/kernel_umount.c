#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "manager.h"
#include "kernel_umount.h"
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"
#include "allowlist.h"
#include "selinux/selinux.h"
#include "feature.h"
#include "ksud.h"

#include "sulog.h"

#ifndef CONFIG_KSU_SUSFS
static bool ksu_kernel_umount_enabled = true;
#else
bool ksu_kernel_umount_enabled = true;
#endif

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

#ifdef CONFIG_KSU_SUSFS
extern bool susfs_is_mnt_devname_ksu(struct path *path);

#if defined(CONFIG_KSU_SUSFS_TRY_UMOUNT) && defined(CONFIG_KSU_SUSFS_ENABLE_LOG)
extern bool susfs_is_log_enabled;
#endif // #if defined(CONFIG_KSU_SUSFS_TRY_UMOUNT) && defined(CONFIG_KSU_SUSFS_ENABLE_LOG)
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
extern void susfs_try_umount(void);
#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
#endif // #ifdef CONFIG_KSU_SUSFS

static bool should_umount(struct path *path)
{
    if (!path) {
        return false;
    }
#ifdef CONFIG_KSU_SUSFS
    return susfs_is_mnt_devname_ksu(path);
#else

    if (current->nsproxy->mnt_ns == init_nsproxy.mnt_ns) {
        pr_info("ignore global mnt namespace process: %d\n", current_uid().val);
        return false;
    }

    if (path->mnt && path->mnt->mnt_sb && path->mnt->mnt_sb->s_type) {
        const char *fstype = path->mnt->mnt_sb->s_type->name;
        return strcmp(fstype, "overlay") == 0;
    }
    return false;
#endif // #ifdef CONFIG_KSU_SUSFS
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) || defined(KSU_HAS_PATH_UMOUNT)
static int ksu_path_umount(struct path *path, int flags)
{
    return path_umount(path, flags);
}
#define ksu_umount_mnt(__unused, path, flags)    (ksu_path_umount(path, flags))
#else
// TODO: Search a way to make this works without set_fs functions
static int ksu_sys_umount(const char *mnt, int flags)
{
    char __user *usermnt = (char __user *)mnt;
    mm_segment_t old_fs;
    int ret; // although asmlinkage long

    old_fs = get_fs();
    set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    ret = ksys_umount(usermnt, flags);
#else
    ret = sys_umount(usermnt, flags); // cuz asmlinkage long sys##name
#endif
    set_fs(old_fs);
    pr_info("%s was called, ret: %d\n", __func__, ret);
    return ret;
}

#define ksu_umount_mnt(mnt, __unused, flags)        \
    ({                        \
        int ret;                \
        path_put(__unused);            \
        ret = ksu_sys_umount(mnt, flags);    \
        ret;                    \
    })

#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
void try_umount(const char *mnt, bool check_mnt, int flags)
#else
static void try_umount(const char *mnt, bool check_mnt, int flags)
#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
{
    struct path path;
    int ret;
    int err = kern_path(mnt, 0, &path);
    if (err) {
        return;
    }

    if (path.dentry != path.mnt->mnt_root) {
        // it is not root mountpoint, maybe umounted by others already.
        path_put(&path);
        return;
    }

    // we are only interest in some specific mounts
    if (check_mnt && !should_umount(&path)) {
        path_put(&path);
        return;
    }

#if defined(CONFIG_KSU_SUSFS_TRY_UMOUNT) && defined(CONFIG_KSU_SUSFS_ENABLE_LOG)
    if (susfs_is_log_enabled) {
        pr_info("susfs: umounting '%s'\n", mnt);
    }
#endif // #if defined(CONFIG_KSU_SUSFS_TRY_UMOUNT) && defined(CONFIG_KSU_SUSFS_ENABLE_LOG)

    ret = ksu_umount_mnt(mnt, &path, flags);
    if (ret) {
#ifdef CONFIG_KSU_DEBUG
        pr_info("%s: path: %s, ret: %d\n", __func__, mnt, ret);
#endif
    }
}

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
void susfs_try_umount_all(void) {
    susfs_try_umount();
    try_umount("/odm", true, 0);
    try_umount("/system", true, 0);
    try_umount("/vendor", true, 0);
    try_umount("/product", true, 0);
    try_umount("/system_ext", true, 0);
    try_umount("/data/adb/modules", false, MNT_DETACH);
    try_umount("/debug_ramdisk", true, MNT_DETACH);
}
#endif // #ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT

#ifndef CONFIG_KSU_SUSFS
struct umount_tw {
    struct callback_head cb;
    const struct cred *old_cred;
};

static void umount_tw_func(struct callback_head *cb)
{
    struct umount_tw *tw = container_of(cb, struct umount_tw, cb);
    const struct cred *saved = NULL;
    if (tw->old_cred) {
        saved = override_creds(tw->old_cred);
    }

    // fixme: use `collect_mounts` and `iterate_mount` to iterate all mountpoint and
    // filter the mountpoint whose target is `/data/adb`
    try_umount("/odm", true, 0);
    try_umount("/system", true, 0);
    try_umount("/vendor", true, 0);
    try_umount("/product", true, 0);
    try_umount("/system_ext", true, 0);
    try_umount("/data/adb/modules", false, MNT_DETACH);
    // try umount ksu temp path
    try_umount("/debug_ramdisk", false, MNT_DETACH);

    if (saved)
        revert_creds(saved);

    if (tw->old_cred)
        put_cred(tw->old_cred);

    kfree(tw);
}

int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
    struct umount_tw *tw;

    // this hook is used for umounting overlayfs for some uid, if there isn't any module mounted, just ignore it!
    if (!ksu_module_mounted) {
        return 0;
    }

    if (!ksu_kernel_umount_enabled) {
        return 0;
    }

    // FIXME: isolated process which directly forks from zygote is not handled
    if (!is_appuid(new_uid)) {
        return 0;
    }

    if (!ksu_uid_should_umount(new_uid)) {
        return 0;
    }

    // check old process's selinux context, if it is not zygote, ignore it!
    // because some su apps may setuid to untrusted_app but they are in global mount namespace
    // when we umount for such process, that is a disaster!
    bool is_zygote_child = is_zygote(get_current_cred());
    if (!is_zygote_child) {
        pr_info("handle umount ignore non zygote child: %d\n", current->pid);
        return 0;
    }
#if __SULOG_GATE
    ksu_sulog_report_syscall(new_uid, NULL, "setuid", NULL);
#endif
    // umount the target mnt
    pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

    tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
    if (!tw)
        return 0;

    tw->old_cred = get_current_cred();
    tw->cb.func = umount_tw_func;

    int err = task_work_add(current, &tw->cb, TWA_RESUME);
    if (err) {
        if (tw->old_cred) {
            put_cred(tw->old_cred);
        }
        kfree(tw);
        pr_warn("unmount add task_work failed\n");
    }

    return 0;
}
#endif // #ifndef CONFIG_KSU_SUSFS

void ksu_kernel_umount_init(void)
{
    if (ksu_register_feature_handler(&kernel_umount_handler)) {
        pr_err("Failed to register kernel_umount feature handler\n");
    }
}

void ksu_kernel_umount_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
}