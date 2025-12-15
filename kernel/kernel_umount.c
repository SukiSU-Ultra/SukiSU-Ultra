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
#ifndef KSU_HAS_PATH_UMOUNT
#include <linux/syscalls.h>
#endif

#include "kernel_umount.h"
#include "klog.h" // IWYU pragma: keep
#include "allowlist.h"
#include "kernel_compat.h"
#include "selinux/selinux.h"
#include "feature.h"
#include "ksud.h"
#include "ksu.h"

#include "sulog.h"

static bool ksu_kernel_umount_enabled = true;

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) ||                           \
	defined(KSU_HAS_PATH_UMOUNT)
extern int path_umount(struct path *path, int flags);
static int ksu_umount_mnt(const char *__never_use_mnt, struct path *path,
			  int flags)
{
	return path_umount(path, flags);
}
#else
static int ksu_sys_umount(const char *mnt, int flags)
{
	char __user *usermnt = (char __user *)mnt;
	mm_segment_t old_fs;
	int ret = 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	ret = ksys_umount(usermnt, flags);
#else
	ret = sys_umount(usermnt, flags); // cuz asmlinkage long sys##name
#endif
	set_fs(old_fs);
	return ret;
}
#define ksu_umount_mnt(mnt, __unused, flags)                                   \
	({                                                                     \
		path_put(__unused);                                            \
		ksu_sys_umount(mnt, flags);                                    \
	})

#endif

static void try_umount(const char *mnt, int flags)
{
	struct path path;
	int ret = 0;
	if (kern_path(mnt, 0, &path)) {
		return;
	}

	if (path.dentry != path.mnt->mnt_root) {
		// it is not root mountpoint, maybe umounted by others already.
		path_put(&path);
		return;
	}

	ret = ksu_umount_mnt(mnt, &path, flags);
	if (ret) {
		pr_info("%s: umounting %s (flags=0x%x) failed, err: %d\n",
			__func__, mnt, flags, ret);
	}
}

struct umount_tw {
	struct callback_head cb;
};

static void umount_tw_func(struct callback_head *cb)
{
	struct umount_tw *tw = container_of(cb, struct umount_tw, cb);
	const struct cred *saved = override_creds(ksu_cred);

	down_read(&mount_list_lock);
	struct mount_entry *entry;
	list_for_each_entry (entry, &mount_list, list) {
		pr_info("%s: unmounting: %s flags 0x%x\n", __func__,
			entry->umountable, entry->flags);
		try_umount(entry->umountable, entry->flags);
	}
	up_read(&mount_list_lock);

	revert_creds(saved);
	kfree(tw);
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

#ifndef CONFIG_KSU_SUSFS
	// There are 5 scenarios:
	// 1. Normal app: zygote -> appuid
	// 2. Isolated process forked from zygote: zygote -> isolated_process
	// 3. App zygote forked from zygote: zygote -> appuid
	// 4. Isolated process froked from app zygote: appuid -> isolated_process (already handled by 3)
	// 5. Isolated process froked from webview zygote (no need to handle, app cannot run custom code)
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
	bool is_zygote_child = is_zygote(get_current_cred());
	if (!is_zygote_child) {
		pr_info("handle umount ignore non zygote child: %d\n",
			current->pid);
		return 0;
	}
#endif // #ifndef CONFIG_KSU_SUSFS

	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

#if __SULOG_GATE
	ksu_sulog_report_syscall(new_uid, NULL, "setuid", NULL);
#endif

	struct umount_tw *tw;
	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;

	tw->cb.func = umount_tw_func;

	int err = task_work_add(current, &tw->cb, TWA_RESUME);
	if (err) {
		kfree(tw);
		pr_warn("unmount add task_work failed\n");
	}

	return 0;
}

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
