#include <linux/version.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>


/*
 * Mount-view hiding.
 *
 * Two mount-based root probes are defeated here:
 *   1. A classic isolated process that inherits AID_READPROC (gid 3009) and reads
 *	  every process's /proc/<pid>/{mountinfo,mounts,mountstats} - it flags module
 *	  marker substrings AND a differential (distinct mount views vs propagation
 *	  classes).
 *   2. An Android 17 zygote_next native isolated process that reads its OWN
 *	  /proc/self/mountinfo but from init's GLOBAL namespace, where the module
 *	  mounts are still present.
 *
 * Implementation choice: this fork (SukiSU-Ultra) ships without
 * kernel/hook/patch_memory.h and the per-arch patch_memory.c implementations of
 * ksu_patch_text(), so the upstream design that rewrites the .open pointer of
 * proc_{mounts,mountinfo,mountstats}_operations is impossible here. We hook the
 * same point through the LSM framework that this fork already wires up via
 * kernel/hook/lsm_hook.c - the file_open LSM hook fires after VFS has resolved
 * the path and a fresh struct file is in place, but before the file is returned
 * to userspace, which is exactly when the upstream variant's ksu_*_open shim
 * runs. We refuse the open (-ENOENT) for hide targets so the file shows up as
 * "not present" and is consistent across mounts/mountinfo/mountstats (no
 * differential between the three). The kernel-side umount path
 * (feature/kernel_umount.c) is kept as-is for classic private-namespace apps;
 * this filter is complementary.
 *
 * HIDE DECISION.
 * ---------------------------------------------------------
 * (is_appuid || is_isolated) && (is_isolated || ksu_uid_should_umount)
 *
 * ksu_uid_should_umount already excludes the manager, su-granted apps and the
 * webview zygote, so those keep the real view. Isolated processes are always
 * filtered (they can never legitimately need the module view, and this is what
 * defeats the zygote_next global-namespace probe).
 *
 * "Isolated" means both ranges an isolated process can land in: the app-zygote
 * range [90000, 98999] and the regular one [99000, 99999]. is_isolated_process()
 * in policy/allowlist.h spans both, so the umount path and this filter agree on
 * who counts as isolated.
 */

static DEFINE_MUTEX(ksu_mount_hide_mutex);
static bool ksu_mount_hide_enabled __read_mostly = true;
static bool ksu_mount_hide_running __read_mostly = false;

#define KSU_PROC_MAGIC_NAME_MAX 32

static const char *const ksu_proc_magic_names[] = { "mountinfo", "mounts", "mountstats" };

static bool ksu_path_is_proc_mount_file(struct file *file)
{
	char buf[KSU_PROC_MAGIC_NAME_MAX];
	const char *name;
	size_t i;

	if (!file || !file->f_path.dentry)
		return false;

	name = file->f_path.dentry->d_name.name;
	if (!name)
		return false;

	for (i = 0; i < sizeof(buf) - 1; i++) {
		char c = name[i];

		buf[i] = c;
		if (!c)
			break;
	}
	buf[sizeof(buf) - 1] = '\0';

	for (i = 0; i < ARRAY_SIZE(ksu_proc_magic_names); i++) {
		if (!strcmp(buf, ksu_proc_magic_names[i]))
			return true;
	}
	return false;
}

static bool ksu_should_hide_mount_for_current(void)
{
	uid_t uid;
	bool isolated;

	if (!ksu_mount_hide_running)
		return false;
	if (!ksu_mount_hide_enabled)
		return false;

	uid = current_uid().val;
	isolated = is_isolated_process(uid);
	if (!is_appuid(uid) && !isolated)
		return false;
	if (!isolated && !ksu_uid_should_umount(uid))
		return false;

	return true;
}

int ksu_mount_hide_file_open(struct file *file)
{
	if (!ksu_should_hide_mount_for_current())
		return 0;
	if (!ksu_path_is_proc_mount_file(file))
		return 0;

	return -ENOENT;
}

static int mount_hide_feature_get(u64 *value)
{
	*value = ksu_mount_hide_enabled ? 1 : 0;
	return 0;
}

static int mount_hide_feature_set(u64 value)
{
	bool enable = value != 0;

	pr_info("mount_hide: set to %d\n", enable);
	mutex_lock(&ksu_mount_hide_mutex);
	ksu_mount_hide_enabled = enable;
	mutex_unlock(&ksu_mount_hide_mutex);
	return 0;
}

static const struct ksu_feature_handler mount_hide_handler = {
	.feature_id = KSU_FEATURE_MOUNT_HIDE,
	.name = "mount_hide",
	.get_handler = mount_hide_feature_get,
	.set_handler = mount_hide_feature_set,
};

void __init ksu_mount_hide_init(void)
{
	if (ksu_register_feature_handler(&mount_hide_handler))
		pr_err("Failed to register mount_hide feature handler\n");

	mutex_lock(&ksu_mount_hide_mutex);
	ksu_mount_hide_running = true;
	mutex_unlock(&ksu_mount_hide_mutex);
}

void __exit ksu_mount_hide_exit(void)
{
	mutex_lock(&ksu_mount_hide_mutex);
	ksu_mount_hide_running = false;
	mutex_unlock(&ksu_mount_hide_mutex);
	ksu_unregister_feature_handler(KSU_FEATURE_MOUNT_HIDE);
}
