#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif

#ifdef CONFIG_KSU_SUSFS
#include <linux/namei.h>
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "supercalls.h"
#include "arch.h"
#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#ifdef CONFIG_KSU_SYSCALL_HOOK
#include "kp_hook.h"
#include "syscall_handler.h"
#endif
#include "kernel_compat.h"
#include "kernel_umount.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "objsec.h"
#include "file_wrapper.h"

#include "throne_comm.h"
#include "dynamic_manager.h"
#include "sulog.h"
#ifdef CONFIG_KSU_MANUAL_SU
#include "manual_su.h"
#endif

#ifdef CONFIG_KSU_SUSFS
bool susfs_is_boot_completed_triggered __read_mostly = false;
#endif // #ifdef CONFIG_KSU_SUSFS

bool ksu_uid_scanner_enabled = false;

// Permission check functions
bool only_manager(void)
{
	return is_manager();
}

bool only_root(void)
{
	return current_uid().val == 0;
}

bool manager_or_root(void)
{
	return current_uid().val == 0 || is_manager();
}

bool always_allow(void)
{
	return true; // No permission check
}

bool allowed_for_su(void)
{
	bool is_allowed =
		is_manager() || ksu_is_allow_uid_for_current(current_uid().val);
#if __SULOG_GATE
	ksu_sulog_report_permission_check(current_uid().val, current->comm, is_allowed);
#endif
	return is_allowed;
}

static void init_uid_scanner(void)
{
	ksu_throne_comm_load_state();	
	if (ksu_uid_scanner_enabled) {
		int ret = ksu_throne_comm_init();
		if (ret != 0) {
			pr_err("Failed to initialize throne communication: %d\n", ret);
		}
	}
}

static int do_grant_root(void __user *arg)
{
	// we already check uid above on allowed_for_su()

	pr_info("allow root for: %d\n", current_uid().val);
	escape_with_root_profile();

	return 0;
}

static int do_get_info(void __user *arg)
{
	struct ksu_get_info_cmd cmd = { .version = KERNEL_SU_VERSION,
					.flags = 0 };

#ifdef MODULE
	cmd.flags |= 0x1;
#endif

	if (is_manager()) {
		cmd.flags |= 0x2;
	}
	cmd.features = KSU_FEATURE_MAX;

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_report_event(void __user *arg)
{
	struct ksu_report_event_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	switch (cmd.event) {
	case EVENT_POST_FS_DATA: {
		static bool post_fs_data_lock = false;
		if (!post_fs_data_lock) {
			post_fs_data_lock = true;
			pr_info("post-fs-data triggered\n");
			on_post_fs_data();
			init_uid_scanner();
#if __SULOG_GATE	
			ksu_sulog_init();
#endif
			ksu_dynamic_manager_init();
		}
		break;
	}
	case EVENT_BOOT_COMPLETED: {
		static bool boot_complete_lock = false;
		if (!boot_complete_lock) {
			boot_complete_lock = true;
			pr_info("boot_complete triggered\n");
			on_boot_completed();
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
			susfs_is_boot_completed_triggered = true;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		}
		break;
	}
	case EVENT_MODULE_MOUNTED: {
		pr_info("module mounted!\n");
		on_module_mounted();
		break;
	}
	default:
		break;
	}

	return 0;
}

static int do_set_sepolicy(void __user *arg)
{
	struct ksu_set_sepolicy_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	return handle_sepolicy(cmd.cmd, (void __user *)cmd.arg);
}

static int do_check_safemode(void __user *arg)
{
	struct ksu_check_safemode_cmd cmd;

	cmd.in_safe_mode = ksu_is_safe_mode();

	if (cmd.in_safe_mode) {
		pr_warn("safemode enabled!\n");
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("check_safemode: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_allow_list(void __user *arg)
{
	struct ksu_get_allow_list_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	bool success =
		ksu_get_allow_list((int *)cmd.uids, (int *)&cmd.count, true);

	if (!success) {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_allow_list: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_deny_list(void __user *arg)
{
	struct ksu_get_allow_list_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	bool success =
		ksu_get_allow_list((int *)cmd.uids, (int *)&cmd.count, false);

	if (!success) {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_deny_list: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_uid_granted_root(void __user *arg)
{
	struct ksu_uid_granted_root_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.granted = ksu_is_allow_uid_for_current(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_granted_root: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_uid_should_umount(void __user *arg)
{
	struct ksu_uid_should_umount_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.should_umount = ksu_uid_should_umount(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_should_umount: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_manager_appid(void __user *arg)
{
	struct ksu_get_manager_appid_cmd cmd;

	cmd.appid = ksu_get_manager_appid();

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_manager_appid: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_app_profile(void __user *arg)
{
	struct ksu_get_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_get_app_profile(&cmd.profile)) {
		return -ENOENT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_app_profile: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_app_profile(void __user *arg)
{
	struct ksu_set_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_set_app_profile(&cmd.profile, true)) {
#if __SULOG_GATE
			ksu_sulog_report_manager_operation("SET_APP_PROFILE", 
				current_uid().val, cmd.profile.current_uid);
#endif
		return -EFAULT;
	}

	return 0;
}

static int do_get_feature(void __user *arg)
{
	struct ksu_get_feature_cmd cmd;
	bool supported;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_feature: copy_from_user failed\n");
		return -EFAULT;
	}

	ret = ksu_get_feature(cmd.feature_id, &cmd.value, &supported);
	cmd.supported = supported ? 1 : 0;

	if (ret && supported) {
		pr_err("get_feature: failed for feature %u: %d\n",
			   cmd.feature_id, ret);
		return ret;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_feature: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_feature(void __user *arg)
{
	struct ksu_set_feature_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_feature: copy_from_user failed\n");
		return -EFAULT;
	}

	ret = ksu_set_feature(cmd.feature_id, cmd.value);
	if (ret) {
		pr_err("set_feature: failed for feature %u: %d\n",
			   cmd.feature_id, ret);
		return ret;
	}

	return 0;
}

// kcompat for older kernel
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define getfd_secure anon_inode_create_getfd
#elif defined(KSU_HAS_GETFD_SECURE)
#define getfd_secure anon_inode_getfd_secure
#else
// technically not a secure inode, but, this is the only way so.
#define getfd_secure(name, ops, data, flags, __unused)						 \
	anon_inode_getfd(name, ops, data, flags)
#endif

static int do_get_wrapper_fd(void __user *arg)
{
	if (!ksu_file_sid) {
		return -EINVAL;
	}

	struct ksu_get_wrapper_fd_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_wrapper_fd: copy_from_user failed\n");
		return -EFAULT;
	}

	struct file *f = fget(cmd.fd);
	if (!f) {
		return -EBADF;
	}

	struct ksu_file_wrapper *data = ksu_create_file_wrapper(f);
	if (data == NULL) {
		ret = -ENOMEM;
		goto put_orig_file;
	}

	ret = getfd_secure("[ksu_fdwrapper]", &data->ops, data, f->f_flags,
			   NULL);
	if (ret < 0) {
		pr_err("ksu_fdwrapper: getfd failed: %d\n", ret);
		goto put_wrapper_data;
	}
	struct file *pf = fget(ret);

	struct inode *wrapper_inode = file_inode(pf);
	// copy original inode mode
	wrapper_inode->i_mode = file_inode(f)->i_mode;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0) ||						   \
	defined(KSU_OPTIONAL_SELINUX_INODE)
	struct inode_security_struct *sec = selinux_inode(wrapper_inode);
#else
	struct inode_security_struct *sec =
		(struct inode_security_struct *)wrapper_inode->i_security;
#endif

	if (sec) {
		sec->sid = ksu_file_sid;
	}

	fput(pf);
	goto put_orig_file;
put_wrapper_data:
	ksu_delete_file_wrapper(data);
put_orig_file:
	fput(f);

	return ret;
}

static int do_manage_mark(void __user *arg)
{
#if defined(CONFIG_KSU_SYSCALL_HOOK) || defined(CONFIG_KSU_SUSFS)
	struct ksu_manage_mark_cmd cmd;
#ifndef CONFIG_KSU_SUSFS
	int ret = 0;
#endif

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("manage_mark: copy_from_user failed\n");
		return -EFAULT;
	}

	switch (cmd.operation) {
	case KSU_MARK_GET: {
#ifndef CONFIG_KSU_SUSFS
		// Get task mark status
		ret = ksu_get_task_mark(cmd.pid);
		if (ret < 0) {
			pr_err("manage_mark: get failed for pid %d: %d\n",
				   cmd.pid, ret);
			return ret;
		}
		cmd.result = (u32)ret;
		break;
#else
        cmd.result = 0;
        break;
#endif // #ifndef CONFIG_KSU_SUSFS
	}
	case KSU_MARK_MARK: {
#ifndef CONFIG_KSU_SUSFS
		if (cmd.pid == 0) {
			ksu_mark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, true);
			if (ret < 0) {
				pr_err("manage_mark: set_mark failed for pid %d: %d\n",
					   cmd.pid, ret);
				return ret;
			}
		}
		break;
#else
        cmd.result = 0;
        break;
#endif // #ifndef CONFIG_KSU_SUSFS
	}
	case KSU_MARK_UNMARK: {
#ifndef CONFIG_KSU_SUSFS
		if (cmd.pid == 0) {
			ksu_unmark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, false);
			if (ret < 0) {
				pr_err("manage_mark: set_unmark failed for pid %d: %d\n",
					   cmd.pid, ret);
				return ret;
			}
		}
		break;
#else
        cmd.result = 0;
        break;
#endif // #ifndef CONFIG_KSU_SUSFS
	}
	case KSU_MARK_REFRESH: {
#ifndef CONFIG_KSU_SUSFS
		ksu_mark_running_process();
		pr_info("manage_mark: refreshed running processes\n");
		break;
#else
		pr_info("susfs: cmd: KSU_MARK_REFRESH: do nothing\n");
		break;
#endif // #ifndef CONFIG_KSU_SUSFS
	}
	default: {
		pr_err("manage_mark: invalid operation %u\n", cmd.operation);
		return -EINVAL;
	}
	}
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("manage_mark: copy_to_user failed\n");
		return -EFAULT;
	}
	return 0;
#else
	// We don't care, just return -ENOTSUPP
	pr_warn("manage_mark: this supercalls is not implemented for manual hook.\n");
	return -ENOTSUPP;
#endif
}

struct list_head mount_list = LIST_HEAD_INIT(mount_list);
DECLARE_RWSEM(mount_list_lock);

static int add_try_umount(void __user *arg)
{
	struct mount_entry *new_entry, *entry, *tmp;
	struct ksu_add_try_umount_cmd cmd;
	char buf[256] = { 0 };

	if (copy_from_user(&cmd, arg, sizeof cmd))
		return -EFAULT;

	switch (cmd.mode) {
	case KSU_UMOUNT_WIPE: {
		struct mount_entry *entry, *tmp;
		down_write(&mount_list_lock);
		list_for_each_entry_safe (entry, tmp, &mount_list, list) {
			pr_info("wipe_umount_list: removing entry: %s\n",
				entry->umountable);
			list_del(&entry->list);
			kfree(entry->umountable);
			kfree(entry);
		}
		up_write(&mount_list_lock);

		return 0;
	}

	case KSU_UMOUNT_ADD: {
		long len = strncpy_from_user(buf, (const char __user *)cmd.arg,
						 256);
		if (len <= 0)
			return -EFAULT;

		buf[sizeof(buf) - 1] = '\0';

		new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry)
			return -ENOMEM;

		new_entry->umountable = kstrdup(buf, GFP_KERNEL);
		if (!new_entry->umountable) {
			kfree(new_entry);
			return -1;
		}

		down_write(&mount_list_lock);

		// disallow dupes
		// if this gets too many, we can consider moving this whole task to a kthread
		list_for_each_entry (entry, &mount_list, list) {
			if (!strcmp(entry->umountable, buf)) {
				pr_info("cmd_add_try_umount: %s is already here!\n",
					buf);
				up_write(&mount_list_lock);
				kfree(new_entry->umountable);
				kfree(new_entry);
				return -1;
			}
		}

		// now check flags and add
		// this also serves as a null check
		if (cmd.flags)
			new_entry->flags = cmd.flags;
		else
			new_entry->flags = 0;

		// debug
		list_add(&new_entry->list, &mount_list);
		up_write(&mount_list_lock);
		pr_info("cmd_add_try_umount: %s added!\n", buf);

		return 0;
	}

	// this is just strcmp'd wipe anyway
	case KSU_UMOUNT_DEL: {
		long len = strncpy_from_user(buf, (const char __user *)cmd.arg,
						 sizeof(buf) - 1);
		if (len <= 0)
			return -EFAULT;

		buf[sizeof(buf) - 1] = '\0';

		down_write(&mount_list_lock);
		list_for_each_entry_safe (entry, tmp, &mount_list, list) {
			if (!strcmp(entry->umountable, buf)) {
				pr_info("cmd_add_try_umount: entry removed: %s\n",
					entry->umountable);
				list_del(&entry->list);
				kfree(entry->umountable);
				kfree(entry);
			}
		}
		up_write(&mount_list_lock);

		return 0;
	}

	default: {
		pr_err("cmd_add_try_umount: invalid operation %u\n", cmd.mode);
		return -EINVAL;
	}

	} // switch(cmd.mode)

	return 0;
}

static int do_nuke_ext4_sysfs(void __user *arg)
{
	struct ksu_nuke_ext4_sysfs_cmd cmd;
	char mnt[256];
	long ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd)))
		return -EFAULT;

	if (!cmd.arg)
		return -EINVAL;

	memset(mnt, 0, sizeof(mnt));

	ret = strncpy_from_user(mnt, cmd.arg, sizeof(mnt));
	if (ret < 0) {
		pr_err("nuke ext4 copy mnt failed: %ld\n", ret);
		return -EFAULT; // 或者 return ret;
	}

	if (ret == sizeof(mnt)) {
		pr_err("nuke ext4 mnt path too long\n");
		return -ENAMETOOLONG;
	}

	pr_info("do_nuke_ext4_sysfs: %s\n", mnt);

	return nuke_ext4_sysfs(mnt);
}

static int list_try_umount(void __user *arg)
{
    struct ksu_list_try_umount_cmd cmd;
    struct mount_entry *entry;
    char *output_buf;
    size_t output_size;
    size_t offset = 0;
    int ret = 0;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    output_size = cmd.buf_size ? cmd.buf_size : 4096;

    if (!cmd.arg || output_size == 0)
        return -EINVAL;

    output_buf = kzalloc(output_size, GFP_KERNEL);
    if (!output_buf)
        return -ENOMEM;

    offset += snprintf(output_buf + offset, output_size - offset, "Mount Point\tFlags\n");
    offset += snprintf(output_buf + offset, output_size - offset, "----------\t-----\n");

    down_read(&mount_list_lock);
    list_for_each_entry(entry, &mount_list, list) {
        int written = snprintf(output_buf + offset, output_size - offset,
                               "%s\t%u\n", entry->umountable, entry->flags);
        if (written < 0) {
            ret = -EFAULT;
            break;
        }
        if (written >= (int)(output_size - offset)) {
            ret = -ENOSPC;
            break;
        }
        offset += written;
    }
    up_read(&mount_list_lock);

    if (ret == 0) {
        if (copy_to_user((void __user *)cmd.arg, output_buf, offset))
            ret = -EFAULT;
    }

    kfree(output_buf);
    return ret;
}

// 100. GET_FULL_VERSION - Get full version string
static int do_get_full_version(void __user *arg)
{
	struct ksu_get_full_version_cmd cmd = {0};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	strscpy(cmd.version_full, KSU_VERSION_FULL, sizeof(cmd.version_full));
#else
	strlcpy(cmd.version_full, KSU_VERSION_FULL, sizeof(cmd.version_full));
#endif

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_full_version: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

// 101. HOOK_TYPE - Get hook type
static int do_get_hook_type(void __user *arg)
{
	struct ksu_hook_type_cmd cmd = {0};
	const char *type = "Tracepoint";
	
#if defined(CONFIG_KSU_MANUAL_HOOK)
	type = "Manual";
#elif defined(CONFIG_KSU_SUSFS)
	type = "Inline";
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	strscpy(cmd.hook_type, type, sizeof(cmd.hook_type));
#else
	strlcpy(cmd.hook_type, type, sizeof(cmd.hook_type));
#endif

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_hook_type: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

// 102. ENABLE_KPM - Check if KPM is enabled
static int do_enable_kpm(void __user *arg)
{
	struct ksu_enable_kpm_cmd cmd;
	
	cmd.enabled = IS_ENABLED(CONFIG_KPM);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("enable_kpm: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_dynamic_manager(void __user *arg)
{
	struct ksu_dynamic_manager_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("dynamic_manager: copy_from_user failed\n");
		return -EFAULT;
	}

	int ret = ksu_handle_dynamic_manager(&cmd.config);
	if (ret)
		return ret;

	if (cmd.config.operation == DYNAMIC_MANAGER_OP_GET && 
		copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("dynamic_manager: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_managers(void __user *arg)
{
	struct ksu_get_managers_cmd cmd;

	int ret = ksu_get_active_managers(&cmd.manager_info);
	if (ret)
		return ret;

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_managers: copy_from_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_enable_uid_scanner(void __user *arg)
{
	struct ksu_enable_uid_scanner_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("enable_uid_scanner: copy_from_user failed\n");
		return -EFAULT;
	}

	switch (cmd.operation) {
		case UID_SCANNER_OP_GET_STATUS: {
			bool status = ksu_uid_scanner_enabled;
			if (copy_to_user((void __user *)cmd.status_ptr, &status, sizeof(status))) {
				pr_err("enable_uid_scanner: copy status failed\n");
				return -EFAULT;
			}
			break;
		}
		case UID_SCANNER_OP_TOGGLE: {
			bool enabled = cmd.enabled;

			if (enabled == ksu_uid_scanner_enabled) {
				pr_info("enable_uid_scanner: no need to change, already %s\n",
					enabled ? "enabled" : "disabled");
				break;
			}

			if (enabled) {
				// Enable UID scanner
				int ret = ksu_throne_comm_init();
				if (ret != 0) {
					pr_err("enable_uid_scanner: failed to initialize: %d\n", ret);
					return -EFAULT;
				}
				pr_info("enable_uid_scanner: enabled\n");
			} else {
				// Disable UID scanner
				ksu_throne_comm_exit();
				pr_info("enable_uid_scanner: disabled\n");
			}

			ksu_uid_scanner_enabled = enabled;
			ksu_throne_comm_save_state();
			break;
		}
		case UID_SCANNER_OP_CLEAR_ENV: {
			// Clear environment (force exit)
			ksu_throne_comm_exit();
			ksu_uid_scanner_enabled = false;
			ksu_throne_comm_save_state();
			pr_info("enable_uid_scanner: environment cleared\n");
			break;
		}
		default:
			pr_err("enable_uid_scanner: invalid operation\n");
			return -EINVAL;
	}

	return 0;
}

#ifdef CONFIG_KSU_MANUAL_SU
static bool system_uid_check(void)
{
	return current_uid().val <= 2000;
}

static int do_manual_su(void __user *arg)
{
	struct ksu_manual_su_cmd cmd;
	struct manual_su_request request;
	int res;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("manual_su: copy_from_user failed\n");
		return -EFAULT;
	}

	pr_info("manual_su request, option=%d, uid=%d, pid=%d\n",
			cmd.option, cmd.target_uid, cmd.target_pid);

	memset(&request, 0, sizeof(request));
	request.target_uid = cmd.target_uid;
	request.target_pid = cmd.target_pid;

	if (cmd.option == MANUAL_SU_OP_GENERATE_TOKEN ||
		cmd.option == MANUAL_SU_OP_ESCALATE) {
		memcpy(request.token_buffer, cmd.token_buffer, sizeof(request.token_buffer));
	}

	res = ksu_handle_manual_su_request(cmd.option, &request);

	if (cmd.option == MANUAL_SU_OP_GENERATE_TOKEN && res == 0) {
		memcpy(cmd.token_buffer, request.token_buffer, sizeof(cmd.token_buffer));
		if (copy_to_user(arg, &cmd, sizeof(cmd))) {
			pr_err("manual_su: copy_to_user failed\n");
			return -EFAULT;
		}
	}

	return res;
}
#endif

// IOCTL handlers mapping table
static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[] = {
	KSU_IOCTL(GRANT_ROOT, "GRANT_ROOT", do_grant_root, allowed_for_su),
	KSU_IOCTL(GET_INFO, "GET_INFO", do_get_info, always_allow),
	KSU_IOCTL(REPORT_EVENT, "REPORT_EVENT", do_report_event, only_root),
	KSU_IOCTL(SET_SEPOLICY, "SET_SEPOLICY", do_set_sepolicy, only_root),
	KSU_IOCTL(CHECK_SAFEMODE, "CHECK_SAFEMODE", do_check_safemode,
		  always_allow),
	KSU_IOCTL(GET_ALLOW_LIST, "GET_ALLOW_LIST", do_get_allow_list,
		  manager_or_root),
	KSU_IOCTL(GET_DENY_LIST, "GET_DENY_LIST", do_get_deny_list,
		  manager_or_root),
	KSU_IOCTL(UID_GRANTED_ROOT, "UID_GRANTED_ROOT", do_uid_granted_root,
		  manager_or_root),
	KSU_IOCTL(UID_SHOULD_UMOUNT, "UID_SHOULD_UMOUNT", do_uid_should_umount,
		  manager_or_root),
	KSU_IOCTL(GET_MANAGER_APPID, "GET_MANAGER_UID", do_get_manager_appid,
		  manager_or_root),
	KSU_IOCTL(GET_APP_PROFILE, "GET_APP_PROFILE", do_get_app_profile,
		  only_manager),
	KSU_IOCTL(SET_APP_PROFILE, "SET_APP_PROFILE", do_set_app_profile,
		  only_manager),
	KSU_IOCTL(GET_FEATURE, "GET_FEATURE", do_get_feature, manager_or_root),
	KSU_IOCTL(SET_FEATURE, "SET_FEATURE", do_set_feature, manager_or_root),
	KSU_IOCTL(GET_WRAPPER_FD, "GET_WRAPPER_FD", do_get_wrapper_fd,
		  manager_or_root),
	KSU_IOCTL(MANAGE_MARK, "MANAGE_MARK", do_manage_mark, manager_or_root),
	KSU_IOCTL(NUKE_EXT4_SYSFS, "NUKE_EXT4_SYSFS", do_nuke_ext4_sysfs,
		  manager_or_root),
	KSU_IOCTL(ADD_TRY_UMOUNT, "ADD_TRY_UMOUNT", add_try_umount,
		  manager_or_root),
	KSU_IOCTL(GET_FULL_VERSION, "GET_FULL_VERSION", do_get_full_version,
		  always_allow),
	KSU_IOCTL(HOOK_TYPE, "GET_HOOK_TYPE", do_get_hook_type,
		  manager_or_root),
	KSU_IOCTL(ENABLE_KPM, "GET_ENABLE_KPM", do_enable_kpm,
		  manager_or_root),
	KSU_IOCTL(DYNAMIC_MANAGER, "SET_DYNAMIC_MANAGER", do_dynamic_manager,
		  manager_or_root),
	KSU_IOCTL(GET_MANAGERS, "GET_MANAGERS", do_get_managers,
		  manager_or_root),
	KSU_IOCTL(ENABLE_UID_SCANNER, "SET_ENABLE_UID_SCANNER", do_enable_uid_scanner,
		  manager_or_root),
#ifdef CONFIG_KSU_MANUAL_SU
	KSU_IOCTL(MANUAL_SU, "MANUAL_SU", do_manual_su,
		  system_uid_check),
#endif
#ifdef CONFIG_KPM
	KSU_IOCTL(KPM, "KPM_OPERATION", do_kpm,
		  manager_or_root),
#endif
	KSU_IOCTL(LIST_TRY_UMOUNT, "LIST_TRY_UMOUNT", list_try_umount,
		  manager_or_root),
	// Sentinel
	{ .cmd = 0, .name = NULL, .handler = NULL, .perm_check = NULL }
};

struct ksu_install_fd_tw {
	struct callback_head cb;
	int __user *outp;
};

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
	struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
	int fd = ksu_install_fd();

	if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
		pr_err("install ksu fd reply err\n");
		do_close_fd(fd);
	}

	kfree(tw);
}

static int ksu_handle_fd_request(void __user *arg)
{
	struct ksu_install_fd_tw *tw;

	tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;

	tw->outp = (int __user *)arg;
	tw->cb.func = ksu_install_fd_tw_func;

	if (task_work_add(current, &tw->cb, TWA_RESUME)) {
		kfree(tw);
		pr_warn("install fd add task_work failed\n");
	}

	return 0;
}

#ifndef CONFIG_KSU_SUSFS
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
			  void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;

#ifdef CONFIG_KSU_DEBUG
	pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1,
		magic2);
#endif

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		return ksu_handle_fd_request((void __user *)*arg);
	}

	return 0;
}

#else
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1) {
		return -EINVAL; 
	}

	// If magic2 is susfs and current process is root
	if (magic2 == SUSFS_MAGIC && current_uid().val == 0) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		if (cmd == CMD_SUSFS_ADD_SUS_PATH) {
			susfs_add_sus_path(arg);
			return 0;
		}
		if (cmd == CMD_SUSFS_ADD_SUS_PATH_LOOP) {
			susfs_add_sus_path_loop(arg);
			return 0;
		}
		if (cmd == CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH) {
			susfs_set_i_state_on_external_dir(arg);
			return 0;
		}
		if (cmd == CMD_SUSFS_SET_SDCARD_ROOT_PATH) {
			susfs_set_i_state_on_external_dir(arg);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		if (cmd == CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS) {
			susfs_set_hide_sus_mnts_for_all_procs(arg);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		if (cmd == CMD_SUSFS_ADD_SUS_KSTAT) {
			susfs_add_sus_kstat(arg);
			return 0;
		}
		if (cmd == CMD_SUSFS_UPDATE_SUS_KSTAT) {
			susfs_update_sus_kstat(arg);
			return 0;
		}
		if (cmd == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
			susfs_add_sus_kstat(arg);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		if (cmd == CMD_SUSFS_SET_UNAME) {
			susfs_set_uname(arg);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		if (cmd == CMD_SUSFS_ENABLE_LOG) {
			susfs_enable_log(arg);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		if (cmd == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
			susfs_set_cmdline_or_bootconfig(arg);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		if (cmd == CMD_SUSFS_ADD_OPEN_REDIRECT) {
			susfs_add_open_redirect(arg);
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
		if (cmd == CMD_SUSFS_ADD_SUS_MAP) {
			susfs_add_sus_map(arg);
			return 0;
		}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP
		if (cmd == CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING) {
			susfs_set_avc_log_spoofing(arg);
			return 0;
		}
		if (cmd == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
			susfs_get_enabled_features(arg);
			return 0;
		}
		if (cmd == CMD_SUSFS_SHOW_VARIANT) {
			susfs_show_variant(arg);
			return 0;
		}
		if (cmd == CMD_SUSFS_SHOW_VERSION) {
			susfs_show_version(arg);
			return 0;
		}
		return 0;
	}

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		return ksu_handle_fd_request((void __user *)*arg);
	}
	return 0;
}
#endif // #ifndef CONFIG_KSU_SUSFS

void ksu_supercalls_init(void)
{
	int i;

	pr_info("KernelSU IOCTL Commands:\n");
	for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
		pr_info("  %-18s = 0x%08x\n", ksu_ioctl_handlers[i].name,
			ksu_ioctl_handlers[i].cmd);
	}
#ifdef CONFIG_KSU_SYSCALL_HOOK
	kp_handle_supercalls_init();
#endif
}

void ksu_supercalls_exit(void)
{
#ifdef CONFIG_KSU_SYSCALL_HOOK
	kp_handle_supercalls_exit();
#endif
}

static inline void ksu_ioctl_audit(unsigned int cmd, const char *cmd_name, uid_t uid, int ret)
{
#if __SULOG_GATE
	const char *result = (ret == 0) ? "SUCCESS" :
						 (ret == -EPERM) ? "DENIED" : "FAILED";
	ksu_sulog_report_syscall(uid, NULL, cmd_name, result);
#endif
}

// IOCTL dispatcher
static long anon_ksu_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int i;

#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu ioctl: cmd=0x%x from uid=%d\n", cmd, current_uid().val);
#endif

	for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
		if (cmd == ksu_ioctl_handlers[i].cmd) {
			// Check permission first
			if (ksu_ioctl_handlers[i].perm_check &&
				!ksu_ioctl_handlers[i].perm_check()) {
				pr_warn("ksu ioctl: permission denied for cmd=0x%x uid=%d\n",
					cmd, current_uid().val);
				ksu_ioctl_audit(cmd, ksu_ioctl_handlers[i].name,
								current_uid().val, -EPERM);
				return -EPERM;
			}
			// Execute handler
			int ret = ksu_ioctl_handlers[i].handler(argp);
			ksu_ioctl_audit(cmd, ksu_ioctl_handlers[i].name,
							current_uid().val, ret);
			return ret;
		}
	}

	pr_warn("ksu ioctl: unsupported command 0x%x\n", cmd);
	return -ENOTTY;
}

// File release handler
static int anon_ksu_release(struct inode *inode, struct file *filp)
{
#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu fd released\n");
#endif
	return 0;
}

// File operations structure
static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

// Install KSU fd to current process
int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

	// Create anonymous inode file
	filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL,
				  O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
		pr_err("ksu_install_fd: failed to create anon inode file\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	// Install fd
	fd_install(fd, filp);

#if __SULOG_GATE
	ksu_sulog_report_permission_check(current_uid().val, current->comm, fd >= 0);
#endif

#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu fd[%d] installed for %s/%d\n", fd, current->comm,
		current->pid);
#endif

	return fd;
}
