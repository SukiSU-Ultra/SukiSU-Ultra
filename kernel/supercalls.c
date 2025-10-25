#include "supercalls.h"

#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "manager.h"
#include "sulog.h"
#include "selinux/selinux.h"

#ifdef CONFIG_KSU_MANUAL_SU
#include "manual_su.h"
#endif

#ifdef CONFIG_KPM
#include "kpm/kpm.h"
#endif


// Forward declarations from core_hook.c
extern void escape_to_root(void);
extern void nuke_ext4_sysfs(void);
extern bool ksu_module_mounted;
extern int handle_sepolicy(unsigned long arg3, void __user *arg4);
extern void ksu_sucompat_init(void);
extern void ksu_sucompat_exit(void);

static bool ksu_su_compat_enabled = true;

// Permission check functions
bool perm_check_manager(void)
{
	return is_manager();
}

bool perm_check_root(void)
{
	return current_uid().val == 0;
}

bool perm_check_daemon(void)
{
	return is_daemon();
}

bool perm_check_daemon_or_manager(void)
{
	return is_daemon() || is_manager();
}

bool perm_check_basic(void)
{
	return current_uid().val == 0 || is_daemon() || is_manager();
}

bool perm_check_all(void)
{
	return true; // No permission check
}


// 1. BECOME_MANAGER - Verify manager identity
int do_become_manager(void __user *arg)
{
	if (!ksu_is_manager_uid_valid() ||
		ksu_get_manager_uid() != current_uid().val) {
		return -EPERM;
	}

	return 0;
}

// 2. BECOME_DAEMON - Register ksud daemon
int do_become_daemon(void __user *arg)
{
	struct ksu_become_daemon_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("become_daemon: copy_from_user failed\n");
		return -EFAULT;
	}

	cmd.token[64] = '\0';

	if (!ksu_verify_daemon_token(cmd.token)) {
		pr_err("become_daemon: invalid token\n");
		return -EINVAL;
	}

	ksu_set_daemon_pid(current->pid);
	pr_info("ksud daemon registered, pid: %d\n", current->pid);

	return 0;
}

// 3. GRANT_ROOT - Escalate to root privileges
int do_grant_root(void __user *arg)
{
	// Check if current UID is allowed
	bool is_allowed = is_manager() || ksu_is_allow_uid(current_uid().val);

	if (!is_allowed) {
		return -EPERM;
	}

	pr_info("allow root for: %d\n", current_uid().val);
	escape_to_root();

	return 0;
}

// 4. GET_VERSION - Get KernelSU version
int do_get_version(void __user *arg)
{
	struct ksu_get_version_cmd cmd;

	cmd.version = KERNEL_SU_VERSION;
	cmd.version_flags = 0;

#ifdef MODULE
	cmd.version_flags |= 0x1;
#endif

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

// 5. REPORT_EVENT - Report system events
int do_report_event(void __user *arg)
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
		}
		break;
	}
	case EVENT_BOOT_COMPLETED: {
		static bool boot_complete_lock = false;
		if (!boot_complete_lock) {
			boot_complete_lock = true;
			pr_info("boot_complete triggered\n");
		}
		break;
	}
	case EVENT_MODULE_MOUNTED: {
		ksu_module_mounted = true;
		pr_info("module mounted!\n");
		nuke_ext4_sysfs();
		break;
	}
	default:
		break;
	}

	return 0;
}

// 6. SET_SEPOLICY - Set SELinux policy
int do_set_sepolicy(void __user *arg)
{
	struct ksu_set_sepolicy_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	return handle_sepolicy(cmd.cmd, cmd.arg);
}

// 7. CHECK_SAFEMODE - Check if in safe mode
int do_check_safemode(void __user *arg)
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

// 8. GET_ALLOW_LIST - Get allowed UIDs
int do_get_allow_list(void __user *arg)
{
	struct ksu_get_allow_list_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	bool success = ksu_get_allow_list((int *)cmd.uids, (int *)&cmd.count, true);

	if (!success) {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_allow_list: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

// 9. GET_DENY_LIST - Get denied UIDs
int do_get_deny_list(void __user *arg)
{
	struct ksu_get_allow_list_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	bool success = ksu_get_allow_list((int *)cmd.uids, (int *)&cmd.count, false);

	if (!success) {
		return -EFAULT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_deny_list: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

// 10. UID_GRANTED_ROOT - Check if UID has root
int do_uid_granted_root(void __user *arg)
{
	struct ksu_uid_granted_root_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.granted = ksu_is_allow_uid(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_granted_root: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

// 11. UID_SHOULD_UMOUNT - Check if UID should umount
int do_uid_should_umount(void __user *arg)
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

// 12. GET_MANAGER_UID - Get manager UID
int do_get_manager_uid(void __user *arg)
{
	struct ksu_get_manager_uid_cmd cmd;

	cmd.uid = ksu_get_manager_uid();

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_manager_uid: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

// 13. SET_MANAGER_UID - Set manager UID
int do_set_manager_uid(void __user *arg)
{
	struct ksu_set_manager_uid_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_manager_uid: copy_from_user failed\n");
		return -EFAULT;
	}

	ksu_set_manager_uid(cmd.uid);
	pr_info("manager uid set to %d\n", cmd.uid);

	return 0;
}

// 14. GET_APP_PROFILE - Get app profile
int do_get_app_profile(void __user *arg)
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

// 15. SET_APP_PROFILE - Set app profile
int do_set_app_profile(void __user *arg)
{
	struct ksu_set_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_set_app_profile(&cmd.profile, true)) {
		return -EFAULT;
	}

	return 0;
}

// 16. IS_SU_ENABLED - Check if su compat is enabled
int do_is_su_enabled(void __user *arg)
{
	struct ksu_is_su_enabled_cmd cmd;

	cmd.enabled = ksu_su_compat_enabled;

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("is_su_enabled: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

// 17. ENABLE_SU - Enable/disable su compat
int do_enable_su(void __user *arg)
{
	struct ksu_enable_su_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("enable_su: copy_from_user failed\n");
		return -EFAULT;
	}

	if (cmd.enable == ksu_su_compat_enabled) {
		pr_info("enable_su: no need to change\n");
		return 0;
	}

	if (cmd.enable) {
		ksu_sucompat_init();
	} else {
		ksu_sucompat_exit();
	}

	ksu_su_compat_enabled = cmd.enable;

	return 0;
}

// 100. GET_FULL_VERSION - Get full version string
int do_get_full_version(void __user *arg)
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
int do_hook_type(void __user *arg)
{
	struct ksu_hook_type_cmd cmd;

#if defined(CONFIG_KSU_TRACEPOINT_HOOK)
	strncpy(cmd.hook_type, "Tracepoint", sizeof(cmd.hook_type) - 1);
#elif defined(CONFIG_KSU_MANUAL_HOOK)
	strncpy(cmd.hook_type, "Manual", sizeof(cmd.hook_type) - 1);
#else
	strncpy(cmd.hook_type, "Kprobes", sizeof(cmd.hook_type) - 1);
#endif

	cmd.hook_type[sizeof(cmd.hook_type) - 1] = '\0';

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("hook_type: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

// 102. ENABLE_KPM - Check if KPM is enabled
int do_enable_kpm(void __user *arg)
{
	struct ksu_enable_kpm_cmd cmd = {0};
	
	cmd.enabled = IS_ENABLED(CONFIG_KPM);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("enable_kpm: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

// IOCTL handlers mapping table
static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[] = {
	{ .cmd = KSU_IOCTL_BECOME_MANAGER, .handler = do_become_manager, .perm_check = perm_check_manager, .name = "become_manager" },
	{ .cmd = KSU_IOCTL_BECOME_DAEMON, .handler = do_become_daemon, .perm_check = perm_check_root, .name = "become_daemon" },
	{ .cmd = KSU_IOCTL_GRANT_ROOT, .handler = do_grant_root, .perm_check = perm_check_basic, .name = "grant_root" },
	{ .cmd = KSU_IOCTL_GET_VERSION, .handler = do_get_version, .perm_check = perm_check_all, .name = "get_version" },
	{ .cmd = KSU_IOCTL_REPORT_EVENT, .handler = do_report_event, .perm_check = perm_check_root, .name = "report_event" },
	{ .cmd = KSU_IOCTL_SET_SEPOLICY, .handler = do_set_sepolicy, .perm_check = perm_check_root, .name = "set_sepolicy" },
	{ .cmd = KSU_IOCTL_CHECK_SAFEMODE, .handler = do_check_safemode, .perm_check = perm_check_all, .name = "check_safemode" },
	{ .cmd = KSU_IOCTL_GET_ALLOW_LIST, .handler = do_get_allow_list, .perm_check = perm_check_basic, .name = "get_allow_list" },
	{ .cmd = KSU_IOCTL_GET_DENY_LIST, .handler = do_get_deny_list, .perm_check = perm_check_basic, .name = "get_deny_list" },
	{ .cmd = KSU_IOCTL_UID_GRANTED_ROOT, .handler = do_uid_granted_root, .perm_check = perm_check_basic, .name = "uid_granted_root" },
	{ .cmd = KSU_IOCTL_UID_SHOULD_UMOUNT, .handler = do_uid_should_umount, .perm_check = perm_check_basic, .name = "uid_should_umount" },
	{ .cmd = KSU_IOCTL_GET_MANAGER_UID, .handler = do_get_manager_uid, .perm_check = perm_check_basic, .name = "get_manager_uid" },
	{ .cmd = KSU_IOCTL_SET_MANAGER_UID, .handler = do_set_manager_uid, .perm_check = perm_check_daemon, .name = "set_manager_uid" },
	{ .cmd = KSU_IOCTL_GET_APP_PROFILE, .handler = do_get_app_profile, .perm_check = perm_check_daemon_or_manager, .name = "get_app_profile" },
	{ .cmd = KSU_IOCTL_SET_APP_PROFILE, .handler = do_set_app_profile, .perm_check = perm_check_daemon_or_manager, .name = "set_app_profile" },
	{ .cmd = KSU_IOCTL_IS_SU_ENABLED, .handler = do_is_su_enabled, .perm_check = perm_check_daemon_or_manager, .name = "is_su_enabled" },
	{ .cmd = KSU_IOCTL_ENABLE_SU, .handler = do_enable_su, .perm_check = perm_check_daemon_or_manager, .name = "enable_su" },
	{ .cmd = KSU_IOCTL_GET_FULL_VERSION, .handler = do_get_full_version, .perm_check = perm_check_daemon_or_manager, .name = "get_full_version" },
	{ .cmd = KSU_IOCTL_HOOK_TYPE, .handler = do_hook_type, .perm_check = perm_check_daemon_or_manager, .name = "hook_type" },
	{ .cmd = KSU_IOCTL_ENABLE_KPM, .handler = do_enable_kpm, .perm_check = perm_check_daemon_or_manager, .name = "enable_kpm" },
	{ .cmd = 0, .handler = NULL, .perm_check = NULL, .name = NULL } // Sentinel
};

// IOCTL dispatcher
static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int i;
	const char *cmd_name = "unknown";
	int ret = -ENOTTY;

#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu ioctl: cmd=0x%x from uid=%d\n", cmd, current_uid().val);
#endif

	// Determine the command name based on the cmd value
	for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
		if (cmd == ksu_ioctl_handlers[i].cmd) {
			cmd_name = ksu_ioctl_handlers[i].name;
			break;
		}
	}

#if __SULOG_GATE
	// Log the start of the ioctl command
	ksu_sulog_report_syscall(current_uid().val, NULL, cmd_name, "START");
#endif

	// Check permission first
	if (ksu_ioctl_handlers[i].perm_check &&
		!ksu_ioctl_handlers[i].perm_check()) {
			pr_warn("ksu ioctl: permission denied for cmd=0x%x uid=%d\n",
				cmd, current_uid().val);
#if __SULOG_GATE
			ksu_sulog_report_syscall(current_uid().val, NULL, cmd_name, "DENIED");
#endif
		return -EPERM;
	}

	// Execute handler
	ret = ksu_ioctl_handlers[i].handler(argp);

	// Log the result of the ioctl command
	if (ret == 0) {
#if __SULOG_GATE
		ksu_sulog_report_syscall(current_uid().val, NULL, cmd_name, "SUCCESS");
#endif
	} else {
#if __SULOG_GATE
		ksu_sulog_report_syscall(current_uid().val, NULL, cmd_name, "FAILED");
#endif
	}

	if (ksu_ioctl_handlers[i].handler == NULL) {
		pr_warn("ksu ioctl: unsupported command 0x%x\n", cmd);
		ret = -ENOTTY;
	}

	return ret;
}

// File release handler
static int anon_ksu_release(struct inode *inode, struct file *filp)
{
	pr_info("ksu fd released\n");
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
	filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
		pr_err("ksu_install_fd: failed to create anon inode file\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	// Install fd
	fd_install(fd, filp);

	pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);

	return fd;
}