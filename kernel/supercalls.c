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
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "manager.h"
#include "sulog.h"
#include "selinux/selinux.h"
#include "kernel_compat.h"
#include "throne_comm.h"
#include "dynamic_manager.h"

#ifdef CONFIG_KSU_MANUAL_SU
#include "manual_su.h"
#endif

// Forward declarations from core_hook.c
extern void escape_to_root(void);
extern void nuke_ext4_sysfs(void);
extern bool ksu_module_mounted;
extern int handle_sepolicy(unsigned long arg3, void __user *arg4);
extern void ksu_sucompat_init(void);
extern void ksu_sucompat_exit(void);

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

static void init_uid_scanner(void)
{
    ksu_uid_init();
    do_load_throne_state(NULL);
    
    if (ksu_uid_scanner_enabled) {
        int ret = ksu_throne_comm_init();
        if (ret != 0) {
            pr_err("Failed to initialize throne communication: %d\n", ret);
        }
    }
}

void ksu_handle_reboot(int magic1, int magic2, void __user * arg) {
    if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
        int fd = ksu_install_fd();
        pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

        if (copy_to_user(arg, &fd, sizeof(fd))) {
            pr_err("install ksu fd reply err\n");
        }
    }
}

static int do_grant_root(void __user *arg)
{
    // Check if current UID is allowed
    bool is_allowed = is_manager() || ksu_is_allow_uid(current_uid().val);

#if __SULOG_GATE
	ksu_sulog_report_permission_check(current_uid().val, current->comm, is_allowed);
#endif

    if (!is_allowed) {
        return -EPERM;
    }

    pr_info("allow root for: %d\n", current_uid().val);
    escape_to_root();

    return 0;
}

static int do_get_info(void __user *arg)
{
    struct ksu_get_info_cmd cmd = {.version = KERNEL_SU_VERSION, .flags = 0};

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

static int do_get_deny_list(void __user *arg)
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

static int do_uid_granted_root(void __user *arg)
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

static int do_get_manager_uid(void __user *arg)
{
    struct ksu_get_manager_uid_cmd cmd;

    cmd.uid = ksu_get_manager_uid();

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        pr_err("get_manager_uid: copy_to_user failed\n");
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
        pr_err("get_feature: failed for feature %u: %d\n", cmd.feature_id, ret);
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
        pr_err("set_feature: failed for feature %u: %d\n", cmd.feature_id, ret);
        return ret;
    }

    return 0;
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
    const char *type = "Kprobes";

#if defined(CONFIG_KSU_TRACEPOINT_HOOK)
    type = "Tracepoint";
#elif defined(CONFIG_KSU_MANUAL_HOOK)
    type = "Manual";
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

// IOCTL handlers mapping table
static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[] = {
   { .cmd = KSU_IOCTL_GRANT_ROOT, .name = "GRANT_ROOT", .handler = do_grant_root, .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_INFO, .name = "GET_INFO", .handler = do_get_info, .perm_check = always_allow },
    { .cmd = KSU_IOCTL_REPORT_EVENT, .name = "REPORT_EVENT", .handler = do_report_event, .perm_check = only_root },
    { .cmd = KSU_IOCTL_SET_SEPOLICY, .name = "SET_SEPOLICY", .handler = do_set_sepolicy, .perm_check = only_root },
    { .cmd = KSU_IOCTL_CHECK_SAFEMODE, .name = "CHECK_SAFEMODE", .handler = do_check_safemode, .perm_check = always_allow },
    { .cmd = KSU_IOCTL_GET_ALLOW_LIST, .name = "GET_ALLOW_LIST", .handler = do_get_allow_list, .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_DENY_LIST, .name = "GET_DENY_LIST", .handler = do_get_deny_list, .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_UID_GRANTED_ROOT, .name = "UID_GRANTED_ROOT", .handler = do_uid_granted_root, .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_UID_SHOULD_UMOUNT, .name = "UID_SHOULD_UMOUNT", .handler = do_uid_should_umount, .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_MANAGER_UID, .name = "GET_MANAGER_UID", .handler = do_get_manager_uid, .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_APP_PROFILE, .name = "GET_APP_PROFILE", .handler = do_get_app_profile, .perm_check = only_manager },
    { .cmd = KSU_IOCTL_SET_APP_PROFILE, .name = "SET_APP_PROFILE", .handler = do_set_app_profile, .perm_check = only_manager },
    { .cmd = KSU_IOCTL_GET_FEATURE, .name = "GET_FEATURE", .handler = do_get_feature, .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_SET_FEATURE, .name = "SET_FEATURE", .handler = do_set_feature, .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_FULL_VERSION,.name = "GET_FULL_VERSION", .handler = do_get_full_version, .perm_check = always_allow},
    { .cmd = KSU_IOCTL_HOOK_TYPE,.name = "GET_HOOK_TYPE", .handler = do_get_hook_type, .perm_check = manager_or_root},
    { .cmd = KSU_IOCTL_ENABLE_KPM, .name = "GET_ENABLE_KPM", .handler = do_enable_kpm, .perm_check = manager_or_root},
    { .cmd = KSU_IOCTL_DYNAMIC_MANAGER, .name = "SET_DYNAMIC_MANAGER", .handler = do_dynamic_manager, .perm_check = manager_or_root},
    { .cmd = KSU_IOCTL_GET_MANAGERS, .name = "GET_MANAGERS", .handler = do_get_managers, .perm_check = manager_or_root},
    { .cmd = KSU_IOCTL_ENABLE_UID_SCANNER, .name = "SET_ENABLE_UID_SCANNER", .handler = do_enable_uid_scanner, .perm_check = manager_or_root},
#ifdef CONFIG_KPM
    { .cmd = KSU_IOCTL_KPM, .name = "KPM_OPERATION", .handler = do_kpm, .perm_check = manager_or_root},
#endif
    { .cmd = 0, .name = NULL, .handler = NULL, .perm_check = NULL} // Sentine
};

void ksu_supercalls_init(void)
{
    int i;

    pr_info("KernelSU IOCTL Commands:\n");
    for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
        pr_info("  %-18s = 0x%08x\n", ksu_ioctl_handlers[i].name, ksu_ioctl_handlers[i].cmd);
    }
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
static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
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

#if __SULOG_GATE
    ksu_sulog_report_permission_check(current_uid().val, current->comm, fd >= 0);
#endif

    pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);

    return fd;
}