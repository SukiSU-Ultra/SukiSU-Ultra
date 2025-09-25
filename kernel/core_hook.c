#include <linux/capability.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/mount.h>
#include <linux/binfmts.h>

#include <linux/fs.h>
#include <linux/namei.h>
#ifndef KSU_HAS_PATH_UMOUNT
#include <linux/syscalls.h> // sys_umount (<4.17) & ksys_umount (4.17+)
#endif

#ifdef MODULE
#include <linux/list.h>
#include <linux/irqflags.h>
#include <linux/mm_types.h>
#include <linux/rcupdate.h>
#include <linux/vmalloc.h>
#endif

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "allowlist.h"
#include "arch.h"
#include "core_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "throne_tracker.h"
#include "throne_comm.h"
#include "kernel_compat.h"
#include "dynamic_manager.h"

#ifdef CONFIG_KPM
#include "kpm/kpm.h"
#endif

#ifdef CONFIG_KSU_SUSFS
bool susfs_is_allow_su(void)
{
	if (is_manager()) {
		// we are manager, allow!
		return true;
	}
	return ksu_is_allow_uid(current_uid().val);
}

extern u32 susfs_zygote_sid;
extern bool susfs_is_mnt_devname_ksu(struct path *path);
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
extern void susfs_run_sus_path_loop(uid_t uid);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
extern bool susfs_is_log_enabled __read_mostly;
#endif // #ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
static bool susfs_is_umount_for_zygote_system_process_enabled = false;
static bool susfs_is_umount_for_zygote_iso_service_enabled = false;
extern bool susfs_hide_sus_mnts_for_all_procs;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
extern bool susfs_is_auto_add_sus_bind_mount_enabled;
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
extern bool susfs_is_auto_add_sus_ksu_default_mount_enabled;
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
extern bool susfs_is_auto_add_try_umount_for_bind_mount_enabled;
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_SU
extern bool susfs_is_sus_su_ready;
extern int susfs_sus_su_working_mode;
extern bool susfs_is_sus_su_hooks_enabled __read_mostly;
extern bool ksu_devpts_hook;
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_SU

static inline void susfs_on_post_fs_data(void) {
	struct path path;
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (!kern_path(DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS, 0, &path)) {
		susfs_is_umount_for_zygote_system_process_enabled = true;
		path_put(&path);
	}
	pr_info("susfs_is_umount_for_zygote_system_process_enabled: %d\n", susfs_is_umount_for_zygote_system_process_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT, 0, &path)) {
		susfs_is_auto_add_sus_bind_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_sus_bind_mount_enabled: %d\n", susfs_is_auto_add_sus_bind_mount_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT, 0, &path)) {
		susfs_is_auto_add_sus_ksu_default_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_sus_ksu_default_mount_enabled: %d\n", susfs_is_auto_add_sus_ksu_default_mount_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT, 0, &path)) {
		susfs_is_auto_add_try_umount_for_bind_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_try_umount_for_bind_mount_enabled: %d\n", susfs_is_auto_add_try_umount_for_bind_mount_enabled);
#endif // #ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
}
#endif // #ifdef CONFIG_KSU_SUSFS

static bool ksu_module_mounted = false;

extern int handle_sepolicy(unsigned long arg3, void __user *arg4);

bool ksu_su_compat_enabled = true;
extern void ksu_sucompat_init(void);
extern void ksu_sucompat_exit(void);

static inline bool is_allow_su(void)
{
	if (is_manager()) {
		// we are manager, allow!
		return true;
	}
	return ksu_is_allow_uid(current_uid().val);
}

static inline bool is_unsupported_uid(uid_t uid)
{
#define LAST_APPLICATION_UID 19999
	uid_t appid = uid % 100000;
	return appid > LAST_APPLICATION_UID;
}

static struct group_info root_groups = { .usage = ATOMIC_INIT(2) };

static void setup_groups(struct root_profile *profile, struct cred *cred)
{
	if (profile->groups_count > KSU_MAX_GROUPS) {
		pr_warn("Failed to setgroups, too large group: %d!\n",
			profile->uid);
		return;
	}

	if (profile->groups_count == 1 && profile->groups[0] == 0) {
		// setgroup to root and return early.
		if (cred->group_info)
			put_group_info(cred->group_info);
		cred->group_info = get_group_info(&root_groups);
		return;
	}

	u32 ngroups = profile->groups_count;
	struct group_info *group_info = groups_alloc(ngroups);
	if (!group_info) {
		pr_warn("Failed to setgroups, ENOMEM for: %d\n", profile->uid);
		return;
	}

	int i;
	for (i = 0; i < ngroups; i++) {
		gid_t gid = profile->groups[i];
		kgid_t kgid = make_kgid(current_user_ns(), gid);
		if (!gid_valid(kgid)) {
			pr_warn("Failed to setgroups, invalid gid: %d\n", gid);
			put_group_info(group_info);
			return;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
		group_info->gid[i] = kgid;
#else
		GROUP_AT(group_info, i) = kgid;
#endif
	}

	groups_sort(group_info);
	set_groups(cred, group_info);
	put_group_info(group_info);
}

static void disable_seccomp(struct task_struct *tsk)
{
	assert_spin_locked(&tsk->sighand->siglock);

	// disable seccomp
#if defined(CONFIG_GENERIC_ENTRY) &&                                           \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	current_thread_info()->syscall_work &= ~SYSCALL_WORK_SECCOMP;
#else
	current_thread_info()->flags &= ~(TIF_SECCOMP | _TIF_SECCOMP);
#endif

#ifdef CONFIG_SECCOMP
	tsk->seccomp.mode = 0;
	if (tsk->seccomp.filter) {
	// TODO: Add kernel 6.11+ support
	// 5.9+ have filter_count and use seccomp_filter_release
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
		seccomp_filter_release(tsk);
		atomic_set(&tsk->seccomp.filter_count, 0);
#else
		put_seccomp_filter(tsk);
		tsk->seccomp.filter = NULL;
#endif
	}
#endif
}

void escape_to_root(void)
{
	struct cred *newcreds;

	if (current_euid().val == 0) {
		pr_warn("Already root, don't escape!\n");
		return;
	}
	
	newcreds = prepare_creds();
	if (newcreds == NULL) {
		pr_err("%s: failed to allocate new cred.\n", __func__);
		return;
	}

	struct root_profile *profile =
		ksu_get_root_profile(newcreds->uid.val);

	newcreds->uid.val = profile->uid;
	newcreds->suid.val = profile->uid;
	newcreds->euid.val = profile->uid;
	newcreds->fsuid.val = profile->uid;

	newcreds->gid.val = profile->gid;
	newcreds->fsgid.val = profile->gid;
	newcreds->sgid.val = profile->gid;
	newcreds->egid.val = profile->gid;
	newcreds->securebits = 0;

	BUILD_BUG_ON(sizeof(profile->capabilities.effective) !=
		     sizeof(kernel_cap_t));

	// setup capabilities
	// we need CAP_DAC_READ_SEARCH becuase `/data/adb/ksud` is not accessible for non root process
	// we add it here but don't add it to cap_inhertiable, it would be dropped automaticly after exec!
	u64 cap_for_ksud =
		profile->capabilities.effective | CAP_DAC_READ_SEARCH;
	memcpy(&newcreds->cap_effective, &cap_for_ksud,
	       sizeof(newcreds->cap_effective));
	memcpy(&newcreds->cap_permitted, &profile->capabilities.effective,
	       sizeof(newcreds->cap_permitted));
	memcpy(&newcreds->cap_bset, &profile->capabilities.effective,
	       sizeof(newcreds->cap_bset));

	setup_groups(profile, newcreds);
	commit_creds(newcreds);

	spin_lock_irq(&current->sighand->siglock);
	disable_seccomp(current);
	spin_unlock_irq(&current->sighand->siglock);

	setup_selinux(profile->selinux_domain);
}

int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry)
{
	if (!current->mm) {
		// skip kernel threads
		return 0;
	}

	if (current_uid().val != 1000) {
		// skip non system uid
		return 0;
	}

	if (!old_dentry || !new_dentry) {
		return 0;
	}

	// /data/system/packages.list.tmp -> /data/system/packages.list
	if (strcmp(new_dentry->d_iname, "packages.list")) {
		return 0;
	}

	char path[128];
	char *buf = dentry_path_raw(new_dentry, path, sizeof(path));
	if (IS_ERR(buf)) {
		pr_err("dentry_path_raw failed.\n");
		return 0;
	}

	if (!strstr(buf, "/system/packages.list")) {
		return 0;
	}
	pr_info("renameat: %s -> %s, new path: %s\n", old_dentry->d_iname,
		new_dentry->d_iname, buf);

	track_throne();
	
	// Also request userspace scan for next time
	ksu_request_userspace_scan();

	return 0;
}

#ifdef CONFIG_EXT4_FS
static void nuke_ext4_sysfs(void) 
{
	struct path path;
	int err = kern_path("/data/adb/modules", 0, &path);
	if (err) {
		pr_err("nuke path err: %d\n", err);
		return;
	}

	struct super_block* sb = path.dentry->d_inode->i_sb;
	const char* name = sb->s_type->name;
	if (strcmp(name, "ext4") != 0) {
		pr_info("nuke but module aren't mounted\n");
		path_put(&path);
		return;
	}

	ext4_unregister_sysfs(sb);
 	path_put(&path);
}
#else
static inline void nuke_ext4_sysfs(void)
{
}
#endif

int ksu_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
		     unsigned long arg4, unsigned long arg5)
{
	// if success, we modify the arg5 as result!
	u32 *result = (u32 *)arg5;
	u32 reply_ok = KERNEL_SU_OPTION;

	if (KERNEL_SU_OPTION != option) {
		return 0;
	}

	// TODO: find it in throne tracker!
	uid_t current_uid_val = current_uid().val;
	uid_t manager_uid = ksu_get_manager_uid();
	if (current_uid_val != manager_uid &&
	    current_uid_val % 100000 == manager_uid) {
		ksu_set_manager_uid(current_uid_val);
	}

	bool from_root = 0 == current_uid().val;
	bool from_manager = is_manager();

	if (!from_root && !from_manager) {
		// only root or manager can access this interface
		return 0;
	}

#ifdef CONFIG_KSU_DEBUG
	pr_info("option: 0x%x, cmd: %ld\n", option, arg2);
#endif

	if (arg2 == CMD_BECOME_MANAGER) {
		if (from_manager) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("become_manager: prctl reply error\n");
			}
			return 0;
		}
		return 0;
	}

	if (arg2 == CMD_GRANT_ROOT) {
		if (is_allow_su()) {
			pr_info("allow root for: %d\n", current_uid().val);
			escape_to_root();
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("grant_root: prctl reply error\n");
			}
		}
		return 0;
	}

	// Both root manager and root processes should be allowed to get version
	if (arg2 == CMD_GET_VERSION) {
		u32 version = KERNEL_SU_VERSION;
		if (copy_to_user(arg3, &version, sizeof(version))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		u32 version_flags = 2;
#ifdef MODULE
		version_flags |= 0x1;
#endif
		if (arg4 &&
		    copy_to_user(arg4, &version_flags, sizeof(version_flags))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	// Allow root manager to get full version strings
	if (arg2 == CMD_GET_FULL_VERSION) {
		char ksu_version_full[KSU_FULL_VERSION_STRING] = {0};
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
		strscpy(ksu_version_full, KSU_VERSION_FULL, KSU_FULL_VERSION_STRING);
#else
		strlcpy(ksu_version_full, KSU_VERSION_FULL, KSU_FULL_VERSION_STRING);
#endif
		if (copy_to_user((void __user *)arg3, ksu_version_full, KSU_FULL_VERSION_STRING)) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
			return -EFAULT;
		}
		return 0;
	}

	// Allow the root manager to configure dynamic manageratures
	if (arg2 == CMD_DYNAMIC_MANAGER) {
    	if (!from_root && !from_manager) {
        	return 0;
    	}
    
    	struct dynamic_manager_user_config config;
    
    	if (copy_from_user(&config, (void __user *)arg3, sizeof(config))) {
        	pr_err("copy dynamic manager config failed\n");
        	return 0;
    	}
    
    	int ret = ksu_handle_dynamic_manager(&config);
    	
    	if (ret == 0 && config.operation == DYNAMIC_MANAGER_OP_GET) {
        	if (copy_to_user((void __user *)arg3, &config, sizeof(config))) {
            	pr_err("copy dynamic manager config back failed\n");
            	return 0;
        	}
    	}
    	
    	if (ret == 0) {
        	if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
            	pr_err("dynamic_manager: prctl reply error\n");
        	}
    	}
    	return 0;
	}

	// Allow root manager to get active managers
	if (arg2 == CMD_GET_MANAGERS) {
		if (!from_root && !from_manager) {
			return 0;
		}
		
		struct manager_list_info manager_info;
		int ret = ksu_get_active_managers(&manager_info);
		
		if (ret == 0) {
			if (copy_to_user((void __user *)arg3, &manager_info, sizeof(manager_info))) {
				pr_err("copy manager list failed\n");
				return 0;
			}
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("get_managers: prctl reply error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_REPORT_EVENT) {
		if (!from_root) {
			return 0;
		}
		switch (arg3) {
		case EVENT_POST_FS_DATA: {
			static bool post_fs_data_lock = false;
#ifdef CONFIG_KSU_SUSFS
			susfs_on_post_fs_data();
#endif
			if (!post_fs_data_lock) {
				post_fs_data_lock = true;
				pr_info("post-fs-data triggered\n");
				on_post_fs_data();
				// Initialize throne communication
				ksu_throne_comm_init();
				// Initializing Dynamic Signatures
        		ksu_dynamic_manager_init();
        		pr_info("Dynamic sign config loaded during post-fs-data\n");
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

	if (arg2 == CMD_SET_SEPOLICY) {
		if (!from_root) {
			return 0;
		}
		if (!handle_sepolicy(arg3, arg4)) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("sepolicy: prctl reply error\n");
			}
		}

		return 0;
	}

	if (arg2 == CMD_CHECK_SAFEMODE) {
		if (ksu_is_safe_mode()) {
			pr_warn("safemode enabled!\n");
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("safemode: prctl reply error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_GET_ALLOW_LIST || arg2 == CMD_GET_DENY_LIST) {
		u32 array[128];
		u32 array_length;
		bool success = ksu_get_allow_list(array, &array_length,
						  arg2 == CMD_GET_ALLOW_LIST);
		if (success) {
			if (!copy_to_user(arg4, &array_length,
					  sizeof(array_length)) &&
			    !copy_to_user(arg3, array,
					  sizeof(u32) * array_length)) {
				if (copy_to_user(result, &reply_ok,
						 sizeof(reply_ok))) {
					pr_err("prctl reply error, cmd: %lu\n",
					       arg2);
				}
			} else {
				pr_err("prctl copy allowlist error\n");
			}
		}
		return 0;
	}

	if (arg2 == CMD_UID_GRANTED_ROOT || arg2 == CMD_UID_SHOULD_UMOUNT) {
		uid_t target_uid = (uid_t)arg3;
		bool allow = false;
		if (arg2 == CMD_UID_GRANTED_ROOT) {
			allow = ksu_is_allow_uid(target_uid);
		} else if (arg2 == CMD_UID_SHOULD_UMOUNT) {
			allow = ksu_uid_should_umount(target_uid);
		} else {
			pr_err("unknown cmd: %lu\n", arg2);
		}
		if (!copy_to_user(arg4, &allow, sizeof(allow))) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
		} else {
			pr_err("prctl copy err, cmd: %lu\n", arg2);
		}
		return 0;
	}

#ifdef CONFIG_KPM
	// ADD: 添加KPM模块控制
	if(sukisu_is_kpm_control_code(arg2)) {
		int res;

		pr_info("KPM: calling before arg2=%d\n", (int) arg2);
		
		res = sukisu_handle_kpm(arg2, arg3, arg4, arg5);

		return 0;
	}
#endif

	// Check if kpm is enabled
	if (arg2 == CMD_ENABLE_KPM) {
    	bool KPM_Enabled = IS_ENABLED(CONFIG_KPM);
    	if (copy_to_user((void __user *)arg3, &KPM_Enabled, sizeof(KPM_Enabled)))
        	pr_info("KPM: copy_to_user() failed\n");
    	return 0;
	}

	// Checking hook usage
	if (arg2 == CMD_HOOK_TYPE) {
		const char *hook_type;
		
#if defined(CONFIG_KSU_KPROBES_HOOK)
		hook_type = "Kprobes";
#elif defined(CONFIG_KSU_TRACEPOINT_HOOK)
		hook_type = "Tracepoint";
#elif defined(CONFIG_KSU_MANUAL_HOOK)
		hook_type = "Manual";
#else
		hook_type = "Unknown";
#endif
		
		size_t len = strlen(hook_type) + 1;
		if (copy_to_user((void __user *)arg3, hook_type, len)) {
			pr_err("hook_type: copy_to_user failed\n");
			return 0;
		}
		
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("hook_type: prctl reply error\n");
		}
		return 0;
	}

	// Get SUSFS function status
	if (arg2 == CMD_GET_SUSFS_FEATURE_STATUS) {
    	struct susfs_feature_status status;
    
    	if (!ksu_access_ok((void __user*)arg3, sizeof(status))) {
        	pr_err("susfs_feature_status: arg3 is not accessible\n");
        	return 0;
    	}
    
    	init_susfs_feature_status(&status);
    
    	if (copy_to_user((void __user*)arg3, &status, sizeof(status))) {
        	pr_err("susfs_feature_status: copy_to_user failed\n");
        	return 0;
    	}
    
    	if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
        	pr_err("susfs_feature_status: prctl reply error\n");
    	}
    
    	pr_info("susfs_feature_status: successfully returned feature status\n");
    	return 0;
	}

#ifdef CONFIG_KSU_SUSFS
	if (current_uid_val == 0) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		if (arg2 == CMD_SUSFS_ADD_SUS_PATH) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(struct st_susfs_sus_path))) {
				pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_add_sus_path((struct st_susfs_sus_path __user*)arg3);
			pr_info("susfs: CMD_SUSFS_ADD_SUS_PATH -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
		if (arg2 == CMD_SUSFS_ADD_SUS_PATH_LOOP) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(struct st_susfs_sus_path))) {
				pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH_LOOP -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH_LOOP -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_add_sus_path_loop((struct st_susfs_sus_path __user*)arg3);
			pr_info("susfs: CMD_SUSFS_ADD_SUS_PATH_LOOP -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
		if (arg2 == CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, SUSFS_MAX_LEN_PATHNAME)) {
				pr_err("susfs: CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_set_i_state_on_external_dir((char __user*)arg3, CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH);
			pr_info("susfs: CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
		if (arg2 == CMD_SUSFS_SET_SDCARD_ROOT_PATH) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, SUSFS_MAX_LEN_PATHNAME)) {
				pr_err("susfs: CMD_SUSFS_SET_SDCARD_ROOT_PATH -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_SET_SDCARD_ROOT_PATH -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_set_i_state_on_external_dir((char __user*)arg3, CMD_SUSFS_SET_SDCARD_ROOT_PATH);
			pr_info("susfs: CMD_SUSFS_SET_SDCARD_ROOT_PATH -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		if (arg2 == CMD_SUSFS_ADD_SUS_MOUNT) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(struct st_susfs_sus_mount))) {
				pr_err("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_add_sus_mount((struct st_susfs_sus_mount __user*)arg3);
			pr_info("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
		if (arg2 == CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS) {
			int error = 0;
			if (arg3 != 0 && arg3 != 1) {
				pr_err("susfs: CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS -> arg3 can only be 0 or 1\n");
				return 0;
			}
			susfs_hide_sus_mnts_for_all_procs = arg3;
			pr_info("susfs: CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS -> susfs_hide_sus_mnts_for_all_procs: %lu\n", arg3);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(struct st_susfs_sus_kstat))) {
				pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user*)arg3);
			pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
		if (arg2 == CMD_SUSFS_UPDATE_SUS_KSTAT) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(struct st_susfs_sus_kstat))) {
				pr_err("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_update_sus_kstat((struct st_susfs_sus_kstat __user*)arg3);
			pr_info("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
		if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(struct st_susfs_sus_kstat))) {
				pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user*)arg3);
			pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
        }
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		if (arg2 == CMD_SUSFS_ADD_TRY_UMOUNT) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(struct st_susfs_try_umount))) {
				pr_err("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_add_try_umount((struct st_susfs_try_umount __user*)arg3);
			pr_info("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		if (arg2 == CMD_SUSFS_SET_UNAME) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(struct st_susfs_uname))) {
				pr_err("susfs: CMD_SUSFS_SET_UNAME -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_SET_UNAME -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_set_uname((struct st_susfs_uname __user*)arg3);
			pr_info("susfs: CMD_SUSFS_SET_UNAME -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		if (arg2 == CMD_SUSFS_ENABLE_LOG) {
			int error = 0;
			if (arg3 != 0 && arg3 != 1) {
				pr_err("susfs: CMD_SUSFS_ENABLE_LOG -> arg3 can only be 0 or 1\n");
				return 0;
			}
			susfs_set_log(arg3);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		if (arg2 == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE)) {
				pr_err("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_set_cmdline_or_bootconfig((char __user*)arg3);
			pr_info("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		if (arg2 == CMD_SUSFS_ADD_OPEN_REDIRECT) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(struct st_susfs_open_redirect))) {
				pr_err("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_add_open_redirect((struct st_susfs_open_redirect __user*)arg3);
			pr_info("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
#ifdef CONFIG_KSU_SUSFS_SUS_SU
		if (arg2 == CMD_SUSFS_SUS_SU) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(struct st_sus_su))) {
				pr_err("susfs: CMD_SUSFS_SUS_SU -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_SUS_SU -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_sus_su((struct st_sus_su __user*)arg3);
			pr_info("susfs: CMD_SUSFS_SUS_SU -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
#endif //#ifdef CONFIG_KSU_SUSFS_SUS_SU
		if (arg2 == CMD_SUSFS_SHOW_VERSION) {
			int error = 0;
			int len_of_susfs_version = strlen(SUSFS_VERSION);
			char *susfs_version = SUSFS_VERSION;
			if (!ksu_access_ok((void __user*)arg3, len_of_susfs_version+1)) {
				pr_err("susfs: CMD_SUSFS_SHOW_VERSION -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_SHOW_VERSION -> arg5 is not accessible\n");
				return 0;
			}
			error = copy_to_user((void __user*)arg3, (void*)susfs_version, len_of_susfs_version+1);
			pr_info("susfs: CMD_SUSFS_SHOW_VERSION -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
		if (arg2 == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
			int error = 0;
			if (arg4 <= 0) {
				pr_err("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> arg4 cannot be <= 0\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg3, arg4)) {
				pr_err("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> arg5 is not accessible\n");
				return 0;
			}
			error = susfs_get_enabled_features((char __user*)arg3, arg4);
			pr_info("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
		if (arg2 == CMD_SUSFS_SHOW_VARIANT) {
			int error = 0;
			int len_of_variant = strlen(SUSFS_VARIANT);
			char *susfs_variant = SUSFS_VARIANT;
			if (!ksu_access_ok((void __user*)arg3, len_of_variant+1)) {
				pr_err("susfs: CMD_SUSFS_SHOW_VARIANT -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_SHOW_VARIANT -> arg5 is not accessible\n");
				return 0;
			}
			error = copy_to_user((void __user*)arg3, (void*)susfs_variant, len_of_variant+1);
			pr_info("susfs: CMD_SUSFS_SHOW_VARIANT -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
#ifdef CONFIG_KSU_SUSFS_SUS_SU
		if (arg2 == CMD_SUSFS_IS_SUS_SU_READY) {
			int error = 0;
			if (!ksu_access_ok((void __user*)arg3, sizeof(susfs_is_sus_su_ready))) {
				pr_err("susfs: CMD_SUSFS_IS_SUS_SU_READY -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_IS_SUS_SU_READY -> arg5 is not accessible\n");
				return 0;
			}
			error = copy_to_user((void __user*)arg3, (void*)&susfs_is_sus_su_ready, sizeof(susfs_is_sus_su_ready));
			pr_info("susfs: CMD_SUSFS_IS_SUS_SU_READY -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
		if (arg2 == CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE) {
			int error = 0;
			int working_mode = susfs_get_sus_su_working_mode();
			if (!ksu_access_ok((void __user*)arg3, sizeof(working_mode))) {
				pr_err("susfs: CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE -> arg3 is not accessible\n");
				return 0;
			}
			if (!ksu_access_ok((void __user*)arg5, sizeof(error))) {
				pr_err("susfs: CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE -> arg5 is not accessible\n");
				return 0;
			}
			error = copy_to_user((void __user*)arg3, (void*)&working_mode, sizeof(working_mode));
			pr_info("susfs: CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE -> ret: %d\n", error);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_SU
		if (arg2 == CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING) {
			int error = 0;
			if (arg3 != 0 && arg3 != 1) {
				pr_err("susfs: CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING -> arg3 can only be 0 or 1\n");
				return 0;
			}
			susfs_set_avc_log_spoofing(arg3);
			if (copy_to_user((void __user*)arg5, &error, sizeof(error)))
				pr_info("susfs: copy_to_user() failed\n");
			return 0;
		}
	}
#endif //#ifdef CONFIG_KSU_SUSFS

	// all other cmds are for 'root manager'
	if (!from_manager) {
		return 0;
	}

	// we are already manager
	if (arg2 == CMD_GET_APP_PROFILE) {
		struct app_profile profile;
		if (copy_from_user(&profile, arg3, sizeof(profile))) {
			pr_err("copy profile failed\n");
			return 0;
		}

		bool success = ksu_get_app_profile(&profile);
		if (success) {
			if (copy_to_user(arg3, &profile, sizeof(profile))) {
				pr_err("copy profile failed\n");
				return 0;
			}
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
		}
		return 0;
	}

	if (arg2 == CMD_SET_APP_PROFILE) {
		struct app_profile profile;
		if (copy_from_user(&profile, arg3, sizeof(profile))) {
			pr_err("copy profile failed\n");
			return 0;
		}

		// todo: validate the params
		if (ksu_set_app_profile(&profile, true)) {
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
		}
		return 0;
	}

	if (arg2 == CMD_IS_SU_ENABLED) {
		if (copy_to_user(arg3, &ksu_su_compat_enabled,
				 sizeof(ksu_su_compat_enabled))) {
			pr_err("copy su compat failed\n");
			return 0;
		}
		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}
		return 0;
	}

	if (arg2 == CMD_ENABLE_SU) {
		bool enabled = (arg3 != 0);
		if (enabled == ksu_su_compat_enabled) {
			pr_info("cmd enable su but no need to change.\n");
			if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {// return the reply_ok directly
				pr_err("prctl reply error, cmd: %lu\n", arg2);
			}
			return 0;
		}

		if (enabled) {
#ifdef CONFIG_KSU_SUSFS_SUS_SU
			// We disable all sus_su hook whenever user toggle on su_kps
			susfs_is_sus_su_hooks_enabled = false;
			ksu_devpts_hook = false;
			susfs_sus_su_working_mode = SUS_SU_DISABLED;
#endif
			ksu_sucompat_init();
		} else {
			ksu_sucompat_exit();
		}
		ksu_su_compat_enabled = enabled;

		if (copy_to_user(result, &reply_ok, sizeof(reply_ok))) {
			pr_err("prctl reply error, cmd: %lu\n", arg2);
		}

		return 0;
	}

	return 0;
}

static bool is_appuid(kuid_t uid)
{
#define PER_USER_RANGE 100000
#define FIRST_APPLICATION_UID 10000
#define LAST_APPLICATION_UID 19999

	uid_t appid = uid.val % PER_USER_RANGE;
	return appid >= FIRST_APPLICATION_UID && appid <= LAST_APPLICATION_UID;
}

static bool should_umount(struct path *path)
{
	if (!path) {
		return false;
	}

	if (current->nsproxy->mnt_ns == init_nsproxy.mnt_ns) {
		pr_info("ignore global mnt namespace process: %d\n",
			current_uid().val);
		return false;
	}

#ifdef CONFIG_KSU_SUSFS
	return susfs_is_mnt_devname_ksu(path);
#else
	if (path->mnt && path->mnt->mnt_sb && path->mnt->mnt_sb->s_type) {
		const char *fstype = path->mnt->mnt_sb->s_type->name;
		return strcmp(fstype, "overlay") == 0;
	}
	return false;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0) || defined(KSU_HAS_PATH_UMOUNT)
static int ksu_path_umount(struct path *path, int flags)
{
	return path_umount(path, flags);
}
#define ksu_umount_mnt(__unused, path, flags)	(ksu_path_umount(path, flags))
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

#define ksu_umount_mnt(mnt, __unused, flags)		\
	({						\
		int ret;				\
		path_put(__unused);			\
		ret = ksu_sys_umount(mnt, flags);	\
		ret;					\
	})

#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
void try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid)
#else
static void try_umount(const char *mnt, bool check_mnt, int flags)
#endif
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
		pr_info("susfs: umounting '%s' for uid: %d\n", mnt, uid);
	}
#endif

	ret = ksu_umount_mnt(mnt, &path, flags);
	if (ret) {
#ifdef CONFIG_KSU_DEBUG
		pr_info("%s: path: %s, ret: %d\n", __func__, mnt, ret);
#endif
	}
}

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
void susfs_try_umount_all(uid_t uid) {
	susfs_try_umount(uid);
	/* For Legacy KSU only */
	try_umount("/system", true, 0, uid);
	try_umount("/system_ext", true, 0, uid);
	try_umount("/vendor", true, 0, uid);
	try_umount("/product", true, 0, uid);
	try_umount("/odm", true, 0, uid);
	// - For '/data/adb/modules' we pass 'false' here because it is a loop device that we can't determine whether 
	//   its dev_name is KSU or not, and it is safe to just umount it if it is really a mountpoint
	try_umount("/data/adb/modules", false, MNT_DETACH, uid);
	try_umount("/data/adb/kpm", false, MNT_DETACH, uid);
	/* For both Legacy KSU and Magic Mount KSU */
	try_umount("/debug_ramdisk", true, MNT_DETACH, uid);
	try_umount("/sbin", false, MNT_DETACH, uid);
	
	// try umount hosts file
	try_umount("/system/etc/hosts", false, MNT_DETACH, uid);

	// try umount lsposed dex2oat bins
	try_umount("/apex/com.android.art/bin/dex2oat64", false, MNT_DETACH, uid);
	try_umount("/apex/com.android.art/bin/dex2oat32", false, MNT_DETACH, uid);
}
#endif

int ksu_handle_setuid(struct cred *new, const struct cred *old)
{
	// this hook is used for umounting overlayfs for some uid, if there isn't any module mounted, just ignore it!
	if (!ksu_module_mounted) {
		return 0;
	}

	if (!new || !old) {
		return 0;
	}

	kuid_t new_uid = new->uid;
	kuid_t old_uid = old->uid;

	if (0 != old_uid.val) {
		// old process is not root, ignore it.
		return 0;
	}

#ifdef CONFIG_KSU_SUSFS
	// check if current process is zygote
	bool is_zygote_child = susfs_is_sid_equal(old->security, susfs_zygote_sid);
#endif // #ifdef CONFIG_KSU_SUSFS
	if (likely(is_zygote_child)) {
		// if spawned process is non user app process
		if (unlikely(new_uid.val < 10000 && new_uid.val >= 1000)) {
#ifdef CONFIG_KSU_SUSFS_SUS_SU
			// set flag if zygote spawned system process is allowed for root access
			if (!ksu_is_allow_uid(new_uid.val)) {
				task_lock(current);
				susfs_set_current_proc_su_not_allowed();
				task_unlock(current);
			}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_SU
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
			// umount for the system process if path DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS exists
			if (susfs_is_umount_for_zygote_system_process_enabled) {
				goto out_try_umount;
			}
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		}
#ifdef CONFIG_KSU_SUSFS
		// - here we check if uid is a isolated service spawned by zygote directly
		// - Apps that do not use "useAppZyogte" to start a isolated service will be directly
		//   spawned by zygote which KSU will ignore it by default, the only fix for now is to
		//   force a umount for those uid
		// - Therefore make sure your root app doesn't use isolated service for root access
		// - Kudos to ThePedroo, the author and maintainer of Rezygisk for finding and reporting
		//   the detection, really big helps here!
		else if (new_uid.val >= 90000 && new_uid.val < 1000000) {
			task_lock(current);
			susfs_set_current_non_root_user_app_proc();
#ifdef CONFIG_KSU_SUSFS_SUS_SU
			susfs_set_current_proc_su_not_allowed();
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_SU
			task_unlock(current);
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
			susfs_run_sus_path_loop(new_uid.val);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
			if (susfs_is_umount_for_zygote_iso_service_enabled) {
			goto out_susfs_try_umount_all;
		}
	#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		}
	}
#endif // #ifdef CONFIG_KSU_SUSFS

	if (!is_appuid(new_uid) || is_unsupported_uid(new_uid.val)) {
		// pr_info("handle setuid ignore non application or isolated uid: %d\n", new_uid.val);
		return 0;
	}

	if (ksu_is_allow_uid(new_uid.val)) {
		// pr_info("handle setuid ignore allowed application: %d\n", new_uid.val);
		return 0;
	}

	if (ksu_is_allow_uid(new_uid.val)) {
#ifdef CONFIG_KSU_DEBUG
		pr_info("handle setuid ignore allowed application: %d\n", new_uid.val);
#endif
		return 0;
	}
#ifdef CONFIG_KSU_SUSFS
	else {
		task_lock(current);
		susfs_set_current_non_root_user_app_proc();
#ifdef CONFIG_KSU_SUSFS_SUS_SU
		susfs_set_current_proc_su_not_allowed();
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_SU
		task_unlock(current);
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		susfs_run_sus_path_loop(new_uid.val);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH
	}
#endif // #ifdef CONFIG_KSU_SUSFS

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
out_try_umount:
#endif
	if (!ksu_uid_should_umount(new_uid.val)) {
		return 0;
	} else {
#ifdef CONFIG_KSU_DEBUG
		pr_info("uid: %d should not umount!\n", current_uid().val);
#endif
	}
#ifndef CONFIG_KSU_SUSFS
 	// check old process's selinux context, if it is not zygote, ignore it!
 	// because some su apps may setuid to untrusted_app but they are in global mount namespace
 	// when we umount for such process, that is a disaster!
	bool is_zygote_child = ksu_is_zygote(old->security);
#endif
	if (!is_zygote_child) {
		pr_info("handle umount ignore non zygote child: %d\n",
			current->pid);
		return 0;
	}


#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
out_susfs_try_umount_all:
	// susfs come first, and lastly umount by ksu, make sure umount in reversed order
	susfs_try_umount_all(new_uid.val);
#else
	// fixme: use `collect_mounts` and `iterate_mount` to iterate all mountpoint and
	// filter the mountpoint whose target is `/data/adb`
	try_umount("/system", true, 0);
	try_umount("/vendor", true, 0);
	try_umount("/product", true, 0);
	try_umount("/system_ext", true, 0);

	// try umount modules path
	try_umount("/data/adb/modules", false, MNT_DETACH);

	// try umount kpm path
	try_umount("/data/adb/kpm", false, MNT_DETACH);

	// try umount ksu temp path
	try_umount("/debug_ramdisk", false, MNT_DETACH);
	
	// try umount ksu su path
	try_umount("/sbin", false, MNT_DETACH);
	
	// try umount hosts file
	try_umount("/system/etc/hosts", false, MNT_DETACH);

	// try umount lsposed dex2oat bins
	try_umount("/apex/com.android.art/bin/dex2oat64", false, MNT_DETACH);
	try_umount("/apex/com.android.art/bin/dex2oat32", false, MNT_DETACH);
#endif
	return 0;
}

static int ksu_task_prctl(int option, unsigned long arg2, unsigned long arg3,
			  unsigned long arg4, unsigned long arg5)
{
	ksu_handle_prctl(option, arg2, arg3, arg4, arg5);
	return -ENOSYS;
}
// kernel 4.4 and 4.9
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||	\
	defined(CONFIG_IS_HW_HISI) ||	\
	defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
static int ksu_key_permission(key_ref_t key_ref, const struct cred *cred,
			      unsigned perm)
{
	if (init_session_keyring != NULL) {
		return 0;
	}
	if (strcmp(current->comm, "init")) {
		// we are only interested in `init` process
		return 0;
	}
	init_session_keyring = cred->session_keyring;
	pr_info("kernel_compat: got init_session_keyring\n");
	return 0;
}
#endif

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC	0x1cd1
#endif

extern int __ksu_handle_devpts(struct inode *inode); // sucompat.c

int ksu_inode_permission(struct inode *inode, int mask)
{
	if (inode && inode->i_sb 
		&& unlikely(inode->i_sb->s_magic == DEVPTS_SUPER_MAGIC)) {
		//pr_info("%s: handling devpts for: %s \n", __func__, current->comm);
		__ksu_handle_devpts(inode);
	}
	return 0;
}

#ifdef CONFIG_COMPAT
bool ksu_is_compat __read_mostly = false;
#endif

int ksu_bprm_check(struct linux_binprm *bprm)
{
	char *filename = (char *)bprm->filename;
	
	if (likely(!ksu_execveat_hook))
		return 0;

#ifdef CONFIG_COMPAT
	static bool compat_check_done __read_mostly = false;
	if ( unlikely(!compat_check_done) && unlikely(!strcmp(filename, "/data/adb/ksud"))
		&& !memcmp(bprm->buf, "\x7f\x45\x4c\x46", 4) ) {
		if (bprm->buf[4] == 0x01 )
			ksu_is_compat = true;

		pr_info("%s: %s ELF magic found! ksu_is_compat: %d \n", __func__, filename, ksu_is_compat);
		compat_check_done = true;
	}
#endif

	ksu_handle_pre_ksud(filename);

	return 0;

}

static int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	return ksu_handle_rename(old_dentry, new_dentry);
}

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	return ksu_handle_setuid(new, old);
}

#ifndef MODULE
static struct security_hook_list ksu_hooks[] = {
	LSM_HOOK_INIT(task_prctl, ksu_task_prctl),
	LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
	LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
	LSM_HOOK_INIT(inode_permission, ksu_inode_permission),
#ifndef CONFIG_KSU_KPROBES_HOOK
	LSM_HOOK_INIT(bprm_check_security, ksu_bprm_check),
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || \
	defined(CONFIG_IS_HW_HISI) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
	LSM_HOOK_INIT(key_permission, ksu_key_permission)
#endif
};

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
	// https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
	security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
}

#else
// keep renameat_handler for LKM support
static int renameat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	// https://elixir.bootlin.com/linux/v5.12-rc1/source/include/linux/fs.h
	struct renamedata *rd = PT_REGS_PARM1(regs);
	struct dentry *old_entry = rd->old_dentry;
	struct dentry *new_entry = rd->new_dentry;
#else
	struct dentry *old_entry = (struct dentry *)PT_REGS_PARM2(regs);
	struct dentry *new_entry = (struct dentry *)PT_REGS_CCALL_PARM4(regs);
#endif

	return ksu_handle_rename(old_entry, new_entry);
}

static struct kprobe renameat_kp = {
	.symbol_name = "vfs_rename",
	.pre_handler = renameat_handler_pre,
};

static int override_security_head(void *head, const void *new_head, size_t len)
{
	unsigned long base = (unsigned long)head & PAGE_MASK;
	unsigned long offset = offset_in_page(head);

	// this is impossible for our case because the page alignment
	// but be careful for other cases!
	BUG_ON(offset + len > PAGE_SIZE);
	struct page *page = phys_to_page(__pa(base));
	if (!page) {
		return -EFAULT;
	}

	void *addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!addr) {
		return -ENOMEM;
	}
	local_irq_disable();
	memcpy(addr + offset, new_head, len);
	local_irq_enable();
	vunmap(addr);
	return 0;
}

static void free_security_hook_list(struct hlist_head *head)
{
	struct hlist_node *temp;
	struct security_hook_list *entry;

	if (!head)
		return;

	hlist_for_each_entry_safe (entry, temp, head, list) {
		hlist_del(&entry->list);
		kfree(entry);
	}

	kfree(head);
}

struct hlist_head *copy_security_hlist(struct hlist_head *orig)
{
	struct hlist_head *new_head = kmalloc(sizeof(*new_head), GFP_KERNEL);
	if (!new_head)
		return NULL;

	INIT_HLIST_HEAD(new_head);

	struct security_hook_list *entry;
	struct security_hook_list *new_entry;

	hlist_for_each_entry (entry, orig, list) {
		new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry) {
			free_security_hook_list(new_head);
			return NULL;
		}

		*new_entry = *entry;

		hlist_add_tail_rcu(&new_entry->list, new_head);
	}

	return new_head;
}

#define LSM_SEARCH_MAX 180 // This should be enough to iterate
static void *find_head_addr(void *security_ptr, int *index)
{
	if (!security_ptr) {
		return NULL;
	}
	struct hlist_head *head_start =
		(struct hlist_head *)&security_hook_heads;

	for (int i = 0; i < LSM_SEARCH_MAX; i++) {
		struct hlist_head *head = head_start + i;
		struct security_hook_list *pos;
		hlist_for_each_entry (pos, head, list) {
			if (pos->hook.capget == security_ptr) {
				if (index) {
					*index = i;
				}
				return head;
			}
		}
	}

	return NULL;
}

#define GET_SYMBOL_ADDR(sym)                                                   \
	({                                                                     \
		void *addr = kallsyms_lookup_name(#sym ".cfi_jt");             \
		if (!addr) {                                                   \
			addr = kallsyms_lookup_name(#sym);                     \
		}                                                              \
		addr;                                                          \
	})

#define KSU_LSM_HOOK_HACK_INIT(head_ptr, name, func)                           \
	do {                                                                   \
		static struct security_hook_list hook = {                      \
			.hook = { .name = func }                               \
		};                                                             \
		hook.head = head_ptr;                                          \
		hook.lsm = "ksu";                                              \
		struct hlist_head *new_head = copy_security_hlist(hook.head);  \
		if (!new_head) {                                               \
			pr_err("Failed to copy security list: %s\n", #name);   \
			break;                                                 \
		}                                                              \
		hlist_add_tail_rcu(&hook.list, new_head);                      \
		if (override_security_head(hook.head, new_head,                \
					   sizeof(*new_head))) {               \
			free_security_hook_list(new_head);                     \
			pr_err("Failed to hack lsm for: %s\n", #name);         \
		}                                                              \
	} while (0)

void __init ksu_lsm_hook_init(void)
{
	void *cap_prctl = GET_SYMBOL_ADDR(cap_task_prctl);
	void *prctl_head = find_head_addr(cap_prctl, NULL);
	if (prctl_head) {
		if (prctl_head != &security_hook_heads.task_prctl) {
			pr_warn("prctl's address has shifted!\n");
		}
		KSU_LSM_HOOK_HACK_INIT(prctl_head, task_prctl, ksu_task_prctl);
	} else {
		pr_warn("Failed to find task_prctl!\n");
	}

	int inode_killpriv_index = -1;
	void *cap_killpriv = GET_SYMBOL_ADDR(cap_inode_killpriv);
	find_head_addr(cap_killpriv, &inode_killpriv_index);
	if (inode_killpriv_index < 0) {
		pr_warn("Failed to find inode_rename, use kprobe instead!\n");
		register_kprobe(&renameat_kp);
	} else {
		int inode_rename_index = inode_killpriv_index +
					 &security_hook_heads.inode_rename -
					 &security_hook_heads.inode_killpriv;
		struct hlist_head *head_start =
			(struct hlist_head *)&security_hook_heads;
		void *inode_rename_head = head_start + inode_rename_index;
		if (inode_rename_head != &security_hook_heads.inode_rename) {
			pr_warn("inode_rename's address has shifted!\n");
		}
		KSU_LSM_HOOK_HACK_INIT(inode_rename_head, inode_rename,
				       ksu_inode_rename);
	}
	void *cap_setuid = GET_SYMBOL_ADDR(cap_task_fix_setuid);
	void *setuid_head = find_head_addr(cap_setuid, NULL);
	if (setuid_head) {
		if (setuid_head != &security_hook_heads.task_fix_setuid) {
			pr_warn("setuid's address has shifted!\n");
		}
		KSU_LSM_HOOK_HACK_INIT(setuid_head, task_fix_setuid,
				       ksu_task_fix_setuid);
	} else {
		pr_warn("Failed to find task_fix_setuid!\n");
	}
	smp_mb();
}
#endif

void __init ksu_core_init(void)
{
	ksu_lsm_hook_init();
}

void ksu_core_exit(void)
{
	ksu_throne_comm_exit();
	
#ifdef CONFIG_KSU_KPROBES_HOOK
	pr_info("ksu_core_kprobe_exit\n");
	// we dont use this now
	// ksu_kprobe_exit();
#endif
}
