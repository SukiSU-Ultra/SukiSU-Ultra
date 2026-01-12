#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <asm/current.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#include <linux/input-event-codes.h>
#else
#include <uapi/linux/input.h>
#endif
#include <linux/aio.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/namei.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif

#include "manager.h"
#include "allowlist.h"
#include "arch.h"
#include "kernel_compat.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#ifdef CONFIG_KSU_SYSCALL_HOOK
#include "kp_hook.h"
#endif
#include "selinux/selinux.h"
#include "throne_tracker.h"
#if defined(CONFIG_KSU_MANUAL_HOOK) && !defined(CONFIG_KSU_SUSFS)
#include "sucompat.h"
#endif

#if defined(CONFIG_KSU_SYSCALL_HOOK) || defined(CONFIG_KSU_SUSFS) ||                \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) &&                      \
	 defined(CONFIG_KSU_MANUAL_HOOK))
extern int ksu_observer_init(void);
#endif

bool ksu_module_mounted __read_mostly = false;
bool ksu_boot_completed __read_mostly = false;

static const char KERNEL_SU_RC[] =
	"\n"

	"on post-fs-data\n"
	"	start logd\n"
	// We should wait for the post-fs-data finish
	"	exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH
	" post-fs-data\n"
	"\n"

	"on nonencrypted\n"
	"	exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH
	" services\n"
	"\n"

	"on property:vold.decrypt=trigger_restart_framework\n"
	"	exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH
	" services\n"
	"\n"

	"on property:sys.boot_completed=1\n"
	"	exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH
	" boot-completed\n"
	"\n"

	"\n";

static void stop_init_rc_hook(void);
static void stop_execve_hook(void);
static void stop_input_hook(void);

#if defined(CONFIG_KSU_MANUAL_HOOK) || defined(CONFIG_KSU_SUSFS)
bool ksu_init_rc_hook __read_mostly = true;
bool ksu_execveat_hook __read_mostly = true;
bool ksu_input_hook __read_mostly = true;
#endif // #ifndef CONFIG_KSU_SUSFS

// Detect whether it is on or not
static bool is_boot_phase = true;

void on_post_fs_data(void)
{
	static bool already_post_fs_data = false;
	if (already_post_fs_data) {
		pr_info("on_post_fs_data already done\n");
		return;
	}
	already_post_fs_data = true;
	pr_info("on_post_fs_data!\n");
	ksu_load_allow_list();
#if defined(CONFIG_KSU_SYSCALL_HOOK) || defined(CONFIG_KSU_SUSFS) ||          \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) &&                      \
	 defined(CONFIG_KSU_MANUAL_HOOK))
	ksu_observer_init();
#endif
	stop_input_hook();

	// End of boot state
	is_boot_phase = false;
}

extern void ext4_unregister_sysfs(struct super_block *sb);
int nuke_ext4_sysfs(const char *mnt)
{
	struct path path;
	struct super_block *sb = NULL;
	const char *name = NULL;
	int err;
	
	err = kern_path(mnt, 0, &path);
	if (err) {
		pr_err("nuke path err: %d\n", err);
		return err;
	}

	sb = path.dentry->d_inode->i_sb;
	name = sb->s_type->name;
	if (strcmp(name, "ext4") != 0) {
		pr_info("nuke but module aren't mounted\n");
		path_put(&path);
		return -EINVAL;
	}

	ext4_unregister_sysfs(sb);
	path_put(&path);
	return 0;
}

void on_module_mounted(void)
{
	pr_info("on_module_mounted!\n");
	ksu_module_mounted = true;
}

void on_boot_completed(void)
{
	ksu_boot_completed = true;
	pr_info("on_boot_completed!\n");
#if defined(CONFIG_KSU_SYSCALL_HOOK) || defined(CONFIG_KSU_SUSFS) ||          \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) &&                      \
	 defined(CONFIG_KSU_MANUAL_HOOK))
	track_throne(true);
#endif
}

#define MAX_ARG_STRINGS 0x7FFFFFFF

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

/*
 * count() counts the number of strings in array ARGV.
 */

/*
 * Make sure old GCC compiler can use __maybe_unused,
 * Test passed in 4.4.x ~ 4.9.x when use GCC.
 */

static int __maybe_unused count(struct user_arg_ptr argv, int max)
{
	int i = 0;

	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);

			if (!p)
				break;

			if (IS_ERR(p))
				return -EFAULT;

			if (i >= max)
				return -E2BIG;
			++i;

			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
#if defined(CONFIG_KSU_MANUAL_HOOK) && !defined(CONFIG_KSU_SUSFS)
			cond_resched();
#endif
		}
	}
	return i;
}

static void on_post_fs_data_cbfun(struct callback_head *cb)
{
	on_post_fs_data();
}

static struct callback_head on_post_fs_data_cb = {
	.func = on_post_fs_data_cbfun
};

static inline void handle_second_stage(void)
{
	apply_kernelsu_rules();
	cache_sid();
	setup_ksu_cred();
}

static bool check_argv(struct user_arg_ptr argv, int index,
		       const char *expected, char *buf, size_t buf_len)
{
	const char __user *p;
	int argc;
	long ret;

	argc = count(argv, MAX_ARG_STRINGS);
	if (argc <= index) {
		return false;
	}

	p = get_user_arg_ptr(argv, index);
	if (IS_ERR_OR_NULL(p)) {
		if (PTR_ERR(p)) {
			pr_err("check_argv: invalid user pointer, err: %ld\n",
			       PTR_ERR(p));
		}
		return false;
	}

	ret = ksu_strncpy_from_user_nofault(buf, p, buf_len);
	if (ret <= 0) {
		pr_err("check_argv: failed to copy pointer, err: %ld\n", ret);
		return false;
	}

	buf[buf_len - 1] = '\0';

	return !strcmp(buf, expected);
}

// IMPORTANT NOTE: the call from execve_handler_pre WON'T provided correct value for envp and flags in GKI version
int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
			     struct user_arg_ptr *argv,
			     struct user_arg_ptr *envp, int *flags)
{
#if defined(CONFIG_KSU_MANUAL_HOOK) && !defined(CONFIG_KSU_SUSFS)
	if (!ksu_execveat_hook) {
		return 0;
	}
#endif
	struct filename *filename;

	static const char app_process[] = "/system/bin/app_process";
	static bool first_zygote = true;

	/* This applies to versions Android 10+ */
	static const char system_bin_init[] = "/system/bin/init";
	/* This applies to versions between Android 6 ~ 9  */
	static const char old_system_init[] = "/init";
	static bool init_second_stage_executed = false;

	if (!filename_ptr)
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename)) {
		return 0;
	}

	if (unlikely(!memcmp(filename->name, system_bin_init,
			     sizeof(system_bin_init) - 1) &&
		     argv)) {
		char buf[16];
		if (!init_second_stage_executed &&
		    check_argv(*argv, 1, "second_stage", buf, sizeof(buf))) {
			pr_info("/system/bin/init second_stage executed\n");
			handle_second_stage();
			init_second_stage_executed = true;
		}
	} else if (unlikely(!memcmp(filename->name, old_system_init,
				    sizeof(old_system_init) - 1) &&
			    argv)) {
		char buf[16];
		if (!init_second_stage_executed &&
		    check_argv(*argv, 1, "--second-stage", buf, sizeof(buf))) {
			/* This applies to versions between Android 6 ~ 7 */
			pr_info("/init second_stage executed\n");
			handle_second_stage();
			init_second_stage_executed = true;
		} else if (count(*argv, MAX_ARG_STRINGS) == 1 &&
			   !init_second_stage_executed && envp) {
			/* This applies to versions between Android 8 ~ 9  */
			int envc = count(*envp, MAX_ARG_STRINGS);
			if (envc > 0) {
				int n;
				for (n = 1; n <= envc; n++) {
					const char __user *p =
						get_user_arg_ptr(*envp, n);
					if (!p || IS_ERR(p)) {
						continue;
					}
					char env[256];
					// Reading environment variable strings from user space
					if (ksu_strncpy_from_user_nofault(
						    env, p, sizeof(env)) < 0)
						continue;
					// Parsing environment variable names and values
					char *env_name = env;
					char *env_value = strchr(env, '=');
					if (env_value == NULL)
						continue;
					// Replace equal sign with string terminator
					*env_value = '\0';
					env_value++;
					// Check if the environment variable name and value are matching
					if (!strcmp(env_name,
						    "INIT_SECOND_STAGE") &&
					    (!strcmp(env_value, "1") ||
					     !strcmp(env_value, "true"))) {
						pr_info("/init second_stage executed\n");
						handle_second_stage();
						init_second_stage_executed =
							true;
					}
				}
			}
		}
	}

	if (unlikely(first_zygote &&
		     !memcmp(filename->name, app_process,
			     sizeof(app_process) - 1) &&
		     argv)) {
		char buf[16];
		if (check_argv(*argv, 1, "-Xzygote", buf, sizeof(buf))) {
			pr_info("exec zygote, /data prepared, second_stage: %d\n",
				init_second_stage_executed);
			rcu_read_lock();
			struct task_struct *init_task =
				rcu_dereference(current->real_parent);
			if (init_task)
				task_work_add(init_task, &on_post_fs_data_cb,
					      TWA_RESUME);
			rcu_read_unlock();
			first_zygote = false;
			stop_execve_hook();
		}
	}

	return 0;
}

static ssize_t (*orig_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t (*orig_read_iter)(struct kiocb *, struct iov_iter *);
static struct file_operations fops_proxy;
static ssize_t ksu_rc_pos = 0;
const size_t ksu_rc_len = sizeof(KERNEL_SU_RC) - 1;

// https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/parser.cpp;l=144;drc=61197364367c9e404c7da6900658f1b16c42d0da
// https://cs.android.com/android/platform/superproject/main/+/main:system/libbase/file.cpp;l=241-243;drc=61197364367c9e404c7da6900658f1b16c42d0da
// The system will read init.rc file until EOF, whenever read() returns 0,
// so we begin append ksu rc when we meet EOF.

static ssize_t read_proxy(struct file *file, char __user *buf, size_t count,
			  loff_t *pos)
{
	ssize_t ret = 0;
	size_t append_count;
	if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
		goto append_ksu_rc;

	ret = orig_read(file, buf, count, pos);
	if (ret != 0 || ksu_rc_pos >= ksu_rc_len) {
		return ret;
	} else {
		pr_info("read_proxy: orig read finished, start append rc\n");
	}
append_ksu_rc:
	append_count = ksu_rc_len - ksu_rc_pos;
	if (append_count > count - ret)
		append_count = count - ret;
	// copy_to_user returns the number of not copied
	if (copy_to_user(buf + ret, KERNEL_SU_RC + ksu_rc_pos, append_count)) {
		pr_info("read_proxy: append error, totally appended %zd\n",
			ksu_rc_pos);
	} else {
		pr_info("read_proxy: append %zu\n", append_count);

		ksu_rc_pos += append_count;
		if (ksu_rc_pos == ksu_rc_len) {
			pr_info("read_proxy: append done\n");
		}
		ret += append_count;
	}

	return ret;
}

static ssize_t read_iter_proxy(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret = 0;
	size_t append_count;
	if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
		goto append_ksu_rc;

	ret = orig_read_iter(iocb, to);
	if (ret != 0 || ksu_rc_pos >= ksu_rc_len) {
		return ret;
	} else {
		pr_info("read_iter_proxy: orig read finished, start append rc\n");
	}
append_ksu_rc:
	// copy_to_iter returns the number of copied bytes
	append_count = copy_to_iter(KERNEL_SU_RC + ksu_rc_pos,
				    ksu_rc_len - ksu_rc_pos, to);
	if (!append_count) {
		pr_info("read_iter_proxy: append error, totally appended %zd\n",
			ksu_rc_pos);
	} else {
		pr_info("read_iter_proxy: append %zu\n", append_count);

		ksu_rc_pos += append_count;
		if (ksu_rc_pos == ksu_rc_len) {
			pr_info("read_iter_proxy: append done\n");
		}
		ret += append_count;
	}
	return ret;
}

static bool check_init_path(char *dpath)
{
	const char *valid_paths[] = { "/system/etc/init/hw/init.rc",
				      "/init.rc" };
	bool path_match = false;
	int i;

	for (i = 0; i < ARRAY_SIZE(valid_paths); i++) {
		if (strcmp(dpath, valid_paths[i]) == 0) {
			path_match = true;
			break;
		}
	}

	if (!path_match) {
		pr_err("vfs_read: couldn't determine init.rc path for %s\n",
		       dpath);
		return false;
	}

	pr_info("vfs_read: got init.rc path: %s\n", dpath);
	return true;
}

static bool is_init_rc(struct file *fp)
{
#ifdef CONFIG_KSU_MANUAL_HOOK
	if (!ksu_init_rc_hook) {
		return false;
	}
#endif

	if (strcmp(current->comm, "init")) {
		// we are only interest in `init` process
		return false;
	}

	if (!d_is_reg(fp->f_path.dentry)) {
		return false;
	}

	const char *short_name = fp->f_path.dentry->d_name.name;
	if (strcmp(short_name, "init.rc")) {
		// we are only interest `init.rc` file name file
		return false;
	}
	char path[256];
	char *dpath = d_path(&fp->f_path, path, sizeof(path));

	if (IS_ERR(dpath)) {
		return false;
	}

	if (!check_init_path(dpath)) {
		return false;
	}

	return true;
}

void ksu_handle_sys_read(unsigned int fd)
{
	struct file *file = fget(fd);
#if defined(CONFIG_KSU_SYSCALL_HOOK)
	if (!file) {
		return;
	}

	if (!is_init_rc(file)) {
		goto skip;
	}
#else
	/* Do nothing */
	return;
#endif

	// we only process the first read
	static bool rc_hooked = false;
	if (rc_hooked) {
		// we don't need these kprobe, unregister it!
		stop_init_rc_hook();
		goto skip;
	}
	rc_hooked = true;

	// now we can sure that the init process is reading
	// `/system/etc/init/hw/init.rc` or `/init.rc`
	pr_info("read init.rc, comm: %s, rc_count: %zu\n", current->comm,
		ksu_rc_len);

	// Now we need to proxy the read and modify the result!
	// But, we can not modify the file_operations directly, because it's in read-only memory.
	// We just replace the whole file_operations with a proxy one.
	memcpy(&fops_proxy, file->f_op, sizeof(struct file_operations));
	orig_read = file->f_op->read;
	if (orig_read) {
		fops_proxy.read = read_proxy;
	}
	orig_read_iter = file->f_op->read_iter;
	if (orig_read_iter) {
		fops_proxy.read_iter = read_iter_proxy;
	}
	// replace the file_operations
	file->f_op = &fops_proxy;

skip:
	fput(file);
}

static unsigned int volumedown_pressed_count = 0;

static bool is_volumedown_enough(unsigned int count)
{
	return count >= 3;
}

int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code,
				  int *value)
{
#if defined(CONFIG_KSU_MANUAL_HOOK) || defined(CONFIG_KSU_SUSFS)
	if (!ksu_input_hook) {
		return 0;
	}
#endif // #ifndef CONFIG_KSU_SUSFS

	if (*type == EV_KEY && *code == KEY_VOLUMEDOWN && *value) {
		// key pressed, count it
		volumedown_pressed_count++;
		pr_info("input_handle_event: vol_down pressed count: %u\n",
			volumedown_pressed_count);
		if (is_volumedown_enough(volumedown_pressed_count)) {
			pr_info("input_handle_event: vol_down pressed MAX! safe mode is active!\n");
			stop_input_hook();
		}
	}

	return 0;
}

bool ksu_is_safe_mode(void)
{
	return is_volumedown_enough(volumedown_pressed_count);
}

static void stop_init_rc_hook(void)
{
#ifdef CONFIG_KSU_SYSCALL_HOOK
	kp_handle_ksud_stop(INIT_RC_HOOK_KP);
#else
	ksu_init_rc_hook = false;
	pr_info("stop vfs_read_hook\n");
#endif // #ifndef CONFIG_KSU_SUSFS
}

static void stop_execve_hook(void)
{
#ifdef CONFIG_KSU_SYSCALL_HOOK
	kp_handle_ksud_stop(EXECVE_HOOK_KP);
#else
	ksu_execveat_hook = false;
	pr_info("stop execve_hook\n");
#endif // #ifndef CONFIG_KSU_SUSFS
}

static void stop_input_hook(void)
{
#ifdef CONFIG_KSU_SYSCALL_HOOK
	kp_handle_ksud_stop(INPUT_EVENT_HOOK_KP);
#else
	// No need to stop when its already stopped.
	if (!ksu_input_hook) {
		return;
	}
	ksu_input_hook = false;
	pr_info("stop input_hook\n");
#endif // #ifndef CONFIG_KSU_SUSFS
}

// ksud: module support
void ksu_ksud_init(void)
{
#ifdef CONFIG_KSU_SYSCALL_HOOK
	kp_handle_ksud_init();
#endif // #ifndef CONFIG_KSU_SUSFS
}

void ksu_ksud_exit(void)
{
#ifdef CONFIG_KSU_SYSCALL_HOOK
	kp_handle_ksud_exit();
#endif // #ifndef CONFIG_KSU_SUSFS
	is_boot_phase = false;
}

#ifdef CONFIG_KSU_SUSFS
void ksu_handle_sys_newfstatat(int fd, loff_t *kstat_size_ptr) {
    loff_t new_size = *kstat_size_ptr + ksu_rc_len;
    struct file *file = fget(fd);

    if (!file)
        return;

    if (is_init_rc(file)) {
        pr_info("stat init.rc");
        pr_info("adding ksu_rc_len: %lld -> %lld", *kstat_size_ptr, new_size);
        *kstat_size_ptr = new_size;
    }
    fput(file);
}
#endif // #ifdef CONFIG_KSU_SUSFS
