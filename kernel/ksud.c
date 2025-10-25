#include <asm/current.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/input-event-codes.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include "allowlist.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "manager.h"
#include "kernel_compat.h"
#include "selinux/selinux.h"

// Daemon token implementation
pid_t ksu_daemon_pid = KSU_INVALID_PID;
char ksu_daemon_token[65] = {0};

void ksu_generate_daemon_token(void)
{
	unsigned char random_bytes[32];
	get_random_bytes(random_bytes, 32);
	bin2hex(ksu_daemon_token, random_bytes, 32);
	ksu_daemon_token[64] = '\0';
	pr_info("KernelSU daemon token generated\n");
}

const char* ksu_get_daemon_token(void)
{
	return ksu_daemon_token;
}

bool ksu_verify_daemon_token(const char *token)
{
	if (!token || strlen(token) != 64) {
		return false;
	}
	return strncmp(ksu_daemon_token, token, 64) == 0;
}

// Manager UID implementation
uid_t ksu_manager_uid = KSU_INVALID_UID;


static const char KERNEL_SU_RC[] =
	"\n"

	"on post-fs-data\n"
	"    start logd\n"
	// We should wait for the post-fs-data finish
	"    exec u:r:su:s0 root -- " KSUD_PATH " post-fs-data\n"
	"\n"

	"on nonencrypted\n"
	"    exec u:r:su:s0 root -- " KSUD_PATH " services\n"
	"\n"

	"on property:vold.decrypt=trigger_restart_framework\n"
	"    exec u:r:su:s0 root -- " KSUD_PATH " services\n"
	"\n"

	"on property:sys.boot_completed=1\n"
	"    exec u:r:su:s0 root -- " KSUD_PATH " boot-completed\n"
	"\n"

	"on property:sys.boot_completed=1\n"
	"    setenv KSUD_DAEMON_TOKEN %s\n"
	"    exec u:r:su:s0 root -- " KSUD_PATH " daemon\n"
	"\n"

	"\n";

static void stop_vfs_read_hook();
static void stop_execve_hook();
static void stop_input_hook();

#ifdef CONFIG_KSU_KPROBES_HOOK
static struct work_struct stop_vfs_read_work;
static struct work_struct stop_execve_hook_work;
static struct work_struct stop_input_hook_work;
#else
bool ksu_vfs_read_hook __read_mostly = true;
bool ksu_input_hook __read_mostly = true;
#endif
bool ksu_execveat_hook __read_mostly = true;

u32 ksu_devpts_sid;

// Detect whether it is on or not
static bool is_boot_phase = true;

void on_post_fs_data(void)
{
	static bool done = false;
	if (done) {
		pr_info("on_post_fs_data already done\n");
		return;
	}
	done = true;
	pr_info("on_post_fs_data!\n");
	ksu_load_allow_list();
	// sanity check, this may influence the performance
	stop_input_hook();

	ksu_devpts_sid = ksu_get_devpts_sid();
	pr_info("devpts sid: %d\n", ksu_devpts_sid);

	// End of boot state
    is_boot_phase = false;
}

// since _ksud handler only uses argv and envp for comparisons
// this can probably work
// adapted from ksu_handle_execveat_ksud
static int ksu_handle_bprm_ksud(const char *filename, const char *argv1, const char *envp, size_t envp_len)
{
	static const char app_process[] = "/system/bin/app_process";
	static bool first_app_process = true;

	/* This applies to versions Android 10+ */
	static const char system_bin_init[] = "/system/bin/init";
	/* This applies to versions between Android 6 ~ 9  */
	static const char old_system_init[] = "/init";
	static bool init_second_stage_executed = false;

	// return early when disabled
	if (!ksu_execveat_hook)
		return 0;

	if (!filename)
		return 0;

	// debug! remove me!
	pr_info("%s: filename: %s argv1: %s envp_len: %zu\n", __func__, filename, argv1, envp_len);

#ifdef CONFIG_KSU_DEBUG
	const char *envp_n = envp;
	unsigned int envc = 1;
	do {
		pr_info("%s: envp[%d]: %s\n", __func__, envc, envp_n);
		envp_n += strlen(envp_n) + 1;
		envc++;
	} while (envp_n < envp + 256);
#endif

	if (init_second_stage_executed)
		goto first_app_process;

	// /system/bin/init with argv1
	if (!init_second_stage_executed 
		&& (!memcmp(filename, system_bin_init, sizeof(system_bin_init) - 1))) {
		if (argv1 && !strcmp(argv1, "second_stage")) {
			pr_info("%s: /system/bin/init second_stage executed\n", __func__);
			apply_kernelsu_rules();
			init_second_stage_executed = true;
			ksu_android_ns_fs_check();
		}
	}

	// /init with argv1
	if (!init_second_stage_executed 
		&& (!memcmp(filename, old_system_init, sizeof(old_system_init) - 1))) {
		if (argv1 && !strcmp(argv1, "--second-stage")) {
			pr_info("%s: /init --second-stage executed\n", __func__);
			apply_kernelsu_rules();
			init_second_stage_executed = true;
			ksu_android_ns_fs_check();
		}
	}

	if (!envp || !envp_len)
		goto first_app_process;

	// /init without argv1/useless-argv1 but usable envp
	// untested! TODO: test and debug me!
	if (!init_second_stage_executed && (!memcmp(filename, old_system_init, sizeof(old_system_init) - 1))) {
		
		// we hunt for "INIT_SECOND_STAGE"
		const char *envp_n = envp;
		unsigned int envc = 1;
		do {
			if (strstarts(envp_n, "INIT_SECOND_STAGE"))
				break;
			envp_n += strlen(envp_n) + 1;
			envc++;
		} while (envp_n < envp + envp_len);
		pr_info("%s: envp[%d]: %s\n", __func__, envc, envp_n);
		
		if (!strcmp(envp_n, "INIT_SECOND_STAGE=1")
			|| !strcmp(envp_n, "INIT_SECOND_STAGE=true") ) {
			pr_info("%s: /init +envp: INIT_SECOND_STAGE executed\n", __func__);
			apply_kernelsu_rules();
			init_second_stage_executed = true;
			ksu_android_ns_fs_check();
		}
	}

first_app_process:
	if (first_app_process && !memcmp(filename, app_process, sizeof(app_process) - 1)) {
		first_app_process = false;
		pr_info("%s: exec app_process, /data prepared, second_stage: %d\n", __func__, init_second_stage_executed);
		on_post_fs_data();
		stop_execve_hook();
	}

	return 0;
}

int ksu_handle_pre_ksud(const char *filename)
{
	if (likely(!ksu_execveat_hook))
		return 0;

	// not /system/bin/init, not /init, not /system/bin/app_process (64/32 thingy)
	// return 0;
	if (likely(strcmp(filename, "/system/bin/init") && strcmp(filename, "/init")
		&& !strstarts(filename, "/system/bin/app_process") ))
		return 0;

	if (!current || !current->mm)
		return 0;

	// https://elixir.bootlin.com/linux/v4.14.1/source/include/linux/mm_types.h#L429
	// unsigned long arg_start, arg_end, env_start, env_end;
	unsigned long arg_start = current->mm->arg_start;
	unsigned long arg_end = current->mm->arg_end;
	unsigned long env_start = current->mm->env_start;
	unsigned long env_end = current->mm->env_end;

	size_t arg_len = arg_end - arg_start;
	size_t envp_len = env_end - env_start;

	if (arg_len <= 0 || envp_len <= 0) // this wont make sense, filter it
		return 0;

	#define ARGV_MAX 32  // this is enough for argv1
	#define ENVP_MAX 256  // this is enough for INIT_SECOND_STAGE
	char args[ARGV_MAX];
	size_t argv_copy_len = (arg_len > ARGV_MAX) ? ARGV_MAX : arg_len;
	char envp[ENVP_MAX];
	size_t envp_copy_len = (envp_len > ENVP_MAX) ? ENVP_MAX : envp_len;

	// we cant use strncpy on here, else it will truncate once it sees \0
	if (ksu_copy_from_user_retry(args, (void __user *)arg_start, argv_copy_len))
		return 0;

	if (ksu_copy_from_user_retry(envp, (void __user *)env_start, envp_copy_len))
		return 0;

	args[ARGV_MAX - 1] = '\0';
	envp[ENVP_MAX - 1] = '\0';

	// we only need argv1 !
	// abuse strlen here since it only gets length up to \0
	char *argv1 = args + strlen(args) + 1;
	if (argv1 >= args + argv_copy_len) // out of bounds!
		argv1 = "";

	return ksu_handle_bprm_ksud(filename, argv1, envp, envp_copy_len);
}

static ssize_t (*orig_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t (*orig_read_iter)(struct kiocb *, struct iov_iter *);
static struct file_operations fops_proxy;
static ssize_t read_count_append = 0;

static ssize_t read_proxy(struct file *file, char __user *buf, size_t count,
			  loff_t *pos)
{
	bool first_read = file->f_pos == 0;
	ssize_t ret = orig_read(file, buf, count, pos);
	if (first_read) {
		pr_info("read_proxy append %ld + %ld\n", ret,
			read_count_append);
		ret += read_count_append;
	}
	return ret;
}

static ssize_t read_iter_proxy(struct kiocb *iocb, struct iov_iter *to)
{
	bool first_read = iocb->ki_pos == 0;
	ssize_t ret = orig_read_iter(iocb, to);
	if (first_read) {
		pr_info("read_iter_proxy append %ld + %ld\n", ret,
			read_count_append);
		ret += read_count_append;
	}
	return ret;
}

int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,
			size_t *count_ptr, loff_t **pos)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
 	if (!ksu_vfs_read_hook) {
 		return 0;
 	}
#endif
	struct file *file;
	char __user *buf;
	size_t count;

	if (strcmp(current->comm, "init")) {
		// we are only interest in `init` process
		return 0;
	}

	file = *file_ptr;
	if (IS_ERR(file)) {
		return 0;
	}

	if (!d_is_reg(file->f_path.dentry)) {
		return 0;
	}

	const char *short_name = file->f_path.dentry->d_name.name;
	if (strcmp(short_name, "atrace.rc")) {
		// we are only interest `atrace.rc` file name file
		return 0;
	}
	char path[256];
	char *dpath = d_path(&file->f_path, path, sizeof(path));

	if (IS_ERR(dpath)) {
		return 0;
	}

	if (strcmp(dpath, "/system/etc/init/atrace.rc")) {
		return 0;
	}

	// we only process the first read
	static bool rc_inserted = false;
	if (rc_inserted) {
		// we don't need this kprobe, unregister it!
		stop_vfs_read_hook();
		return 0;
	}
	rc_inserted = true;

	// now we can sure that the init process is reading
	// `/system/etc/init/atrace.rc`
	buf = *buf_ptr;
	count = *count_ptr;

	// Prepare RC content with token replacement
	char rc_with_token[sizeof(KERNEL_SU_RC) + 64];
	const char *token = ksu_get_daemon_token();
	
	snprintf(rc_with_token, sizeof(rc_with_token), KERNEL_SU_RC, token);

	size_t rc_count = strlen(rc_with_token);

	pr_info("vfs_read: %s, comm: %s, count: %zu, rc_count: %zu\n", dpath,
		current->comm, count, rc_count);

	if (count < rc_count) {
		pr_err("count: %zu < rc_count: %zu\n", count, rc_count);
		return 0;
	}

	size_t ret = copy_to_user(buf, rc_with_token, rc_count);
	if (ret) {
		pr_err("copy ksud.rc failed: %zu\n", ret);
		return 0;
	}

	// we've succeed to insert ksud.rc, now we need to proxy the read and modify the result!
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
	read_count_append = rc_count;

	*buf_ptr = buf + rc_count;
	*count_ptr = count - rc_count;

	return 0;
}

int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,
			size_t *count_ptr)
{
	struct file *file = fget(fd);
	if (!file) {
		return 0;
	}
	int result = ksu_handle_vfs_read(&file, buf_ptr, count_ptr, NULL);
	fput(file);
	return result;
}

static unsigned int volumedown_pressed_count = 0;

static bool is_volumedown_enough(unsigned int count)
{
	return count >= 3;
}

int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code,
				  int *value)
{
#ifndef CONFIG_KSU_KPROBES_HOOK
 	if (!ksu_input_hook) {
 		return 0;
 	}
#endif
	if (*type == EV_KEY && *code == KEY_VOLUMEDOWN) {
		int val = *value;
		pr_info("KEY_VOLUMEDOWN val: %d\n", val);
		if (val && is_boot_phase) {
			// key pressed, count it
			volumedown_pressed_count += 1;
			if (is_volumedown_enough(volumedown_pressed_count)) {
				stop_input_hook();
			}
		}
	}

	return 0;
}

bool ksu_is_safe_mode()
{
	static bool safe_mode = false;
	if (safe_mode) {
		// don't need to check again, userspace may call multiple times
		return true;
	}

	// stop hook first!
	stop_input_hook();

	pr_info("volumedown_pressed_count: %d\n", volumedown_pressed_count);
	if (is_volumedown_enough(volumedown_pressed_count)) {
		// pressed over 3 times
		pr_info("KEY_VOLUMEDOWN pressed max times, safe mode detected!\n");
		safe_mode = true;
		return true;
	}

	return false;
}

#ifdef CONFIG_KSU_KPROBES_HOOK
static int sys_execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	/*
	asmlinkage int sys_execve(const char __user *filenamei,
				  const char __user *const __user *argv,
				  const char __user *const __user *envp, struct pt_regs *regs)
	*/
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	const char __user *filename_user = (const char __user *)PT_REGS_PARM1(real_regs);
	const char __user *const __user *__argv = (const char __user *const __user *)PT_REGS_PARM2(real_regs);
	const char __user *const __user *__envp = (const char __user *const __user *)PT_REGS_PARM3(real_regs);
	char path[32];

	if (!filename_user)
		return 0;

// filename stage
	if (ksu_copy_from_user_retry(path, filename_user, sizeof(path)))
		return 0;

	path[sizeof(path) - 1] = '\0';

	// not /system/bin/init, not /init, not /system/bin/app_process (64/32 thingy)
	// we dont care !!
	if (likely(strcmp(path, "/system/bin/init") && strcmp(path, "/init")
		&& !strstarts(path, "/system/bin/app_process") ))
		return 0;

// argv stage
	char argv1[32] = {0};
	// memzero_explicit(argv1, 32);
	if (__argv) {
		const char __user *arg1_user = NULL;
		// grab argv[1] pointer
		// this looks like
		/* 
		 * 0x1000 ./program << this is __argv
		 * 0x1001 -o 
		 * 0x1002 arg
		*/
		if (ksu_copy_from_user_retry(&arg1_user, __argv + 1, sizeof(arg1_user)))
			goto no_argv1; // copy argv[1] pointer fail, probably no argv1 !!

		if (arg1_user)
			ksu_copy_from_user_retry(argv1, arg1_user, sizeof(argv1));
	}

no_argv1:
	argv1[sizeof(argv1) - 1] = '\0';

// envp stage
	#define ENVP_MAX 256
	char envp[ENVP_MAX] = {0};
	char *dst = envp;
	size_t envp_len = 0;
	int i = 0; // to track user pointer offset from __envp

	// memzero_explicit(envp, ENVP_MAX);

	if (__envp) {
		do {
			const char __user *env_entry_user = NULL;
			// this is also like argv above
			/*
			 * 0x1001 PATH=/bin
			 * 0x1002 VARIABLE=value
			 * 0x1002 some_more_env_var=1
			 */

			// check if pointer exists
			if (ksu_copy_from_user_retry(&env_entry_user, __envp + i, sizeof(env_entry_user)))
				break; 

			// check if no more env entry
			if (!env_entry_user)
				break; 
			
			// probably redundant to while condition but ok
			if (envp_len >= ENVP_MAX - 1)
				break;

			// copy strings from env_entry_user pointer that we collected
			// also break if failed
			if (ksu_copy_from_user_retry(dst, env_entry_user, ENVP_MAX - envp_len))
				break;

			// get the length of that new copy above
			// get lngth of dst as far as ENVP_MAX - current collected envp_len
			size_t len = strnlen(dst, ENVP_MAX - envp_len);
			if (envp_len + len + 1 > ENVP_MAX)
				break; // if more than 255 bytes, bail

			dst[len] = '\0';
			// collect total number of copied strings
			envp_len = envp_len + len + 1;
			// increment dst address since we need to put something on next iter
			dst = dst + len + 1;
			// pointer walk, __envp + i
			i++;
		} while (envp_len < ENVP_MAX);
	}

	/*
	at this point, we shoul've collected envp from
		* 0x1001 PATH=/bin
		* 0x1002 VARIABLE=value
		* 0x1002 some_more_env_var=1
	to
		* 0x1234 PATH=/bin\0VARIABLE=value\0some_more_env_var=1\0\0\0\0
	*/

	envp[ENVP_MAX - 1] = '\0';

#ifdef CONFIG_KSU_DEBUG
	pr_info("%s: filename: %s argv[1]:%s envp_len: %zu\n", __func__, path, argv1, envp_len);
#endif
	return ksu_handle_bprm_ksud(path, argv1, envp, envp_len);
}

static int sys_read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	unsigned int fd = PT_REGS_PARM1(real_regs);
	char __user **buf_ptr = (char __user **)&PT_REGS_PARM2(real_regs);
	size_t count_ptr = (size_t *)&PT_REGS_PARM3(real_regs);

	return ksu_handle_sys_read(fd, buf_ptr, count_ptr);
}

static int input_handle_event_handler_pre(struct kprobe *p,
					  struct pt_regs *regs)
{
	unsigned int *type = (unsigned int *)&PT_REGS_PARM2(regs);
	unsigned int *code = (unsigned int *)&PT_REGS_PARM3(regs);
	int *value = (int *)&PT_REGS_CCALL_PARM4(regs);
	return ksu_handle_input_handle_event(type, code, value);
}

static struct kprobe execve_kp = {
	.symbol_name = SYS_EXECVE_SYMBOL,
	.pre_handler = sys_execve_handler_pre,
};

static struct kprobe vfs_read_kp = {
	.symbol_name = SYS_READ_SYMBOL,
	.pre_handler = sys_read_handler_pre,
};

static struct kprobe input_event_kp = {
	.symbol_name = "input_event",
	.pre_handler = input_handle_event_handler_pre,
};


static void do_stop_vfs_read_hook(struct work_struct *work)
{
	unregister_kprobe(&vfs_read_kp);
}

static void do_stop_execve_hook(struct work_struct *work)
{
	unregister_kprobe(&execve_kp);
}

static void do_stop_input_hook(struct work_struct *work)
{
	unregister_kprobe(&input_event_kp);
}
#endif

static void stop_vfs_read_hook()
{
#ifdef CONFIG_KSU_KPROBES_HOOK
	bool ret = schedule_work(&stop_vfs_read_work);
	pr_info("unregister vfs_read kprobe: %d!\n", ret);
#else
 	ksu_vfs_read_hook = false;
 	pr_info("stop vfs_read_hook\n");
#endif
}

static void stop_execve_hook()
{
#ifdef CONFIG_KSU_KPROBES_HOOK
	bool ret = schedule_work(&stop_execve_hook_work);
	pr_info("unregister execve kprobe: %d!\n", ret);
#else
 	pr_info("stop execve_hook\n");
#endif
	ksu_execveat_hook = false;
}

static void stop_input_hook()
{
	static bool input_hook_stopped = false;
	if (input_hook_stopped) {
		return;
	}
	input_hook_stopped = true;
#ifdef CONFIG_KSU_KPROBES_HOOK
	bool ret = schedule_work(&stop_input_hook_work);
	pr_info("unregister input kprobe: %d!\n", ret);
#else
 	ksu_input_hook = false;
 	pr_info("stop input_hook\n");
#endif
}

// ksud: module support
void ksu_ksud_init()
{
#ifdef CONFIG_KSU_KPROBES_HOOK
	int ret;

	ret = register_kprobe(&execve_kp);
	pr_info("ksud: execve_kp: %d\n", ret);

	ret = register_kprobe(&vfs_read_kp);
	pr_info("ksud: vfs_read_kp: %d\n", ret);

	ret = register_kprobe(&input_event_kp);
	pr_info("ksud: input_event_kp: %d\n", ret);

	INIT_WORK(&stop_vfs_read_work, do_stop_vfs_read_hook);
	INIT_WORK(&stop_execve_hook_work, do_stop_execve_hook);
	INIT_WORK(&stop_input_hook_work, do_stop_input_hook);
#endif
}

void ksu_ksud_exit()
{
#ifdef CONFIG_KSU_KPROBES_HOOK
	unregister_kprobe(&execve_kp);
	// this should be done before unregister vfs_read_kp
	// unregister_kprobe(&vfs_read_kp);
	unregister_kprobe(&input_event_kp);
#endif

	is_boot_phase = false;
}
