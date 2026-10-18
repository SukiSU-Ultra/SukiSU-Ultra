static const char KERNEL_SU_RC[] =
	"\n"

	"on post-fs-data\n"
	"    start logd\n"
	// We should wait for the post-fs-data finish
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " post-fs-data\n"
	"\n"

	"on nonencrypted\n"
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " services\n"
	"\n"

	"on property:vold.decrypt=trigger_restart_framework\n"
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " services\n"
	"\n"

	"on property:sys.boot_completed=1\n"
	"    exec u:r:" KERNEL_SU_DOMAIN ":s0 root -- " KSUD_PATH " boot-completed\n"
	"\n"

	"\n";

static void stop_init_rc_hook();

static bool ksu_vfs_read_hook __read_mostly = true;
static bool ksu_input_hook __read_mostly = true;

#ifdef KSU_CAN_USE_JUMP_LABEL
DEFINE_STATIC_KEY_TRUE(ksud_vfs_read_key);
static inline void ksu_disable_vfs_read_branch()
{
	pr_info("vfs_read_hook: remove vfs_read branches\n");
	static_branch_disable(&ksud_vfs_read_key);
	smp_mb();
}
#else
#define ksu_disable_vfs_read_branch() do { } while (0)
#endif

static ssize_t (*orig_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t (*orig_read_iter)(struct kiocb *, struct iov_iter *);
static struct file_operations fops_proxy;
static ssize_t ksu_rc_pos = 0;
const size_t ksu_rc_len = sizeof(KERNEL_SU_RC) - 1;

// Prefer /metadata/vold, else /metadata/watchdog, else /metadata.
#define MODULE_RC_PATH_VOLD "/metadata/vold/ksu/modules.rc"
#define MODULE_RC_PATH_WATCHDOG "/metadata/watchdog/ksu/modules.rc"
#define MODULE_RC_PATH_DEFAULT "/metadata/ksu/modules.rc"
#define MODULE_RC_MAX (1u << 20) /* 1 MiB cap */
static char *module_rc_buf;
static size_t module_rc_len = 0;
static ssize_t module_rc_pos;

static struct file *open_module_rc(const char **chosen_path)
{
	struct file *f = filp_open(MODULE_RC_PATH_VOLD, O_RDONLY, 0);
	if (!IS_ERR(f)) {
		*chosen_path = MODULE_RC_PATH_VOLD;
		return f;
	}
	f = filp_open(MODULE_RC_PATH_WATCHDOG, O_RDONLY, 0);
	if (!IS_ERR(f)) {
		*chosen_path = MODULE_RC_PATH_WATCHDOG;
		return f;
	}
	f = filp_open(MODULE_RC_PATH_DEFAULT, O_RDONLY, 0);
	if (!IS_ERR(f)) {
		*chosen_path = MODULE_RC_PATH_DEFAULT;
		return f;
	}
	*chosen_path = MODULE_RC_PATH_DEFAULT;
	return f;
}

static void load_module_rc_once(void)
{
	static bool loaded = false;
	struct file *f;
	const char *path = NULL;
	loff_t pos = 0;
	ssize_t r;
	size_t fsize;
	const struct cred *old_cred;

	if (loaded)
		return;
	loaded = true;
 
	old_cred = override_creds(ksu_cred);

	f = open_module_rc(&path);
	if (IS_ERR(f)) {
		pr_info("module rc: open %s failed: %ld\n", path, PTR_ERR(f));
		goto out_revert_creds;
	}

	if (!S_ISREG(file_inode(f)->i_mode)) {
		pr_warn("module rc: %s is not a regular file\n", path);
		goto out_close_file;
	}

	fsize = i_size_read(file_inode(f));
	if (fsize == 0) {
		pr_warn("module rc: skip empty module rc\n");
		goto out_close_file;
	}

	module_rc_buf = kvmalloc(fsize, GFP_KERNEL);
	if (!module_rc_buf) {
		pr_err("module rc: alloc %zu failed\n", fsize);
		goto out_close_file;
	}

	r = kernel_read(f, module_rc_buf, fsize, &pos);
 
	if (r <= 0) {
		pr_err("module rc: read failed: %zd\n", r);
		kvfree(module_rc_buf);
		module_rc_buf = NULL;
		goto out_close_file;
	}

	module_rc_len = r;
	pr_info("module rc: loaded %zu bytes from %s\n", module_rc_len, path);

out_close_file:
	filp_close(f, NULL);

out_revert_creds:
	revert_creds(old_cred);
}

static void free_module_rc(void)
{
	kvfree(module_rc_buf);
	module_rc_buf = NULL;
	module_rc_len = 0;
}

static noinline void set_module_rc_len_vfs()
{
	static bool loaded = false;
	if (loaded)
		return;

	loaded = true;

	struct path path;

	int err = kern_path(MODULE_RC_PATH_VOLD, LOOKUP_FOLLOW, &path);
	if (err)
		err = kern_path(MODULE_RC_PATH_WATCHDOG, LOOKUP_FOLLOW, &path);
	if (err)
		err = kern_path(MODULE_RC_PATH_DEFAULT, LOOKUP_FOLLOW, &path);
	if (err)
		return; 

	struct inode *inode = d_inode(path.dentry);
	if (inode && S_ISREG(inode->i_mode))
		module_rc_len = i_size_read(inode);

	path_put(&path);

	if (module_rc_len > MODULE_RC_MAX)
		module_rc_len = MODULE_RC_MAX;

	pr_info("%s: %zu\n", __func__, module_rc_len);

	return;
}

// https://cs.android.com/android/platform/superproject/main/+/main:system/core/init/parser.cpp;l=144;drc=61197364367c9e404c7da6900658f1b16c42d0da
// https://cs.android.com/android/platform/superproject/main/+/main:system/libbase/file.cpp;l=241-243;drc=61197364367c9e404c7da6900658f1b16c42d0da
// The system will read init.rc file until EOF, whenever read() returns 0,
// so we begin append ksu rc when we meet EOF.

static ssize_t read_proxy(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret = 0;
	size_t append_count;
	if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
		goto append_ksu_rc;
	if (ksu_rc_pos >= ksu_rc_len && module_rc_pos < module_rc_len)
		goto append_module_rc;

	ret = orig_read(file, buf, count, pos);
	if (ret != 0) {
		return ret;
	}
	if (ksu_rc_pos >= ksu_rc_len && module_rc_pos >= module_rc_len) {
		return ret;
	}
	pr_info("read_proxy: orig read finished, start append rc\n");

append_ksu_rc:
	if (ksu_rc_pos < ksu_rc_len) {
		append_count = ksu_rc_len - ksu_rc_pos;
		if (append_count > count - ret)
			append_count = count - ret;
		// copy_to_user returns the number of bytes that could not be copied
		if (copy_to_user(buf + ret, KERNEL_SU_RC + ksu_rc_pos, append_count)) {
			pr_info("read_proxy: append error, totally appended %ld\n", ksu_rc_pos);
			return ret;
		}
		pr_info("read_proxy: append static %zu\n", append_count);
		ksu_rc_pos += append_count;
		ret += append_count;
		if (ksu_rc_pos == ksu_rc_len)
			pr_info("read_proxy: static append done\n");
	}

append_module_rc:
	if (module_rc_pos < module_rc_len && (size_t)ret < count) {
		append_count = module_rc_len - module_rc_pos;
		if (append_count > count - ret)
			append_count = count - ret;
		if (copy_to_user(buf + ret, module_rc_buf + module_rc_pos, append_count)) {
			pr_info("read_proxy: module append error, totally appended %zd\n", module_rc_pos);
			return ret;
		}
		pr_info("read_proxy: append module %zu\n", append_count);
		module_rc_pos += append_count;
		ret += append_count;
		if (module_rc_pos == (ssize_t)module_rc_len) {
			pr_info("read_proxy: module append done\n");
			free_module_rc();
		}
	}

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0) || defined(KSU_HAS_FOP_READ_ITER)
static ssize_t read_iter_proxy(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret = 0;
	size_t append_count;
	if (ksu_rc_pos && ksu_rc_pos < ksu_rc_len)
		goto append_ksu_rc;
	if (ksu_rc_pos >= ksu_rc_len && module_rc_pos < module_rc_len)
		goto append_module_rc;

	ret = orig_read_iter(iocb, to);
	if (ret != 0) {
		return ret;
	}
	if (ksu_rc_pos >= ksu_rc_len && module_rc_pos >= module_rc_len) {
		return ret;
	}
	pr_info("read_iter_proxy: orig read finished, start append rc\n");

append_ksu_rc:
	if (ksu_rc_pos < ksu_rc_len) {
		// copy_to_iter returns the number of bytes successfully copied
		append_count = copy_to_iter(KERNEL_SU_RC + ksu_rc_pos, ksu_rc_len - ksu_rc_pos, to);
		if (!append_count) {
			pr_info("read_iter_proxy: append error, totally appended %ld\n", ksu_rc_pos);
			return ret;
		}
		pr_info("read_iter_proxy: append static %zu\n", append_count);
		ksu_rc_pos += append_count;
		ret += append_count;
		if (ksu_rc_pos == ksu_rc_len) {
			pr_info("read_iter_proxy: static append done\n");
		}
	}

append_module_rc:
	if (module_rc_pos < module_rc_len) {
		append_count = copy_to_iter(module_rc_buf + module_rc_pos, module_rc_len - module_rc_pos, to);
		if (!append_count) {
			pr_info("read_iter_proxy: module append error, appended %zd\n", module_rc_pos);
			return ret;
		}
		pr_info("read_iter_proxy: append module %zu\n", append_count);
		module_rc_pos += append_count;
		ret += append_count;
		if (module_rc_pos == (ssize_t)module_rc_len) {
			pr_info("read_iter_proxy: module append done\n");
			free_module_rc();
		}
	}
	return ret;
}
#endif

static bool is_init_rc(struct file *fp)
{
	// we are only interested in `init-like` process
	// catch generic_init, init
	if (!strstr(current->comm, "init")) {
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
	char path[256] = {0};
	char *dpath = d_path(&fp->f_path, path, sizeof(path));

	if (IS_ERR(dpath)) {
		return false;
	}

	if (!!strcmp(dpath, "/init.rc") && !!strcmp(dpath, "/system/etc/init/hw/init.rc")) {
		return false;
	}

	pr_info("%s: %s \n", __func__, dpath);

	return true;
}

static noinline void ksu_install_rc_hook(struct file *file)
{
	if (!is_init_rc(file)) {
		return;
	}

	// we only process the first read
	static bool rc_hooked = false;
	if (rc_hooked) {
		// we don't need these hooks, unregister it!
		return;
	}
	rc_hooked = true;
	stop_init_rc_hook();

	// since we already have domains, selinux is initialized, we can apply rules and shit
	// https://github.com/LineageOS/android_system_core_old/blob/ecbcdafc3/init/init.cpp#L669
	pr_info("%s: init.rc second stage, fp: 0x%lx \n", __func__, (uintptr_t)file);
	apply_kernelsu_rules();
	cache_sid();
	setup_ksu_cred();
	ksu_grab_init_session_keyring();
	ksu_feature_apply_forced();

	// now we can sure that the init process is reading
	// `/system/etc/init/init.rc`

	load_module_rc_once();

	pr_info("read init.rc, comm: %s, rc_count: %zu, module_rc: %zu\n", current->comm, ksu_rc_len, module_rc_len);

	// Now we need to proxy the read and modify the result!
	// But, we can not modify the file_operations directly, because it's in read-only memory.
	// We just replace the whole file_operations with a proxy one.
	memcpy(&fops_proxy, file->f_op, sizeof(struct file_operations));
	orig_read = file->f_op->read;
	if (orig_read) {
		fops_proxy.read = read_proxy;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0) || defined(KSU_HAS_FOP_READ_ITER)
	orig_read_iter = file->f_op->read_iter;
	if (orig_read_iter) {
		fops_proxy.read_iter = read_iter_proxy;
	}
#endif
	// replace the file_operations
	file->f_op = &fops_proxy;

	return;
}

// for sys_read kp / syscall table
static noinline void ksu_handle_sys_read_fd(unsigned int fd)
{
	if (likely(!ksu_vfs_read_hook))
		return;

	struct file *file = fget(fd);
	if (!file) {
		return;
	}
	ksu_install_rc_hook(file);
	fput(file);
}

#define STAT_NATIVE 0
#define STAT_STAT64 1
static inline void ksu_common_newfstat_ret(unsigned int fd_int, void **statbuf_ptr, 
			const int type, const char *syscall_name)
{
	struct file *file = fget(fd_int);
	if (!file)
		return;

	if (!is_init_rc(file)) {
		fput(file);
		return;
	}
	fput(file);

	uintptr_t statbuf_ptr_local = (uintptr_t)*(void **)statbuf_ptr;
	void __user *statbuf = (void __user *)statbuf_ptr_local;
	if (!statbuf)
		return;

	// if init process is running, try to grab module_rc length
	// preempt check is because we are also running newfstat hook on kprobe
	// and we really cannot kern_path on it safely
	if (preemptible())
		set_module_rc_len_vfs();

	pr_info("%s: stat init.rc \n", syscall_name);

	// we do this for kretprobe's reusability
	// this is pretty short, so nbd
	bool got_flipped = false;
	if (!preemptible()) {
		preempt_enable();
		got_flipped = true;
	}

/**
 * NOTE: Workaround to OABI's (likely) write-alignment issue.
 * weirdly enough dedicated copying with offsetof causes an issue! (somehow byte 44 is misaligned?!)
 * here we copy the whole struct, edit and write it over back!
 */
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
	if (type == STAT_NATIVE)
		goto stat_native;
	
	struct stat64 k_stat64;
	if (copy_from_user_retry(&k_stat64, statbuf, sizeof(struct stat64))) {
		pr_info("%s: read statbuf 0x%lx failed \n", syscall_name, (uintptr_t)statbuf);
		goto out;
	}

	// take note of signed + unsigned math here (ksu_rc_len, module_rc_len are size_t)
	// st_size is signed long long
	long long stat64_old_size = (long long)k_stat64.st_size;
	long long stat64_new_size = stat64_old_size + (long long)ksu_rc_len + (long long)module_rc_len;

	pr_info("%s: adding ksu_rc_len: %lld -> %lld (ksu_rc_len: %zu, module_rc_len: %zu) \n", syscall_name, stat64_old_size, stat64_new_size, ksu_rc_len, module_rc_len);

	k_stat64.st_size = stat64_new_size;

	if (copy_to_user(statbuf, &k_stat64, sizeof(struct stat64)))
		pr_info("%s: copy_to_user stat64 failed\n", syscall_name);

	goto out;

stat_native:;
#endif
	struct stat k_stat;
	if (copy_from_user_retry(&k_stat, statbuf, sizeof(struct stat))) {
		pr_info("%s: read statbuf 0x%lx failed \n", syscall_name, (uintptr_t)statbuf);
		goto out;
	}

	// take note of signed + unsigned math here (ksu_rc_len, module_rc_len are size_t)
	long stat_old_size = (long)k_stat.st_size;
	long stat_new_size = stat_old_size + (long)ksu_rc_len + (long)module_rc_len;

	pr_info("%s: adding ksu_rc_len: %ld -> %ld (ksu_rc_len: %zu, module_rc_len: %zu) \n", syscall_name, stat_old_size, stat_new_size, ksu_rc_len, module_rc_len);

	k_stat.st_size = stat_new_size;

	if (copy_to_user(statbuf, &k_stat, sizeof(struct stat)))
		pr_info("%s: copy_to_user stat failed\n", syscall_name);

out:
	if (got_flipped)
		preempt_disable();

	return;
}

void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr)
{
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (static_branch_likely(&ksud_vfs_read_key))
		ksu_common_newfstat_ret(*fd, (void **)statbuf_ptr, STAT_NATIVE, "sys_newfstat");
#else
	if (unlikely(ksu_vfs_read_hook))
		ksu_common_newfstat_ret(*fd, (void **)statbuf_ptr, STAT_NATIVE, "sys_newfstat");
#endif
}

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr)
{
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (static_branch_likely(&ksud_vfs_read_key))
		ksu_common_newfstat_ret(*(unsigned int *)fd, (void **)statbuf_ptr, STAT_STAT64, "sys_fstat64"); // WARNING: LE-only!!!
#else
	if (unlikely(ksu_vfs_read_hook))
		ksu_common_newfstat_ret(*(unsigned int *)fd, (void **)statbuf_ptr, STAT_STAT64, "sys_fstat64"); // WARNING: LE-only!!!
#endif
}
#endif

static bool safe_mode_flag = false;
#define VOLUME_PRESS_THRESHOLD_COUNT 3
bool ksu_is_safe_mode()
{
	// don't need to check again, userspace may call multiple times
	static bool already_checked = false;
	if (already_checked)
		return true;

	// stop hook first!
	ksu_stop_input_hook_runtime();

	if (!safe_mode_flag)
		return false;
		
	pr_info("volume keys pressed max times, safe mode detected!\n");
	already_checked = true;
	return true;
}

static void vol_detector_event(struct input_handle *handle, unsigned int type, unsigned int code, int value)
{
	static int vol_up_cnt = 0;
	static int vol_down_cnt = 0;

	if (!value)
		return;
	
	if (type != EV_KEY)
		return;
	
	if (code == KEY_VOLUMEDOWN) {
		vol_down_cnt++;
		pr_info("KEY_VOLUMEDOWN press detected!\n");
	}

	if (code == KEY_VOLUMEUP) {
		vol_up_cnt++;
		pr_info("KEY_VOLUMEUP press detected!\n");
	}

	pr_info("volume_pressed_count: vol_up: %d vol_down: %d\n", vol_up_cnt, vol_down_cnt);

	/*
	 * on upstream we call stop_input_hook() here but this is causing issues
	 * #1. unregistering an input handler inside the input handler is a bad meme
	 * #2. when I tried to defer unreg to a kthread, it also causes issues on some users? nfi.
	 * since unregging is done anyway on ksu_is_safe_mode() or on_post_fs_data() we just dont bother.
	 *
	 */
	if (vol_up_cnt >= VOLUME_PRESS_THRESHOLD_COUNT || vol_down_cnt >= VOLUME_PRESS_THRESHOLD_COUNT) {
		pr_info("volume keys pressed max times, safe mode detected!\n");
		safe_mode_flag = true;
	}
}

static int vol_detector_connect(struct input_handler *handler, struct input_dev *dev,
					  const struct input_device_id *id)
{
	struct input_handle *handle;
	int error;

	handle = kzalloc(sizeof(struct input_handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->dev = dev;
	handle->handler = handler;
	handle->name = "ksu_handle_input";

	error = input_register_handle(handle);
	if (error)
		goto err_free_handle;

	error = input_open_device(handle);
	if (error)
		goto err_unregister_handle;

	return 0;

err_unregister_handle:
	input_unregister_handle(handle);
err_free_handle:
	kfree(handle);
	return error;
}

static const struct input_device_id vol_detector_ids[] = { 
	// we add key volume up so that
	// 1. if you have broken volume down you get shit
	// 2. we can make sure to trigger only ksu safemode, not android's safemode.
	{
		.flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_KEYBIT,
		.evbit = { BIT_MASK(EV_KEY) },
		.keybit = { [BIT_WORD(KEY_VOLUMEUP)] = BIT_MASK(KEY_VOLUMEUP) },
	},
	{
		.flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_KEYBIT,
		.evbit = { BIT_MASK(EV_KEY) },
		.keybit = { [BIT_WORD(KEY_VOLUMEDOWN)] = BIT_MASK(KEY_VOLUMEDOWN) },
	},
	{ }
};

static void vol_detector_disconnect(struct input_handle *handle)
{
	input_close_device(handle);
	input_unregister_handle(handle);
	kfree(handle);
}

MODULE_DEVICE_TABLE(input, vol_detector_ids);

static struct input_handler vol_detector_handler = {
        .event =	vol_detector_event,
        .connect =	vol_detector_connect,
        .disconnect =	vol_detector_disconnect,
        .name =		"ksu",
        .id_table =	vol_detector_ids,
};

static int vol_detector_init()
{
	pr_info("vol_detector: init\n");
	return input_register_handler(&vol_detector_handler);
}

static int vol_detector_exit()
{
	pr_info("vol_detector: exit\n");
	input_unregister_handler(&vol_detector_handler);
	return 0;
}

/**
 * we do this so that if theres no ksud to call on_post_fs_data/ksu_is_safe_mode/on_boot_completed
 * there will be no input handler / extra execve branch that stays around
 * 60s is more than enough time from second_stage to decrypt/post_fs_data
 * if theres no ksud that does that, we trigger the closing of hooks ourselves
 */
static int ksu_hook_watchdog(void *data)
{
	unsigned int i = 0;

	set_user_nice(current, 19); // low prio
	pr_info("%s: kthread init!\n", __func__);

start:
	if (!*(volatile bool *)&ksu_input_hook)
		goto bail;

	msleep(5000);

	i++;

	if (i < 12)
		goto start;

	// if this path gets triggerred, it means theres no ksud
	pr_info("%s: ksud probably absent, closing hooks!\n", __func__);

	// close down input hook
	ksu_stop_input_hook_runtime();

	ksu_boot_completed = true;

bail:
	pr_info("%s: kthread exit!\n", __func__);
	return 0;
}

static void stop_init_rc_hook()
{
	ksu_vfs_read_hook = false;
	pr_info("stop vfs_read_hook\n");
	ksu_disable_vfs_read_branch();

	kthread_run(ksu_hook_watchdog, NULL, "watchdog");
}

static void ksu_stop_input_hook_runtime()
{
	if (!ksu_input_hook) { return; }
	ksu_input_hook = false;
	pr_info("stop input_hook\n");
	
	vol_detector_exit();
}

void __init ksu_ksud_init()
{
	vol_detector_init();
}

