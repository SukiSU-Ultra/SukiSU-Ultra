#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/task_work.h>
#include <linux/sched.h>
#include <linux/pid.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task.h>
#endif
#ifdef CONFIG_KSU_DEBUG
#include <linux/moduleparam.h>
#endif
#include <crypto/hash.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif

#include "dynamic_manager.h"
#include "klog.h" // IWYU pragma: keep
#include "manager.h"
#include "ksu.h"

#define MAX_MANAGERS 2

// Dynamic sign configuration
static struct dynamic_manager_config dynamic_manager = {
	.size = 0x300, 
	.hash = "0000000000000000000000000000000000000000000000000000000000000000",
	.is_set = 0
};

// Multi-manager state
static struct manager_info active_managers[MAX_MANAGERS];
static DEFINE_SPINLOCK(managers_lock);
static DEFINE_SPINLOCK(dynamic_manager_lock);

// Task work structure for persistent storage
struct save_dynamic_manager_tw {
	struct callback_head cb;
	struct dynamic_manager_config config;
};

bool ksu_is_dynamic_manager_enabled(void)
{
	unsigned long flags;
	bool enabled;
	
	spin_lock_irqsave(&dynamic_manager_lock, flags);
	enabled = dynamic_manager.is_set;
	spin_unlock_irqrestore(&dynamic_manager_lock, flags);
	
	return enabled;
}

void ksu_add_manager(uid_t uid, int signature_index)
{
	unsigned long flags;
	int i;
	
	if (!ksu_is_dynamic_manager_enabled()) {
		pr_info("Dynamic sign not enabled, skipping multi-manager add\n");
		return;
	}
	
	spin_lock_irqsave(&managers_lock, flags);
	
	// Check if manager already exists and update
	for (i = 0; i < MAX_MANAGERS; i++) {
		if (active_managers[i].is_active && active_managers[i].uid == uid) {
			active_managers[i].signature_index = signature_index;
			spin_unlock_irqrestore(&managers_lock, flags);
			pr_info("Updated manager uid=%d, signature_index=%d\n", uid, signature_index);
			return;
		}
	}
	
	// Find free slot for new manager
	for (i = 0; i < MAX_MANAGERS; i++) {
		if (!active_managers[i].is_active) {
			active_managers[i].uid = uid;
			active_managers[i].signature_index = signature_index;
			active_managers[i].is_active = true;
			spin_unlock_irqrestore(&managers_lock, flags);
			pr_info("Added manager uid=%d, signature_index=%d\n", uid, signature_index);
			return;
		}
	}
	
	spin_unlock_irqrestore(&managers_lock, flags);
	pr_warn("Failed to add manager, no free slots\n");
}

void ksu_remove_manager(uid_t uid)
{
	unsigned long flags;
	int i;
	
	if (!ksu_is_dynamic_manager_enabled()) {
		return;
	}
	
	spin_lock_irqsave(&managers_lock, flags);
	
	for (i = 0; i < MAX_MANAGERS; i++) {
		if (active_managers[i].is_active && active_managers[i].uid == uid) {
			active_managers[i].is_active = false;
			pr_info("Removed manager uid=%d\n", uid);
			break;
		}
	}
	
	spin_unlock_irqrestore(&managers_lock, flags);
}

bool ksu_is_any_manager(uid_t uid)
{
	unsigned long flags;
	bool is_manager = false;
	int i;
	
	if (!ksu_is_dynamic_manager_enabled()) {
		return false;
	}
	
	spin_lock_irqsave(&managers_lock, flags);
	
	for (i = 0; i < MAX_MANAGERS; i++) {
		if (active_managers[i].is_active && active_managers[i].uid == uid) {
			is_manager = true;
			break;
		}
	}
	
	spin_unlock_irqrestore(&managers_lock, flags);
	return is_manager;
}

int ksu_get_manager_signature_index(uid_t uid)
{
	unsigned long flags;
	int signature_index = -1;
	int i;
	
	// Check traditional manager first
	if (ksu_manager_uid != KSU_INVALID_UID && uid == ksu_manager_uid) {
		return DYNAMIC_SIGN_INDEX;
	}
	
	if (!ksu_is_dynamic_manager_enabled()) {
		return -1;
	}
	
	spin_lock_irqsave(&managers_lock, flags);
	
	for (i = 0; i < MAX_MANAGERS; i++) {
		if (active_managers[i].is_active && active_managers[i].uid == uid) {
			signature_index = active_managers[i].signature_index;
			break;
		}
	}
	
	spin_unlock_irqrestore(&managers_lock, flags);
	return signature_index;
}

static void clear_dynamic_manager(void)
{
	unsigned long flags;
	int i;
	
	spin_lock_irqsave(&managers_lock, flags);
	
	for (i = 0; i < MAX_MANAGERS; i++) {
		if (active_managers[i].is_active) {
			pr_info("Clearing dynamic manager uid=%d (signature_index=%d) for rescan\n", 
					active_managers[i].uid, active_managers[i].signature_index);
			active_managers[i].is_active = false;
		}
	}
	
	spin_unlock_irqrestore(&managers_lock, flags);
}

int ksu_get_active_managers(struct manager_list_info *info)
{
	unsigned long flags;
	int i, count = 0;
	
	if (!info) {
		return -EINVAL;
	}

	// Add traditional manager first
	if (ksu_manager_uid != KSU_INVALID_UID && count < 2) {
		info->managers[count].uid = ksu_manager_uid;
		info->managers[count].signature_index = 0;
		count++;
	}
	
	// Add dynamic managers
	if (ksu_is_dynamic_manager_enabled()) {
		spin_lock_irqsave(&managers_lock, flags);
		
		for (i = 0; i < MAX_MANAGERS && count < 2; i++) {
			if (active_managers[i].is_active) {
				info->managers[count].uid = active_managers[i].uid;
				info->managers[count].signature_index = active_managers[i].signature_index;
				count++;
			}
		}
		
		spin_unlock_irqrestore(&managers_lock, flags);
	}
	
	info->count = count;
	return 0;
}

static void do_save_dynamic_manager(struct callback_head *_cb)
{
	struct save_dynamic_manager_tw *tw = container_of(_cb, struct save_dynamic_manager_tw, cb);
	u32 magic = DYNAMIC_MANAGER_FILE_MAGIC;
	u32 version = DYNAMIC_MANAGER_FILE_VERSION;
	loff_t off = 0;
	struct file *fp;
	const struct cred *saved = override_creds(ksu_cred);

	if (!tw->config.is_set) {
		pr_info("Dynamic sign config not set, skipping save\n");
		goto revert;
	}

	fp = filp_open(KERNEL_SU_DYNAMIC_MANAGER, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(fp)) {
		pr_err("save_dynamic_manager create file failed: %ld\n", PTR_ERR(fp));
		goto revert;
	}

	if (kernel_write(fp, &magic, sizeof(magic), &off) != sizeof(magic)) {
		pr_err("save_dynamic_manager write magic failed.\n");
		goto close_file;
	}

	if (kernel_write(fp, &version, sizeof(version), &off) != sizeof(version)) {
		pr_err("save_dynamic_manager write version failed.\n");
		goto close_file;
	}

	if (kernel_write(fp, &tw->config, sizeof(tw->config), &off) != sizeof(tw->config)) {
		pr_err("save_dynamic_manager write config failed.\n");
		goto close_file;
	}

	pr_info("Dynamic sign config saved successfully\n");

close_file:
	filp_close(fp, 0);
revert:
	revert_creds(saved);
	kfree(tw);
}

static void do_load_dynamic_manager(struct callback_head *_cb)
{
	loff_t off = 0;
	ssize_t ret = 0;
	struct file *fp = NULL;
	u32 magic;
	u32 version;
	struct dynamic_manager_config loaded_config;
	unsigned long flags;
	int i;
	const struct cred *saved = override_creds(ksu_cred);

	fp = filp_open(KERNEL_SU_DYNAMIC_MANAGER, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		if (PTR_ERR(fp) == -ENOENT) {
			pr_info("No saved dynamic manager config found\n");
		} else {
			pr_err("load_dynamic_manager open file failed: %ld\n", PTR_ERR(fp));
		}
		goto revert;
	}

	if (kernel_read(fp, &magic, sizeof(magic), &off) != sizeof(magic) ||
		magic != DYNAMIC_MANAGER_FILE_MAGIC) {
		pr_err("dynamic manager file invalid magic: %x!\n", magic);
		goto close_file;
	}

	if (kernel_read(fp, &version, sizeof(version), &off) != sizeof(version)) {
		pr_err("dynamic manager read version failed\n");
		goto close_file;
	}

	pr_info("dynamic manager file version: %d\n", version);

	ret = kernel_read(fp, &loaded_config, sizeof(loaded_config), &off);
	if (ret <= 0) {
		pr_info("load_dynamic_manager read err: %zd\n", ret);
		goto close_file;
	}

	if (ret != sizeof(loaded_config)) {
		pr_err("load_dynamic_manager read incomplete config: %zd/%zu\n", ret, sizeof(loaded_config));
		goto close_file;
	}

	if (loaded_config.size < 0x100 || loaded_config.size > 0x1000) {
		pr_err("Invalid saved config size: 0x%x\n", loaded_config.size);
		goto close_file;
	}

	if (strlen(loaded_config.hash) != 64) {
		pr_err("Invalid saved config hash length: %zu\n", strlen(loaded_config.hash));
		goto close_file;
	}

	// Validate hash format
	for (i = 0; i < 64; i++) {
		char c = loaded_config.hash[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			pr_err("Invalid saved config hash character at position %d: %c\n", i, c);
			goto close_file;
		}
	}

	spin_lock_irqsave(&dynamic_manager_lock, flags);
	dynamic_manager = loaded_config;
	spin_unlock_irqrestore(&dynamic_manager_lock, flags);

	pr_info("Dynamic sign config loaded: size=0x%x, hash=%.16s...\n", 
			loaded_config.size, loaded_config.hash);

close_file:
	filp_close(fp, 0);
revert:
	revert_creds(saved);
	kfree(_cb);
}

static bool persistent_dynamic_manager(void)
{
	struct task_struct *tsk;
	struct save_dynamic_manager_tw *tw;
	unsigned long flags;

	tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
	if (!tsk) {
		pr_err("persistent_dynamic_manager find init task err\n");
		return false;
	}

	tw = kzalloc(sizeof(*tw), GFP_KERNEL);
	if (!tw) {
		pr_err("persistent_dynamic_manager alloc cb err\n");
		goto put_task;
	}

	spin_lock_irqsave(&dynamic_manager_lock, flags);
	tw->config = dynamic_manager;
	spin_unlock_irqrestore(&dynamic_manager_lock, flags);

	tw->cb.func = do_save_dynamic_manager;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	task_work_add(tsk, &tw->cb, TWA_RESUME);
#else
	task_work_add(tsk, &tw->cb, true);
#endif

put_task:
	put_task_struct(tsk);
	return true;
}

static void do_clear_dynamic_manager(struct callback_head *_cb)
{
	loff_t off = 0;
	struct file *fp;
	char zero_buffer[512];
	const struct cred *saved = override_creds(ksu_cred);

	memset(zero_buffer, 0, sizeof(zero_buffer));

	fp = filp_open(KERNEL_SU_DYNAMIC_MANAGER, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(fp)) {
		pr_err("clear_dynamic_manager create file failed: %ld\n", PTR_ERR(fp));
		goto revert;
	}

	// Write null bytes to overwrite the file content
	if (kernel_write(fp, zero_buffer, sizeof(zero_buffer), &off) != sizeof(zero_buffer)) {
		pr_err("clear_dynamic_manager write null bytes failed.\n");
	} else {
		pr_info("Dynamic sign config file cleared successfully\n");
	}

	filp_close(fp, 0);
revert:
	revert_creds(saved);
	kfree(_cb);
}

static bool clear_dynamic_manager_file(void)
{
	struct task_struct *tsk;
	struct callback_head *cb;

	tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
	if (!tsk) {
		pr_err("clear_dynamic_manager_file find init task err\n");
		return false;
	}

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb) {
		pr_err("clear_dynamic_manager_file alloc cb err\n");
		goto put_task;
	}
	cb->func = do_clear_dynamic_manager;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	task_work_add(tsk, cb, TWA_RESUME);
#else
	task_work_add(tsk, cb, true);
#endif

put_task:
	put_task_struct(tsk);
	return true;
}

int ksu_handle_dynamic_manager(struct dynamic_manager_user_config *config)
{
	unsigned long flags;
	int ret = 0;
	int i;
	
	if (!config) {
		return -EINVAL;
	}
	
	switch (config->operation) {
	case DYNAMIC_MANAGER_OP_SET:
		if (config->size < 0x100 || config->size > 0x1000) {
			pr_err("invalid size: 0x%x\n", config->size);
			return -EINVAL;
		}
		
		if (strlen(config->hash) != 64) {
			pr_err("invalid hash length: %zu\n", strlen(config->hash));
			return -EINVAL;
		}
		
		// Validate hash format
		for (i = 0; i < 64; i++) {
			char c = config->hash[i];
			if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
				pr_err("invalid hash character at position %d: %c\n", i, c);
				return -EINVAL;
			}
		}
		
		spin_lock_irqsave(&dynamic_manager_lock, flags);
		dynamic_manager.size = config->size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
		strscpy(dynamic_manager.hash, config->hash, sizeof(dynamic_manager.hash));
#else
		strlcpy(dynamic_manager.hash, config->hash, sizeof(dynamic_manager.hash));
#endif
		dynamic_manager.is_set = 1;
		spin_unlock_irqrestore(&dynamic_manager_lock, flags);
		
		persistent_dynamic_manager();
		pr_info("dynamic manager updated: size=0x%x, hash=%.16s... (multi-manager enabled)\n", 
				config->size, config->hash);
		break;
		
	case DYNAMIC_MANAGER_OP_GET:
		spin_lock_irqsave(&dynamic_manager_lock, flags);
		if (dynamic_manager.is_set) {
			config->size = dynamic_manager.size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
			strscpy(config->hash, dynamic_manager.hash, sizeof(config->hash));
#else
			strlcpy(config->hash, dynamic_manager.hash, sizeof(config->hash));
#endif
			ret = 0;
		} else {
			ret = -ENODATA;
		}
		spin_unlock_irqrestore(&dynamic_manager_lock, flags);
		break;
		
	case DYNAMIC_MANAGER_OP_CLEAR:
		spin_lock_irqsave(&dynamic_manager_lock, flags);
		dynamic_manager.size = 0x300;
		strcpy(dynamic_manager.hash, "0000000000000000000000000000000000000000000000000000000000000000");
		dynamic_manager.is_set = 0;
		spin_unlock_irqrestore(&dynamic_manager_lock, flags);
		
		// Clear only dynamic managers, preserve default manager
		clear_dynamic_manager();
		
		// Clear file using the same method as save
		clear_dynamic_manager_file();
		
		pr_info("Dynamic sign config cleared (multi-manager disabled)\n");
		break;
		
	default:
		pr_err("Invalid dynamic manager operation: %d\n", config->operation);
		return -EINVAL;
	}

	return ret;
}

bool ksu_load_dynamic_manager(void)
{
	struct task_struct *tsk;
	struct callback_head *cb;

	tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
	if (!tsk) {
		pr_err("ksu_load_dynamic_manager find init task err\n");
		return false;
	}

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb) {
		pr_err("ksu_load_dynamic_manager alloc cb err\n");
		goto put_task;
	}
	cb->func = do_load_dynamic_manager;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	task_work_add(tsk, cb, TWA_RESUME);
#else
	task_work_add(tsk, cb, true);
#endif

put_task:
	put_task_struct(tsk);
	return true;
}

void ksu_dynamic_manager_init(void)
{
	int i;
	
	// Initialize manager slots
	for (i = 0; i < MAX_MANAGERS; i++) {
		active_managers[i].is_active = false;
	}

	ksu_load_dynamic_manager();
	
	pr_info("Dynamic sign initialized with conditional multi-manager support\n");
}

void ksu_dynamic_manager_exit(void)
{
	struct task_struct *tsk;
	struct save_dynamic_manager_tw *tw;
	unsigned long flags;

	clear_dynamic_manager();
	
	// Save current config before exit
	tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
	if (!tsk) {
		pr_err("ksu_dynamic_manager_exit find init task err\n");
		return;
	}

	tw = kzalloc(sizeof(*tw), GFP_KERNEL);
	if (!tw) {
		pr_err("ksu_dynamic_manager_exit alloc cb err\n");
		goto put_task;
	}

	spin_lock_irqsave(&dynamic_manager_lock, flags);
	tw->config = dynamic_manager;
	spin_unlock_irqrestore(&dynamic_manager_lock, flags);

	tw->cb.func = do_save_dynamic_manager;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	task_work_add(tsk, &tw->cb, TWA_RESUME);
#else
	task_work_add(tsk, &tw->cb, true);
#endif

put_task:
	put_task_struct(tsk);
	pr_info("Dynamic sign exited with persistent storage\n");
}

// Get dynamic manager configuration for signature verification
bool ksu_get_dynamic_manager_config(unsigned int *size, const char **hash)
{
	unsigned long flags;
	bool valid = false;
	
	spin_lock_irqsave(&dynamic_manager_lock, flags);
	if (dynamic_manager.is_set) {
		if (size) *size = dynamic_manager.size;
		if (hash) *hash = dynamic_manager.hash;
		valid = true;
	}
	spin_unlock_irqrestore(&dynamic_manager_lock, flags);
	
	return valid;
}
