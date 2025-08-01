#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#ifdef CONFIG_KSU_DEBUG
#include <linux/moduleparam.h>
#endif
#include <crypto/hash.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif

#include "dynamic_sign.h"
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"
#include "manager.h"
#include "throne_tracker.h"

#define MAX_MANAGERS 2
#define MAX_RETRY_COUNT 3
#define RETRY_DELAY_MS 100

// Dynamic sign configuration with atomic operations support
static struct dynamic_sign_config dynamic_sign = {
    .size = 0x300, 
    .hash = "0000000000000000000000000000000000000000000000000000000000000000",
    .is_set = 0
};

// Multi-manager state
static struct manager_info active_managers[MAX_MANAGERS];
static DEFINE_SPINLOCK(managers_lock);
static DEFINE_SPINLOCK(dynamic_sign_lock);

// Work queues for persistent storage and manager rescanning
static struct workqueue_struct *ksu_dynamic_wq;
static struct work_struct ksu_save_dynamic_sign_work;
static struct work_struct ksu_load_dynamic_sign_work;
static struct work_struct ksu_clear_dynamic_sign_work;
static struct work_struct ksu_rescan_manager_work;

// Completion for synchronous operations when needed
static struct completion save_completion;
static struct completion load_completion;

// Error recovery state
static atomic_t save_retry_count = ATOMIC_INIT(0);
static atomic_t load_retry_count = ATOMIC_INIT(0);

bool ksu_is_dynamic_sign_enabled(void)
{
    unsigned long flags;
    bool enabled;
    
    spin_lock_irqsave(&dynamic_sign_lock, flags);
    enabled = dynamic_sign.is_set;
    spin_unlock_irqrestore(&dynamic_sign_lock, flags);
    
    return enabled;
}

void ksu_add_manager(uid_t uid, int signature_index)
{
    unsigned long flags;
    int i;
    
    if (!ksu_is_dynamic_sign_enabled()) {
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
    
    if (!ksu_is_dynamic_sign_enabled()) {
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
    
    if (!ksu_is_dynamic_sign_enabled()) {
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
        return 1;
    }
    
    if (!ksu_is_dynamic_sign_enabled()) {
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

static void clear_dynamic_managers_only(void)
{
    unsigned long flags;
    int i;
    
    spin_lock_irqsave(&managers_lock, flags);
    
    for (i = 0; i < MAX_MANAGERS; i++) {
        if (active_managers[i].is_active) {
            pr_info("Clearing dynamic manager uid=%d for rescan\n", 
                    active_managers[i].uid);
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
    if (ksu_is_dynamic_sign_enabled()) {
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

// Manager rescanning work handler
static void ksu_rescan_manager_work_handler(struct work_struct *work)
{
    pr_info("Starting manager rescan for dynamic sign changes\n");
    
    // Clear only dynamic managers, preserve default manager
    clear_dynamic_managers_only();
    
    // Note: We preserve the traditional manager (index 0) and only rescan for dynamic managers
    pr_info("Preserved traditional manager, rescanning for dynamic managers\n");
    
    // Trigger manager scanning
    ksu_track_throne();
    
    pr_info("Manager rescan completed\n");
}

bool ksu_trigger_manager_rescan(void)
{
    if (!ksu_dynamic_wq) {
        pr_err("Dynamic sign workqueue not initialized\n");
        return false;
    }
    return queue_work(ksu_dynamic_wq, &ksu_rescan_manager_work);
}

// Enhanced file operations with error recovery
static int safe_file_write(struct file *fp, const void *data, size_t size, loff_t *pos)
{
    ssize_t written;
    int retry = 0;
    
    while (retry < MAX_RETRY_COUNT) {
        written = ksu_kernel_write_compat(fp, data, size, pos);
        if (written == size) {
            return 0;
        }
        
        pr_warn("File write failed, attempt %d/%d, written=%zd, expected=%zu\n", 
                retry + 1, MAX_RETRY_COUNT, written, size);
        
        if (written < 0) {
            return written;
        }
        
        retry++;
        if (retry < MAX_RETRY_COUNT) {
            msleep(RETRY_DELAY_MS);
        }
    }
    
    return -EIO;
}

static int safe_file_read(struct file *fp, void *data, size_t size, loff_t *pos)
{
    ssize_t read_bytes;
    int retry = 0;
    
    while (retry < MAX_RETRY_COUNT) {
        read_bytes = ksu_kernel_read_compat(fp, data, size, pos);
        if (read_bytes == size) {
            return 0;
        }
        
        pr_warn("File read failed, attempt %d/%d, read=%zd, expected=%zu\n", 
                retry + 1, MAX_RETRY_COUNT, read_bytes, size);
        
        if (read_bytes < 0) {
            return read_bytes;
        }
        
        retry++;
        if (retry < MAX_RETRY_COUNT) {
            msleep(RETRY_DELAY_MS);
        }
    }
    
    return -EIO;
}

static void do_save_dynamic_sign_with_recovery(struct work_struct *work)
{
    u32 magic = DYNAMIC_SIGN_FILE_MAGIC;
    u32 version = DYNAMIC_SIGN_FILE_VERSION;
    struct dynamic_sign_config config_to_save;
    struct dynamic_sign_config backup_config;
    loff_t off = 0;
    unsigned long flags;
    struct file *fp = NULL;
    int ret = 0;
    int current_retry;

    // Get current retry count
    current_retry = atomic_read(&save_retry_count);
    
    // Backup current state before any operations
    spin_lock_irqsave(&dynamic_sign_lock, flags);
    config_to_save = dynamic_sign;
    backup_config = dynamic_sign;
    spin_unlock_irqrestore(&dynamic_sign_lock, flags);

    if (!config_to_save.is_set) {
        pr_info("Dynamic sign config not set, skipping save\n");
        goto complete;
    }

    pr_info("Saving dynamic sign config (attempt %d/%d)\n", 
            current_retry + 1, MAX_RETRY_COUNT);

    fp = ksu_filp_open_compat(KERNEL_SU_DYNAMIC_SIGN, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(fp)) {
        ret = PTR_ERR(fp);
        pr_err("save_dynamic_sign create file failed: %d\n", ret);
        goto retry_or_fail;
    }

    // Write with error checking
    ret = safe_file_write(fp, &magic, sizeof(magic), &off);
    if (ret) {
        pr_err("save_dynamic_sign write magic failed: %d\n", ret);
        goto cleanup_and_retry;
    }

    ret = safe_file_write(fp, &version, sizeof(version), &off);
    if (ret) {
        pr_err("save_dynamic_sign write version failed: %d\n", ret);
        goto cleanup_and_retry;
    }

    ret = safe_file_write(fp, &config_to_save, sizeof(config_to_save), &off);
    if (ret) {
        pr_err("save_dynamic_sign write config failed: %d\n", ret);
        goto cleanup_and_retry;
    }

    // Force sync to ensure data is written
    if (fp->f_op && fp->f_op->fsync) {
        ret = fp->f_op->fsync(fp, 0, LLONG_MAX, 1);
        if (ret) {
            pr_warn("save_dynamic_sign fsync failed: %d\n", ret);
            // Continue anyway, fsync failure is not critical
        }
    }

    filp_close(fp, 0);
    fp = NULL;

    // Reset retry count on success
    atomic_set(&save_retry_count, 0);
    pr_info("Dynamic sign config saved successfully\n");
    goto complete;

cleanup_and_retry:
    if (fp && !IS_ERR(fp)) {
        filp_close(fp, 0);
        fp = NULL;
    }

retry_or_fail:
    if (current_retry < MAX_RETRY_COUNT - 1) {
        atomic_inc(&save_retry_count);
        pr_info("Retrying save operation in %dms\n", RETRY_DELAY_MS);
        
        // Schedule retry
        if (ksu_dynamic_wq) {
            queue_delayed_work(ksu_dynamic_wq, 
                             (struct delayed_work *)&ksu_save_dynamic_sign_work,
                             msecs_to_jiffies(RETRY_DELAY_MS));
        }
        return;
    } else {
        // All retries failed, restore backup state
        pr_err("Save operation failed after %d attempts, restoring backup state\n", 
               MAX_RETRY_COUNT);
        
        spin_lock_irqsave(&dynamic_sign_lock, flags);
        dynamic_sign = backup_config;
        spin_unlock_irqrestore(&dynamic_sign_lock, flags);
        
        atomic_set(&save_retry_count, 0);
    }

complete:
    complete(&save_completion);
}

static void do_load_dynamic_sign_with_recovery(struct work_struct *work)
{
    loff_t off = 0;
    struct file *fp = NULL;
    u32 magic;
    u32 version;
    struct dynamic_sign_config loaded_config;
    struct dynamic_sign_config backup_config;
    unsigned long flags;
    int ret = 0;
    int i;
    int current_retry;

    // Get current retry count
    current_retry = atomic_read(&load_retry_count);
    
    pr_info("Loading dynamic sign config (attempt %d/%d)\n", 
            current_retry + 1, MAX_RETRY_COUNT);

    // Backup current state
    spin_lock_irqsave(&dynamic_sign_lock, flags);
    backup_config = dynamic_sign;
    spin_unlock_irqrestore(&dynamic_sign_lock, flags);

    fp = ksu_filp_open_compat(KERNEL_SU_DYNAMIC_SIGN, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        ret = PTR_ERR(fp);
        if (ret == -ENOENT) {
            pr_info("No saved dynamic sign config found\n");
            atomic_set(&load_retry_count, 0);
            goto complete;
        } else {
            pr_err("load_dynamic_sign open file failed: %d\n", ret);
            goto retry_or_fail;
        }
    }

    // Read and validate magic
    ret = safe_file_read(fp, &magic, sizeof(magic), &off);
    if (ret || magic != DYNAMIC_SIGN_FILE_MAGIC) {
        pr_err("dynamic sign file invalid magic: %x (expected: %x)\n", 
               magic, DYNAMIC_SIGN_FILE_MAGIC);
        ret = -EINVAL;
        goto cleanup_and_retry;
    }

    // Read version
    ret = safe_file_read(fp, &version, sizeof(version), &off);
    if (ret) {
        pr_err("dynamic sign read version failed: %d\n", ret);
        goto cleanup_and_retry;
    }

    pr_info("dynamic sign file version: %d\n", version);

    // Read config
    ret = safe_file_read(fp, &loaded_config, sizeof(loaded_config), &off);
    if (ret) {
        pr_err("load_dynamic_sign read config failed: %d\n", ret);
        goto cleanup_and_retry;
    }

    // Validate loaded config
    if (loaded_config.size < 0x100 || loaded_config.size > 0x1000) {
        pr_err("Invalid saved config size: 0x%x\n", loaded_config.size);
        ret = -EINVAL;
        goto cleanup_and_retry;
    }

    if (strlen(loaded_config.hash) != 64) {
        pr_err("Invalid saved config hash length: %zu\n", strlen(loaded_config.hash));
        ret = -EINVAL;
        goto cleanup_and_retry;
    }

    // Validate hash format
    for (i = 0; i < 64; i++) {
        char c = loaded_config.hash[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            pr_err("Invalid saved config hash character at position %d: %c\n", i, c);
            ret = -EINVAL;
            goto cleanup_and_retry;
        }
    }

    filp_close(fp, 0);
    fp = NULL;

    // Apply loaded config
    spin_lock_irqsave(&dynamic_sign_lock, flags);
    dynamic_sign = loaded_config;
    spin_unlock_irqrestore(&dynamic_sign_lock, flags);

    // Reset retry count on success
    atomic_set(&load_retry_count, 0);
    pr_info("Dynamic sign config loaded: size=0x%x, hash=%.16s...\n", 
            loaded_config.size, loaded_config.hash);
    goto complete;

cleanup_and_retry:
    if (fp && !IS_ERR(fp)) {
        filp_close(fp, 0);
        fp = NULL;
    }

retry_or_fail:
    if (current_retry < MAX_RETRY_COUNT - 1) {
        atomic_inc(&load_retry_count);
        pr_info("Retrying load operation in %dms\n", RETRY_DELAY_MS);
        
        // Schedule retry
        if (ksu_dynamic_wq) {
            queue_delayed_work(ksu_dynamic_wq, 
                             (struct delayed_work *)&ksu_load_dynamic_sign_work,
                             msecs_to_jiffies(RETRY_DELAY_MS));
        }
        return;
    } else {
        // All retries failed, keep backup state
        pr_err("Load operation failed after %d attempts, keeping current state\n", 
               MAX_RETRY_COUNT);
        atomic_set(&load_retry_count, 0);
    }

complete:
    complete(&load_completion);
}

static bool persistent_dynamic_sign(void)
{
    if (!ksu_dynamic_wq) {
        pr_err("Dynamic sign workqueue not initialized\n");
        return false;
    }
    
    reinit_completion(&save_completion);
    return queue_work(ksu_dynamic_wq, &ksu_save_dynamic_sign_work);
}

static void do_clear_dynamic_sign_file(struct work_struct *work)
{
    loff_t off = 0;
    struct file *fp;
    char zero_buffer[512];
    int ret;

    memset(zero_buffer, 0, sizeof(zero_buffer));

    fp = ksu_filp_open_compat(KERNEL_SU_DYNAMIC_SIGN, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(fp)) {
        pr_err("clear_dynamic_sign create file failed: %ld\n", PTR_ERR(fp));
        return;
    }

    // Write null bytes to overwrite the file content
    ret = safe_file_write(fp, zero_buffer, sizeof(zero_buffer), &off);
    if (ret) {
        pr_err("clear_dynamic_sign write null bytes failed: %d\n", ret);
    } else {
        pr_info("Dynamic sign config file cleared successfully\n");
    }

    filp_close(fp, 0);
}

static bool clear_dynamic_sign_file(void)
{
    if (!ksu_dynamic_wq) {
        pr_err("Dynamic sign workqueue not initialized\n");
        return false;
    }
    return queue_work(ksu_dynamic_wq, &ksu_clear_dynamic_sign_work);
}

int ksu_handle_dynamic_sign(struct dynamic_sign_user_config *config)
{
    unsigned long flags;
    int ret = 0;
    int i;
    
    if (!config) {
        return -EINVAL;
    }
    
    switch (config->operation) {
    case DYNAMIC_SIGN_OP_SET:
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
        
        // Update configuration atomically
        spin_lock_irqsave(&dynamic_sign_lock, flags);
        dynamic_sign.size = config->size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
        strscpy(dynamic_sign.hash, config->hash, sizeof(dynamic_sign.hash));
#else
        strlcpy(dynamic_sign.hash, config->hash, sizeof(dynamic_sign.hash));
#endif
        dynamic_sign.is_set = 1;
        spin_unlock_irqrestore(&dynamic_sign_lock, flags);
        
        // Trigger async save
        persistent_dynamic_sign();
        pr_info("dynamic sign updated: size=0x%x, hash=%.16s... (multi-manager enabled)\n", 
                config->size, config->hash);
        
        // Always trigger manager rescan when dynamic sign is set
        pr_info("Dynamic sign set, triggering manager rescan\n");
        ksu_trigger_manager_rescan();
        break;
        
    case DYNAMIC_SIGN_OP_GET:
        spin_lock_irqsave(&dynamic_sign_lock, flags);
        if (dynamic_sign.is_set) {
            config->size = dynamic_sign.size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
            strscpy(config->hash, dynamic_sign.hash, sizeof(config->hash));
#else
            strlcpy(config->hash, dynamic_sign.hash, sizeof(config->hash));
#endif
            ret = 0;
        } else {
            ret = -ENODATA;
        }
        spin_unlock_irqrestore(&dynamic_sign_lock, flags);
        break;
        
    case DYNAMIC_SIGN_OP_CLEAR:
        spin_lock_irqsave(&dynamic_sign_lock, flags);
        dynamic_sign.size = 0x300;
        strcpy(dynamic_sign.hash, "0000000000000000000000000000000000000000000000000000000000000000");
        dynamic_sign.is_set = 0;
        spin_unlock_irqrestore(&dynamic_sign_lock, flags);
        
        // Clear only dynamic managers, preserve default manager
        clear_dynamic_managers_only();
        
        // Clear file using async operation
        clear_dynamic_sign_file();
        
        pr_info("Dynamic sign config cleared (multi-manager disabled)\n");
        
        // Always trigger manager rescan when dynamic sign is cleared
        pr_info("Dynamic sign cleared, triggering manager rescan\n");
        ksu_trigger_manager_rescan();
        break;
        
    default:
        pr_err("Invalid dynamic sign operation: %d\n", config->operation);
        return -EINVAL;
    }

    return ret;
}

bool ksu_load_dynamic_sign(void)
{
    if (!ksu_dynamic_wq) {
        pr_err("Dynamic sign workqueue not initialized\n");
        return false;
    }
    
    reinit_completion(&load_completion);
    return queue_work(ksu_dynamic_wq, &ksu_load_dynamic_sign_work);
}

void ksu_dynamic_sign_init(void)
{
    int i;
    
    // Create dedicated workqueue for dynamic sign operations
    ksu_dynamic_wq = alloc_workqueue("ksu_dynamic", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
    if (!ksu_dynamic_wq) {
        pr_err("Failed to create dynamic sign workqueue\n");
        return;
    }
    
    // Initialize work structures
    INIT_WORK(&ksu_save_dynamic_sign_work, do_save_dynamic_sign_with_recovery);
    INIT_WORK(&ksu_load_dynamic_sign_work, do_load_dynamic_sign_with_recovery);
    INIT_WORK(&ksu_clear_dynamic_sign_work, do_clear_dynamic_sign_file);
    INIT_WORK(&ksu_rescan_manager_work, ksu_rescan_manager_work_handler);
    
    // Initialize completions
    init_completion(&save_completion);
    init_completion(&load_completion);
    
    // Initialize manager slots
    for (i = 0; i < MAX_MANAGERS; i++) {
        active_managers[i].is_active = false;
    }
    
    // Reset retry counters
    atomic_set(&save_retry_count, 0);
    atomic_set(&load_retry_count, 0);
    
    pr_info("Dynamic sign initialized with enhanced error recovery and dedicated workqueue\n");
    
    // Auto-load existing dynamic sign configuration after initialization
    if (ksu_load_dynamic_sign()) {
        pr_info("Auto-loading dynamic sign configuration...\n");
    } else {
        pr_warn("Failed to schedule auto-load of dynamic sign configuration\n");
    }
}

void ksu_dynamic_sign_exit(void)
{
    // Clear only dynamic managers on exit, preserve default manager
    clear_dynamic_managers_only();
    
    // Wait for any pending operations to complete
    if (ksu_dynamic_wq) {
        flush_workqueue(ksu_dynamic_wq);
        destroy_workqueue(ksu_dynamic_wq);
        ksu_dynamic_wq = NULL;
    }
    
    pr_info("Dynamic sign exited, cleared dynamic managers, preserved default manager\n");
}

// Get dynamic sign configuration for signature verification
bool ksu_get_dynamic_sign_config(unsigned int *size, const char **hash)
{
    unsigned long flags;
    bool valid = false;
    
    spin_lock_irqsave(&dynamic_sign_lock, flags);
    if (dynamic_sign.is_set) {
        if (size) *size = dynamic_sign.size;
        if (hash) *hash = dynamic_sign.hash;
        valid = true;
    }
    spin_unlock_irqrestore(&dynamic_sign_lock, flags);
    
    return valid;
}