#include <linux/cpu.h>
#include <linux/memory.h>
#include <asm-generic/errno-base.h>
#include <net/genetlink.h>
// security/selinux/include/security.h
#include <security.h>
#include <ss/context.h>
#include <ss/services.h>
#include <ss/mls.h>
#include <ss/conditional.h>

static DEFINE_MUTEX(selinux_hide_mutex);
bool ksu_selinux_hide_enabled __read_mostly = false;
bool ksu_selinux_hide_running __read_mostly = false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#else
struct selinux_state fake_state;
#endif
#ifdef KSU_COMPAT_USE_STATIC_KEY
DEFINE_STATIC_KEY_FALSE(fake_status_initialize_key);
#endif
struct page *fake_status = NULL;

void initialize_fake_status()
{
    mutex_lock(&selinux_state.status_lock);
    if (fake_status)
        goto out;
    if (!selinux_state.status_page) {
        pr_warn("initialize_fake_status: status_page not exist\n");
        goto out;
    }

    struct selinux_kernel_status *status = page_address(selinux_state.status_page);
    if (!status->enforcing) {
        pr_warn("initialize_fake_status: skip not enforcing\n");
        goto out;
    }

    struct page *new_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!new_page) {
        pr_err("initialize_fake_status: failed to allocate page\n");
        goto out;
    }

    struct selinux_kernel_status *new_status = page_address(new_page);
    memcpy(new_status, status, sizeof(*status));

    fake_status = new_page;
    pr_info("initialize_fake_status initialized: sequence=%d, policyload=%d, enforcing=%d\n", new_status->sequence,
            new_status->policyload, new_status->enforcing);

out:
    mutex_unlock(&selinux_state.status_lock);
}

void ksu_selinux_hide_handle_second_stage()
{
    initialize_fake_status();
    // https://github.com/torvalds/linux/blame/e8c2f9fdadee7cbc75134dc463c1e0d856d6e5c7/security/selinux/selinuxfs.c#L2014
    if (fake_status)
        static_key_disable(&fake_status_initialize_key.key);
    else
        pr_warn("selinux_hide: fake status need late initialization\n");
}

void ksu_selinux_hide_handle_post_fs_data()
{
    static_key_disable(&fake_status_initialize_key.key);
    if (!fake_status)
        pr_err("selinux_hide: fake status is not initialized after post-fs-data!\n");
}

static int ksu_selinux_hide_enable()
{
    pr_info("selinux_hide: init selinux hide\n");
    if (!backup_sepolicy) {
        pr_err("no backup sepolicy available, please save feature and reboot to retry!\n");
        return -EAGAIN;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#else
    fake_state.initialized = true;
    fake_state.policy = backup_sepolicy;
#endif

    return 0;
}

static int selinux_hide_feature_get(u64 *value)
{
    *value = ksu_selinux_hide_enabled ? 1 : 0;
    return 0;
}

static int selinux_hide_feature_set(u64 value)
{
    bool enable = value != 0;
    int ret = 0;
    pr_info("selinux_hide: set to %d\n", enable);
    mutex_lock(&selinux_hide_mutex);
    ksu_selinux_hide_enabled = enable;
    if (enable) {
        if (!ksu_selinux_hide_running) {
            ret = ksu_selinux_hide_enable();
            if (!ret) {
                ksu_selinux_hide_running = true;
            }
        }
    } else {
        if (ksu_selinux_hide_running) {
            ksu_selinux_hide_running = false;
        }
    }
    pr_info("selinux_hide: ksu_selinux_hide_enabled: %d, ksu_selinux_hide_running: %d\n",
            ksu_selinux_hide_enabled, ksu_selinux_hide_running);
    mutex_unlock(&selinux_hide_mutex);
    return ret;
}

static const struct ksu_feature_handler selinux_hide_handler = {
    .feature_id = KSU_FEATURE_SELINUX_HIDE,
    .name = "selinux_hide",
    .get_handler = selinux_hide_feature_get,
    .set_handler = selinux_hide_feature_set,
};

void __init ksu_selinux_hide_init(void)
{
    if (ksu_register_feature_handler(&selinux_hide_handler)) {
        pr_err("Failed to register selinux_hide feature handler\n");
    }
    static_key_enable(&fake_status_initialize_key.key);
}

void __exit ksu_selinux_hide_exit(void)
{
    mutex_lock(&selinux_hide_mutex);
    if (ksu_selinux_hide_running) {
        ksu_selinux_hide_running = false;
    }
    mutex_unlock(&selinux_hide_mutex);
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);
    mutex_lock(&selinux_state.status_lock);
    if (fake_status)
        __free_page(fake_status);
    fake_status = NULL;
    mutex_unlock(&selinux_state.status_lock);
}

void ksu_selinux_hide_drop_backup_if_unused()
{
    mutex_lock(&selinux_hide_mutex);
    if (!ksu_selinux_hide_running && backup_sepolicy) {
        pr_info("selinux_hide is not enabled - drop backup_sepolicy\n");
        sidtab_destroy(backup_sepolicy->sidtab);
        kfree(backup_sepolicy->sidtab);
        ksu_destroy_sepolicy(backup_sepolicy);
        backup_sepolicy = NULL;
    }
    mutex_unlock(&selinux_hide_mutex);
}

