/* SPDX-License-Identifier: GPL-2.0-only */
#include "feature/avc_spoof.h"
#include "policy/feature.h"
#include "include/klog.h"
#include <linux/jump_label.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif

#ifdef CONFIG_KSU_SUSFS
static int avc_spoof_feature_get(u64 *value)
{
    *value = static_key_enabled(&susfs_is_avc_log_spoofing_enabled) ? 1 : 0;
    return 0;
}

static int avc_spoof_feature_set(u64 value)
{
    bool enable = value != 0;
    bool current_state = static_key_enabled(&susfs_is_avc_log_spoofing_enabled);

    if (enable == current_state)
        return 0;

    if (enable) {
        static_branch_enable(&susfs_is_avc_log_spoofing_enabled);
        pr_info("avc_spoof: enabled susfs_avc_log_spoofing\n");
    } else {
        static_branch_disable(&susfs_is_avc_log_spoofing_enabled);
        pr_info("avc_spoof: disabled susfs_avc_log_spoofing\n");
    }
    return 0;
}

static const struct ksu_feature_handler avc_spoof_handler = {
    .feature_id = KSU_FEATURE_AVC_SPOOF,
    .name = "avc_spoof",
    .get_handler = avc_spoof_feature_get,
    .set_handler = avc_spoof_feature_set,
};

void __init ksu_avc_spoof_init(void)
{
    if (ksu_register_feature_handler(&avc_spoof_handler))
        pr_err("avc_spoof: failed to register feature handler\n");
    else
        pr_info("avc_spoof: feature handler registered\n");
}

void __exit ksu_avc_spoof_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_AVC_SPOOF);
}
#else
void __init ksu_avc_spoof_init(void)
{
    pr_warn("avc_spoof: CONFIG_KSU_SUSFS is disabled; feature unavailable\n");
}

void __exit ksu_avc_spoof_exit(void)
{
}
#endif
