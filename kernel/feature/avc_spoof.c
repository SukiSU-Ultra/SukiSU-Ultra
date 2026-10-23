/* SPDX-License-Identifier: GPL-2.0-only */
/* Adapted from KOWX712/KernelSU avc spoofing (GPL-2.0-only). */
#include <linux/security.h>
#include <linux/atomic.h>
#include <linux/version.h>
#include <linux/string.h>

#include "policy/feature.h"
#include "feature/avc_spoof.h"
#include "klog.h"
#include "runtime/ksud_boot.h"

/*
 * AVC logging receives a target SID.  This feature changes only the SID used
 * for audit rendering; it does not change the AVC decision or SELinux policy.
 */
static u32 su_sid;
static u32 ksu_sid;
static u32 priv_app_sid;

/* Disabled until SIDs are resolved and the boot-completed hook installs the probe. */
static atomic_t disable_spoof = ATOMIC_INIT(1);
static bool ksu_avc_spoof_enabled = true;
static bool boot_completed;

#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#include <linux/slab.h>
#include "arch.h"

static struct kprobe *slow_avc_audit_kp;

static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    u32 *tsid;

    if (atomic_read(&disable_spoof))
        return 0;

    /*
     * slow_avc_audit changed ABI across Android/Linux versions:
     *   < 6.4: tsid is the third argument
     * >= 6.4: tsid is the second argument
     *
     * This matches the upstream implementation and keeps the probe from
     * writing to the state/ssid argument on newer kernels.
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    tsid = (u32 *)&PT_REGS_PARM2(regs);
#else
    tsid = (u32 *)&PT_REGS_PARM3(regs);
#endif

    if (*tsid == su_sid || *tsid == ksu_sid) {
        pr_info_ratelimited("avc_spoof: replace tsid %u with %u\n", *tsid, priv_app_sid);
        *tsid = priv_app_sid;
    }
    return 0;
}

static struct kprobe *init_avc_kprobe(const char *name, kprobe_pre_handler_t handler)
{
    struct kprobe *kp = kzalloc(sizeof(*kp), GFP_KERNEL);
    int ret;

    if (!kp)
        return NULL;

    kp->symbol_name = name;
    kp->pre_handler = handler;
    ret = register_kprobe(kp);
    pr_info("avc_spoof: register_%s kprobe: %d\n", name, ret);
    if (ret) {
        kfree(kp);
        return NULL;
    }
    return kp;
}

static void destroy_avc_kprobe(struct kprobe **kp_ptr)
{
    struct kprobe *kp = *kp_ptr;

    if (!kp)
        return;
    unregister_kprobe(kp);
    synchronize_rcu();
    kfree(kp);
    *kp_ptr = NULL;
}
#endif /* CONFIG_KPROBES */

static int get_avc_sids(void)
{
    int ret;

    ret = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);
    if (ret) {
        pr_info("avc_spoof: su SID not found\n");
        return ret;
    }
    pr_info("avc_spoof: su SID: %u\n", su_sid);

    ret = security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &ksu_sid);
    if (ret) {
        pr_info("avc_spoof: ksu SID not found\n");
        return ret;
    }
    pr_info("avc_spoof: ksu SID: %u\n", ksu_sid);

    ret = security_secctx_to_secid("u:r:priv_app:s0:c512,c768",
                                   strlen("u:r:priv_app:s0:c512,c768"),
                                   &priv_app_sid);
    if (ret) {
        pr_info("avc_spoof: priv_app SID not found\n");
        return ret;
    }
    pr_info("avc_spoof: priv_app SID: %u\n", priv_app_sid);
    return 0;
}

void ksu_avc_spoof_disable(void)
{
#ifdef CONFIG_KPROBES
    pr_info("avc_spoof: unregister slow_avc_audit kprobe\n");
    destroy_avc_kprobe(&slow_avc_audit_kp);
#endif
    atomic_set(&disable_spoof, 1);
    pr_info("avc_spoof: slow_avc_audit spoofing disabled\n");
}

void ksu_avc_spoof_enable(void)
{
    int ret = get_avc_sids();

    if (ret) {
        pr_info("avc_spoof: SID resolution failed: %d\n", ret);
        return;
    }

#ifdef CONFIG_KPROBES
    if (!slow_avc_audit_kp) {
        pr_info("avc_spoof: register slow_avc_audit kprobe\n");
        slow_avc_audit_kp = init_avc_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);
        if (!slow_avc_audit_kp) {
            atomic_set(&disable_spoof, 1);
            pr_err("avc_spoof: failed to register slow_avc_audit kprobe\n");
            return;
        }
    }
    atomic_set(&disable_spoof, 0);
    pr_info("avc_spoof: slow_avc_audit spoofing enabled\n");
#else
    pr_err("avc_spoof: CONFIG_KPROBES is disabled\n");
#endif
}

static int avc_spoof_feature_get(u64 *value)
{
    *value = ksu_avc_spoof_enabled ? 1 : 0;
    return 0;
}

static int avc_spoof_feature_set(u64 value)
{
    bool enable = value != 0;

    if (enable == ksu_avc_spoof_enabled) {
        pr_info("avc_spoof: no need to change\n");
        return 0;
    }

    ksu_avc_spoof_enabled = enable;
    if (boot_completed) {
        if (enable)
            ksu_avc_spoof_enable();
        else
            ksu_avc_spoof_disable();
    }
    pr_info("avc_spoof: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler avc_spoof_handler = {
    .feature_id = KSU_FEATURE_AVC_SPOOF,
    .name = "avc_spoof",
    .get_handler = avc_spoof_feature_get,
    .set_handler = avc_spoof_feature_set,
};
static bool avc_spoof_registered;

void ksu_avc_spoof_late_init(void)
{
    boot_completed = true;
    if (ksu_avc_spoof_enabled)
        ksu_avc_spoof_enable();
}

void __init ksu_avc_spoof_init(void)
{
#ifndef CONFIG_KPROBES
    pr_warn("avc_spoof: CONFIG_KPROBES is disabled; feature unavailable\n");
    return;
#endif
    avc_spoof_registered = !ksu_register_feature_handler(&avc_spoof_handler);
    if (!avc_spoof_registered)
        pr_err("avc_spoof: failed to register feature handler\n");
}

void __exit ksu_avc_spoof_exit(void)
{
    if (ksu_avc_spoof_enabled)
        ksu_avc_spoof_disable();
    if (avc_spoof_registered)
        ksu_unregister_feature_handler(KSU_FEATURE_AVC_SPOOF);
}
