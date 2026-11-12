/* SPDX-License-Identifier: GPL-2.0-only */
/* Adapted from KOWX712/KernelSU avc spoofing (GPL-2.0-only). */
/*
 * AVC logging receives a target SID.  This feature changes only the SID used
 * for audit rendering; it does not change the AVC decision or SELinux policy.
 *
 * The kprobe below is only one of the entry points. Kernels without
 * CONFIG_KPROBES (KPROBES is a Kconfig option, not a version gate: it exists
 * on arm32 since 2.6 and on arm64 since 4.3) are covered through
 * downstream/slow_avc_audit_defs.h instead: arm64 redirects the
 * avc_has_perm* call sites, arm32 patches every bl/b to slow_avc_audit with
 * the kernel's patch_text(), and both paths call ksu_avc_spoof_rewrite_tsid().
 * A manual hook can also call ksu_slow_avc_audit() on other configs.
 */
static u32 su_sid;
static u32 ksu_sid;
static u32 priv_app_sid;

/* Disabled until SIDs are resolved and the boot-completed hook installs the probe. */
static atomic_t disable_spoof = ATOMIC_INIT(1);
static bool ksu_avc_spoof_enabled = true;
static bool boot_completed;

/*
 * Shared with downstream/slow_avc_audit_defs.h. On ARM64 builds where that
 * hook rewrites the avc_has_perm* call sites with arm64_bl_patch(), the calls
 * no longer reach slow_avc_audit(), so the kprobe below never fires. Let the
 * redirected handler honor this feature too, otherwise avc_spoof is a no-op
 * on those kernels (which includes most 3.4 .. 5.4 arm64 builds).
 *
 * Deliberately not gated on disable_spoof: that flag is also raised when the
 * kprobe cannot be registered, while this path can still work.
 */
void ksu_avc_spoof_rewrite_tsid(u32 *tsid)
{
    if (!ksu_avc_spoof_enabled)
        return;
    /* SIDs are not resolved before the boot-completed init; don't match 0. */
    if (!priv_app_sid || (!su_sid && !ksu_sid))
        return;

    if (*tsid == su_sid || *tsid == ksu_sid)
        *tsid = priv_app_sid;
}

#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#include <linux/slab.h>

static struct kprobe *avc_spoof_slow_avc_audit_kp;

static int avc_spoof_slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    u32 *tsid;

    if (atomic_read(&disable_spoof))
        return 0;

    /*
     * slow_avc_audit changed ABI across Android/Linux versions:
     *   3.4 .. 4.16:      (ssid, tsid, ...)            tsid is argument 2
     *   4.17+ / 4.19+:    (state, ssid, tsid, ...)     tsid is argument 3
     *   >= 6.4:           (ssid, tsid, ...)            tsid is argument 2
     *
     * KSU_COMPAT_HAS_SELINUX_STATE covers vendor trees that backported
     * struct selinux_state before 4.19.
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    tsid = (u32 *)&PT_REGS_PARM2(regs);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || defined(KSU_COMPAT_HAS_SELINUX_STATE)
    tsid = (u32 *)&PT_REGS_PARM3(regs);
#else
    tsid = (u32 *)&PT_REGS_PARM2(regs);
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
    destroy_avc_kprobe(&avc_spoof_slow_avc_audit_kp);
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
    if (!avc_spoof_slow_avc_audit_kp) {
        pr_info("avc_spoof: register slow_avc_audit kprobe\n");
        avc_spoof_slow_avc_audit_kp = init_avc_kprobe("slow_avc_audit", avc_spoof_slow_avc_audit_pre_handler);
        if (!avc_spoof_slow_avc_audit_kp) {
            atomic_set(&disable_spoof, 1);
            pr_err("avc_spoof: failed to register slow_avc_audit kprobe\n");
            return;
        }
    }
    atomic_set(&disable_spoof, 0);
    pr_info("avc_spoof: slow_avc_audit spoofing enabled\n");
#else
    /*
     * No kprobe available. The SIDs above still feed the shared
     * slow_avc_audit hook in downstream/slow_avc_audit_defs.h: the arm64
     * avc_has_perm* call-site patch, or the arm32 bl/b call-site patch,
     * both installed when the selinux_hide init thread runs. Other
     * kernels fall back to a manual hook.
     */
#if defined(CONFIG_AUDIT) && defined(CONFIG_ARM64) && defined(CONFIG_KALLSYMS)
    pr_info("avc_spoof: kprobes disabled; applied via the arm64 slow_avc_audit hook\n");
#elif defined(CONFIG_AUDIT) && defined(CONFIG_ARM) && defined(CONFIG_KALLSYMS) && \
    !defined(CONFIG_CPU_ENDIAN_BE8) && !defined(CONFIG_CPU_ENDIAN_BE32)
    pr_info("avc_spoof: kprobes disabled; applied via the arm32 slow_avc_audit hook\n");
#else
    pr_warn("avc_spoof: kprobes disabled; only a manual slow_avc_audit hook can apply this\n");
#endif
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
    avc_spoof_registered = !ksu_register_feature_handler(&avc_spoof_handler);
    if (!avc_spoof_registered)
        pr_err("avc_spoof: failed to register feature handler\n");

#ifndef CONFIG_KPROBES
    pr_warn("avc_spoof: CONFIG_KPROBES is disabled; using the shared slow_avc_audit hook\n");
#endif
}

void __exit ksu_avc_spoof_exit(void)
{
    if (ksu_avc_spoof_enabled)
        ksu_avc_spoof_disable();
    if (avc_spoof_registered)
        ksu_unregister_feature_handler(KSU_FEATURE_AVC_SPOOF);
}
