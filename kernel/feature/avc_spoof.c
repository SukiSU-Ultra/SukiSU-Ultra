/* SPDX-License-Identifier: GPL-2.0-only */
/* Adapted from KOWX712/KernelSU slow_avc_audit_defs.h (GPL-2.0-only). */
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include "policy/feature.h"
#include "feature/avc_spoof.h"
#include "infra/symbol_resolver.h"
#include "hook/patch_memory.h"
#include "klog.h"

#ifdef CONFIG_ARM64
#include "avc.h"

struct selinux_state;

static bool enabled;
static bool configured;
static u32 ksu_sid, replacement_sid;
static void *original_audit;
static unsigned int patch_count;
static struct {
    u32 *address;
    u32 original;
    u32 replacement;
} patches[32];

static u32 spoof_sid(u32 sid)
{
    return READ_ONCE(enabled) && sid == READ_ONCE(ksu_sid) ?
           READ_ONCE(replacement_sid) : sid;
}

#define OVERLOAD __attribute__((overloadable))
static int __nocfi OVERLOAD audit_wrapper(u32 ssid, u32 tsid, u16 cls, u32 req,
                                         u32 audited, u32 denied, int result,
                                         struct common_audit_data *a)
{
    typedef int (*fn)(u32, u32, u16, u32, u32, u32, int, struct common_audit_data *);
    return ((fn)original_audit)(ssid, spoof_sid(tsid), cls, req, audited, denied, result, a);
}
static int __nocfi OVERLOAD audit_wrapper(struct selinux_state *state, u32 ssid,
                                         u32 tsid, u16 cls, u32 req, u32 audited,
                                         u32 denied, int result, struct common_audit_data *a)
{
    typedef int (*fn)(struct selinux_state *, u32, u32, u16, u32, u32, u32, int, struct common_audit_data *);
    return ((fn)original_audit)(state, ssid, spoof_sid(tsid), cls, req, audited, denied, result, a);
}
static int __nocfi OVERLOAD audit_wrapper(u32 ssid, u32 tsid, u16 cls, u32 req,
                                         u32 audited, u32 denied, int result,
                                         struct common_audit_data *a, unsigned int flags)
{
    typedef int (*fn)(u32, u32, u16, u32, u32, u32, int, struct common_audit_data *, unsigned int);
    return ((fn)original_audit)(ssid, spoof_sid(tsid), cls, req, audited, denied, result, a, flags);
}
static int __nocfi OVERLOAD audit_wrapper(struct selinux_state *state, u32 ssid,
                                         u32 tsid, u16 cls, u32 req, u32 audited,
                                         u32 denied, int result, struct common_audit_data *a,
                                         unsigned int flags)
{
    typedef int (*fn)(struct selinux_state *, u32, u32, u16, u32, u32, u32, int, struct common_audit_data *, unsigned int);
    return ((fn)original_audit)(state, ssid, spoof_sid(tsid), cls, req, audited, denied, result, a, flags);
}
static typeof(slow_avc_audit) *wrapper = audit_wrapper;

/* Collect and validate ALL sites before touching executable memory. */
static int collect_sites(void)
{
    static const char *const names[] = {
        "slow_avc_audit", "avc_has_perm", "avc_has_perm_flags", "avc_has_extended_perms",
    };
    unsigned long addresses[ARRAY_SIZE(names)] = {};
    unsigned int i, j;
    char symbol[KSYM_NAME_LEN], *module;
    unsigned long addr, size, offset;
    int ret;

    patch_count = 0;
    ret = ksu_lookup_kernel_symbols(names, addresses, ARRAY_SIZE(names));
    if (ret < 0)
        return ret;
    original_audit = (void *)addresses[0];
    if (!original_audit)
        return -ENOENT;
    for (i = 1; i < ARRAY_SIZE(names); i++) {
        addr = addresses[i];
        if (!addr)
            continue;
        if (!kallsyms_lookup(addr, &size, &offset, &module, symbol) || offset || module)
            return -EINVAL;
        for (j = 0; j + sizeof(u32) <= size; j += sizeof(u32)) {
            u32 *site = (u32 *)(addr + j);
            u32 insn = READ_ONCE(*site);
            s64 displacement;
            unsigned int k;
            if ((insn & 0xfc000000U) != 0x94000000U)
                continue;
            displacement = (s64)(s32)((insn & 0x03ffffffU) << 6) >> 4;
            if ((unsigned long)site + displacement != (unsigned long)original_audit)
                continue;
            for (k = 0; k < patch_count; k++)
                if (patches[k].address == site)
                    break;
            if (k != patch_count)
                continue;
            displacement = (unsigned long)wrapper - (unsigned long)site;
            if ((displacement & 3) || displacement < -(1LL << 27) || displacement >= (1LL << 27))
                return -ERANGE;
            if (patch_count == ARRAY_SIZE(patches))
                return -ENOSPC;
            patches[patch_count].address = site;
            patches[patch_count].original = insn;
            patches[patch_count++].replacement = 0x94000000U | ((displacement >> 2) & 0x03ffffffU);
        }
    }
    return patch_count ? 0 : -ENOENT;
}

static int resolve_sids(void)
{
    u32 source = 0, target = 0;
    int ret;
    ret = security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"), &source);
    if (ret)
        return ret;
    ret = security_secctx_to_secid("u:r:priv_app:s0:c512,c768",
                                 strlen("u:r:priv_app:s0:c512,c768"), &target);
    if (ret)
        return ret;
    if (!source || !target)
        return -EINVAL;
    WRITE_ONCE(ksu_sid, source);
    WRITE_ONCE(replacement_sid, target);
    return 0;
}

static int avc_get(u64 *value)
{
    *value = READ_ONCE(enabled);
    return 0;
}
static int avc_set(u64 value)
{
    int ret;
    /* Serialized by feature_mutex. Hooks remain installed until module exit. */
    if (value) {
        ret = resolve_sids();
        if (ret)
            return ret;
    }
    WRITE_ONCE(enabled, value != 0);
    WRITE_ONCE(configured, true);
    return 0;
}
static const struct ksu_feature_handler handler = {
    .feature_id = KSU_FEATURE_AVC_SPOOF,
    .name = "avc_spoof",
    .get_handler = avc_get,
    .set_handler = avc_set,
};
static bool registered;

void __init ksu_avc_spoof_init(void)
{
    unsigned int i;
    int ret = collect_sites();
    if (ret) {
        patch_count = 0;
        pr_warn("avc_spoof: unsupported call layout: %d\n", ret);
        return;
    }
    /*
     * A caller may be sleeping inside slow_avc_audit with a return address
     * into our wrapper. stop_machine + synchronize_rcu cannot drain that
     * stack. Pin the module instead of allowing an unsafe unload (upstream
     * traps on unload). Disabling the feature still restores original SID
     * reporting without changing instructions on live callers' stacks.
     */
#ifdef MODULE
    __module_get(THIS_MODULE);
#endif
    for (i = 0; i < patch_count; i++) {
        ret = ksu_patch_text(patches[i].address, &patches[i].replacement, sizeof(u32),
                             KSU_PATCH_TEXT_FLUSH_ICACHE);
        if (ret) {
            while (i--) {
                if (ksu_patch_text(patches[i].address, &patches[i].original, sizeof(u32),
                                   KSU_PATCH_TEXT_FLUSH_ICACHE))
                    panic("avc_spoof: cannot roll back audit call site");
            }
            patch_count = 0;
            pr_err("avc_spoof: patch failed: %d\n", ret);
            return;
        }
    }
    registered = !ksu_register_feature_handler(&handler);
}
void ksu_avc_spoof_late_init(void)
{
    /* Do not overwrite persisted or boot-forced settings at boot completion. */
    if (registered && !READ_ONCE(configured) && !ksu_feature_is_forced(KSU_FEATURE_AVC_SPOOF))
        ksu_set_feature(KSU_FEATURE_AVC_SPOOF, 1);
}
void __exit ksu_avc_spoof_exit(void)
{
    unsigned int i;
    WRITE_ONCE(enabled, false);
    for (i = 0; i < patch_count; i++) {
        int ret = ksu_patch_text(patches[i].address, &patches[i].original, sizeof(u32),
                                 KSU_PATCH_TEXT_FLUSH_ICACHE);
        if (ret)
            panic("avc_spoof: cannot restore audit call site: %d", ret);
    }
    synchronize_rcu();
    if (registered)
        ksu_unregister_feature_handler(KSU_FEATURE_AVC_SPOOF);
}
#else
void __init ksu_avc_spoof_init(void) { }
void ksu_avc_spoof_late_init(void) { }
void __exit ksu_avc_spoof_exit(void) { }
#endif
