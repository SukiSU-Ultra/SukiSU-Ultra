// SPDX-License-Identifier: GPL-2.0
/*
 * KPM extension wiring. Connects KSU_EXTENSION_KPM to the KPM
 * control surface (kernel/extension/kpm/kpm.c).
 *
 * Sticky get: CONFIG_KPM -> 1, else 0. No sticky set; userspace
 * KSU_EXTENSION_SET returns -EOPNOTSUPP.
 *
 * Forced-by-config (force_extension=kpm:<value>) goes through
 * handler->apply_forced. The u64 is decoded as
 *   sub-op = (u32)(value & 0xffffffff)
 *   arg    = (u32)(value >> 32)
 *
 * IMPORTANT: this is a *kernel-internal* ABI between
 * `force_extension_param_set()` and the per-handler `apply_forced`
 * callback. The u64 is never visible to userspace in this code
 * path. The bootloader-side `force_extension=kpm:<value>` is the
 * only producer and is parsed by `kstrtou64(0)`; humans typing
 * this in a boot config will not encounter the (op, arg) split
 * unless they intentionally compose a 64-bit value with a 32-bit
 * sub-op in the low half. (Such a value is meaningful only for
 * sub-ops that actually consume `arg`; today only SUKISU_KPM_VERSION
 * is recognised, and it ignores the arg.)
 *
 * New sub-op authors:
 *   - If your sub-op does not need an argument, do nothing special.
 *     Document the literal value (e.g. `force_extension=kpm:7`).
 *   - If your sub-op DOES need an argument, never write the
 *     `(u32)(value & 0xffffffff)` / `>> 32` bit-twiddling inline.
 *     Use the helpers below — they are the single source of truth
 *     for the encoding, kept in lockstep with the decoder.
 *
 * IMPORTANT: this callback is a *probe*, not an enable hook. KPM
 * availability is fixed at kernel build time (CONFIG_KPM) and cannot
 * be flipped at runtime from the extension hub. force_extension=kpm:1
 * (or any other sub-op) does not load a KPM module, start the KPM
 * watcher, or otherwise alter runtime state. The only recognised
 * sub-op is SUKISU_KPM_VERSION (a no-op dmesg probe that prints
 * whether CONFIG_KPM is on); any other sub-op is a no-op + warning
 * and clears the forced-pending bit because the value has been
 * consumed. If you want a real "force KPM" knob, wire it through
 * ksud's kpm boot stage instead.
 *
 * The userspace ioctl entry point (ksu_extension_kpm_io) is unchanged.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>

#include "kpm/kpm.h"

int ksu_extension_kpm_get(u32 id, u64 *value)
{
#ifdef CONFIG_KPM
    *value = 1;
#else
    *value = 0;
#endif
    return 0;
}

const struct ksu_extension_handler_ops ksu_extension_kpm_ops = {
    .get = ksu_extension_kpm_get,
};

int ksu_extension_kpm_io(u32 id, void __user *raw)
{
#ifdef CONFIG_KPM
    return do_kpm(raw);
#else
    (void)raw;
    return -EOPNOTSUPP;
#endif
}

void ksu_extension_kpm_apply_forced(u32 id, u64 value)
{
    /*
     * Decode using the shared macros in extension.h. The decode
     * direction is part of the kernel-internal ABI; if you change
     * it, also update the KSU_EXTENSION_FORCE_* macros. Today no
     * other consumer exists, so changing one without the other
     * would silently corrupt every KPM force entry.
     */
    u32 op = KSU_EXTENSION_FORCE_OP(value);
    u32 arg = KSU_EXTENSION_FORCE_ARG(value);

    switch (op) {
    case SUKISU_KPM_VERSION:
#ifdef CONFIG_KPM
        pr_info("extension/kpm: forced VERSION probe, KPM is built in (arg=%u)\n", arg);
#else
        pr_warn("extension/kpm: forced VERSION probe, KPM is *not* built in (arg=%u)\n", arg);
#endif
        return;
    default:
        pr_warn("extension/kpm: forced op=%u arg=%u not honoured\n", op, arg);
        return;
    }
}
