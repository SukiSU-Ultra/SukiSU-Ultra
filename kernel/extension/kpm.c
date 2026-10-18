// SPDX-License-Identifier: GPL-2.0
/*
 * KPM extension wiring.
 *
 * Connects KSU_EXTENSION_KPM to the actual KPM control surface
 * (kernel/extension/kpm/kpm.c). The sticky-state get/set only flips a
 * soft "KPM has been initialized" bit; KPM is always-on-or-off via the
 * kernel's CONFIG_KPM, so the set handler is largely a no-op. The io
 * handler forwards a struct ksu_kpm_cmd to do_kpm() in the KPM subsys.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>

#include "extension.h"
#include "kpm/kpm.h"

#include "klog.h" // IWYU pragma: keep

int ksu_extension_kpm_get(u32 id, u64 *value)
{
#ifdef CONFIG_KPM
    *value = 1;
#else
    *value = 0;
#endif
    return 0;
}

int ksu_extension_kpm_set(u32 id, u64 value)
{
#ifdef CONFIG_KPM
    pr_info("extension/kpm: set=%llu ignored, KPM is always enabled at runtime\n",
            value);
    return 0;
#else
    if (value) {
        pr_warn("extension/kpm: cannot enable KPM at runtime, kernel was built without it\n");
        return -EOPNOTSUPP;
    }
    return 0;
#endif
}

const struct ksu_extension_handler_ops ksu_extension_kpm_ops = {
    .get = ksu_extension_kpm_get,
    .set = ksu_extension_kpm_set,
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
