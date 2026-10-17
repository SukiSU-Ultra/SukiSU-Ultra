// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Container for KP "infra" helpers (text patching, symbol resolution, fphook
 * runtime, KPM signature verification). The actual KPM module loader lives in
 * kernel/kpm/. The KP internals (hook engine, fphook engine, transit
 * trampolines) are exposed through kernel/include/kp/ so that any KPM
 * compiled for the standard KP ABI can call into the running kernel.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>

#include <log.h>

int kp_patch_memory_init(void);
int kp_fphook_runtime_init(void);
void kp_symres_init(void);

static int __init kp_infra_init(void)
{
    int err;
    logki("kp infra init\n");
    err = kp_patch_memory_init();
    if (err)
        return err;
    kp_symres_init();
    err = kp_fphook_runtime_init();
    if (err)
        return err;
    return 0;
}
postcore_initcall(kp_infra_init);