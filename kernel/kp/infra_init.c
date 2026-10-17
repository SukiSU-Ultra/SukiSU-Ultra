// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Container for KP "infra" helpers (text patching, symbol resolution, fphook
 * runtime, KPM signature verification). The actual KPM module loader lives in
 * kernel/kpm/. The KP internals (hook engine, fphook engine, transit
 * trampolines) are exposed through kernel/include/kp/ so that any KPM
 * compiled for the standard KP ABI can call into the running kernel.
 *
 * This file is the standalone KP LKM entry point.  In the upstream KP build
 * kp_infra_init() is registered via postcore_initcall() so it runs after the
 * kernel's "init" level.  SukiSU-Ultra does NOT link this file into its
 * kernelsu LKM (see kernel/Kbuild) -- doing so produced a duplicate
 * `init_module` symbol against core/init.o, and the only thing this init
 * sequence does for SukiSU is look up a handful of kallsyms entries, which
 * core/init.c::kernelsu_init() drives inline (after ksu_init_symbol_resolver)
 * to avoid the LTO + post-build check_symbol pitfalls.  This file therefore
 * only matters for freestanding KP LKM builds.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>

#include "kp/include/log.h"

int kp_patch_memory_init(void);
int kp_fphook_runtime_init(void);
void kp_symres_init(void);

static int kp_infra_init(void)
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
