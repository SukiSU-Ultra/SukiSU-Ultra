/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Liankong. All Rights Reserved.
 *
 * Compact symbol table for SukiSU-Ultra KPM. The address_symbol array
 * below lists every helper that a KPM module is allowed to resolve by
 * name. New entries should be reviewed for stability and SELinux
 * implications before being added.
 */

#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uidgid.h>

#include "infra/symbol_resolver.h"
#include "module.h"
#include "kpmodule.h"
#include "policy/allowlist.h"
#include "manager/manager_identity.h"

static int sukisu_is_su_allow_uid(uid_t uid)
{
    return __ksu_is_allow_uid_for_current(uid) ? 1 : 0;
}

static int sukisu_get_ap_mod_exclude(uid_t uid)
{
    return 0; /* Not supported */
}

static int sukisu_is_uid_should_umount(uid_t uid)
{
    return ksu_uid_should_umount(uid) ? 1 : 0;
}

static int sukisu_is_current_uid_manager(void)
{
    return is_manager() ? 1 : 0;
}

static uid_t sukisu_get_manager_uid(void)
{
    return ksu_get_manager_appid();
}

static void sukisu_set_manager_uid(uid_t uid, int force)
{
    /* `force` is honored by the upstream KP API; in SukiSU-Ultra the
     * caller already passed the manager-check, so we always honor it. */
    (void)force;
    ksu_set_manager_appid(uid);
}

struct CompactAddressSymbol {
    const char *symbol_name;
    void *addr;
};

unsigned long sukisu_compact_find_symbol(const char *name);

static int sukisu_is_run_in(void)
{
    /* The compact table needs a stable truthy value here so a KPM can
     * detect "running under SukiSU-Ultra" without dereferencing. Returning
     * a fixed non-NULL pointer would be wrong on architectures that trap
     * on low-address reads, so a real function address is used instead. */
    return 1;
}

static struct CompactAddressSymbol address_symbol[] = {
    { "kallsyms_lookup_name", &kallsyms_lookup_name },
    { "compact_find_symbol", &sukisu_compact_find_symbol },
    { "is_run_in_sukisu_ultra", sukisu_is_run_in },
    { "is_su_allow_uid", &sukisu_is_su_allow_uid },
    { "get_ap_mod_exclude", &sukisu_get_ap_mod_exclude },
    { "is_uid_should_umount", &sukisu_is_uid_should_umount },
    { "is_current_uid_manager", &sukisu_is_current_uid_manager },
    { "get_manager_uid", &sukisu_get_manager_uid },
    { "sukisu_set_manager_uid", &sukisu_set_manager_uid },
    { "kpm_load_module", &load_module },
    { "kpm_load_module_path", &load_module_path },
    { "kpm_unload_module", &unload_module },
    { "kpm_module_control0", &module_control0 },
    { "kpm_module_control1", &module_control1 },
    { "kpm_find_module", &find_module },
    { "kpm_get_module_nums", &get_module_nums },
    { "kpm_list_modules", &list_modules },
    { "kpm_get_module_info", &get_module_info },
    { "kpm_notify_modules_event", &notify_modules_event },
};

unsigned long sukisu_compact_find_symbol(const char *name)
{
    int i;
    unsigned long addr;

    for (i = 0;
         i < (sizeof(address_symbol) / sizeof(struct CompactAddressSymbol));
         i++) {
        struct CompactAddressSymbol *symbol = &address_symbol[i];

        if (strcmp(name, symbol->symbol_name) == 0)
            return (unsigned long)symbol->addr;
    }

    addr = find_kernel_symbol_exact(name);
    if (addr)
        return addr;

    addr = (unsigned long)kallsyms_lookup_name(name);
    if (addr)
        return addr;

    return 0;
}
EXPORT_SYMBOL(sukisu_compact_find_symbol);
