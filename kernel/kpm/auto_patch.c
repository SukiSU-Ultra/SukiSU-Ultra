#include <linux/errno.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#include "../hook/lsm_hook.h"
#include "../hook/patch_memory.h"
#include "../hook/syscall_hook.h"
#include "../infra/symbol_resolver.h"
#include "patch_api.h"
#include "kstorage.h"

int kpm_patch_text(void *destination, const void *source, size_t length, int flags)
{
    if (!destination || !source || !length)
        return -EINVAL;
    return ksu_patch_text(destination, (void *)source, length, flags);
}
EXPORT_SYMBOL(kpm_patch_text);

void *kpm_scan_call_to(void *start, size_t size, void *target)
{
    return scan_call_to(start, size, target);
}
EXPORT_SYMBOL(kpm_scan_call_to);

unsigned long kpm_resolve_symbol(const char *name)
{
    return find_kernel_symbol_exact(name);
}
EXPORT_SYMBOL(kpm_resolve_symbol);

int kpm_register_syscall_hook(int nr, ksu_syscall_hook_fn handler)
{
    return ksu_register_syscall_hook(nr, handler);
}
EXPORT_SYMBOL(kpm_register_syscall_hook);

void kpm_unregister_syscall_hook(int nr)
{
    ksu_unregister_syscall_hook(nr);
}
EXPORT_SYMBOL(kpm_unregister_syscall_hook);

int kpm_register_lsm_hook(struct ksu_lsm_hook *hook)
{
    return ksu_lsm_hook(hook);
}
EXPORT_SYMBOL(kpm_register_lsm_hook);

void kpm_unregister_lsm_hook(struct ksu_lsm_hook *hook)
{
    ksu_lsm_unhook(hook);
}
EXPORT_SYMBOL(kpm_unregister_lsm_hook);

struct kpm_runtime_symbol {
    const char *name;
    unsigned long address;
};

static const struct kpm_runtime_symbol kpm_runtime_symbols[] = {
    { "kpm_patch_text", (unsigned long)kpm_patch_text },
    { "kpm_scan_call_to", (unsigned long)kpm_scan_call_to },
    { "kpm_resolve_symbol", (unsigned long)kpm_resolve_symbol },
    { "kpm_register_syscall_hook", (unsigned long)kpm_register_syscall_hook },
    { "kpm_unregister_syscall_hook", (unsigned long)kpm_unregister_syscall_hook },
    { "kpm_register_lsm_hook", (unsigned long)kpm_register_lsm_hook },
    { "kpm_unregister_lsm_hook", (unsigned long)kpm_unregister_lsm_hook },
    { "kpm_hook_syscall", (unsigned long)kpm_hook_syscall },
    { "kpm_unhook_syscall", (unsigned long)kpm_unhook_syscall },
    { "kpm_kstorage_alloc_group", (unsigned long)kpm_kstorage_alloc_group },
    { "kpm_kstorage_group_size", (unsigned long)kpm_kstorage_group_size },
    { "kpm_kstorage_generation", (unsigned long)kpm_kstorage_generation },
    { "kpm_kstorage_write", (unsigned long)kpm_kstorage_write },
    { "kpm_kstorage_get", (unsigned long)kpm_kstorage_get },
    { "kpm_kstorage_read", (unsigned long)kpm_kstorage_read },
    { "kpm_kstorage_list_ids", (unsigned long)kpm_kstorage_list_ids },
    { "kpm_kstorage_remove", (unsigned long)kpm_kstorage_remove },
};

unsigned long kpm_resolve_runtime_symbol(const char *name)
{
    for (size_t i = 0; i < ARRAY_SIZE(kpm_runtime_symbols); ++i)
        if (!strcmp(kpm_runtime_symbols[i].name, name))
            return kpm_runtime_symbols[i].address;
    return 0;
}

MODULE_LICENSE("GPL");
