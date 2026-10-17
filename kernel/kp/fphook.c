// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KP fphook engine (function-pointer hook). Inside a Linux kernel module we
 * don't have the .kp.fphook link section used by the freestanding kpimg; the
 * fphook chain trampoline layout is allocated from kp_hook_exec_alloc() in
 * hook_runtime.c and the chain is invoked through the same _transit*
 * trampolines used by inline hooks. The interface (fp_hook_wrap / fp_unhook)
 * is exposed verbatim so KPMs that hook through function pointers work
 * unmodified.
 */
#include <linux/compiler.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>

#include "kp/include/hook.h"
#include "kp/include/ktypes.h"

struct kp_fphook_mem {
    struct list_head list;
    uintptr_t fp_addr;
    void *region;
    fp_hook_chain_t *payload;
};

static LIST_HEAD(kp_fphook_mems);
static DEFINE_MUTEX(kp_fphook_lock);

extern unsigned long kp_resolve_symbol(const char *name);
extern int kp_patch_text(void *dst, const void *src, size_t len, int flags);
/* Resident transit bodies defined in hook/hook_runtime.c. The chain-prepare
 * helper below branches each chain trampoline to one of these so the chain
 * hot path lives in module text, not executable-pool memory. */
extern uint64_t _transit0(void);
extern uint64_t _transit4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3);
extern uint64_t _transit8(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                          uint64_t arg6, uint64_t arg7);
extern uint64_t _transit12(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                           uint64_t arg6, uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11);

static void *(*kp_fphook_module_alloc)(unsigned long size);
static void (*kp_fphook_module_memfree)(void *region);
static int (*kp_fphook_set_memory_x)(unsigned long addr, int numpages);

__attribute__((no_sanitize("cfi"), __noinline__)) static void *kp_fphook_exec_alloc(unsigned long size)
{
    void *p;
    if (kp_fphook_module_alloc)
        p = kp_fphook_module_alloc(size);
    else
        p = vmalloc(size);
    if (p && kp_fphook_set_memory_x)
        kp_fphook_set_memory_x((unsigned long)p, (size + PAGE_SIZE - 1) >> PAGE_SHIFT);
    return p;
}

__attribute__((no_sanitize("cfi"), __noinline__)) static void kp_fphook_exec_free(void *region)
{
    if (kp_fphook_module_memfree)
        kp_fphook_module_memfree(region);
    else
        vfree(region);
}

int kp_fphook_runtime_init(void)
{
    kp_fphook_module_alloc = (void *)kp_resolve_symbol("module_alloc");
    kp_fphook_module_memfree = (void *)kp_resolve_symbol("module_memfree");
    kp_fphook_set_memory_x = (int (*)(unsigned long, int))kp_resolve_symbol("set_memory_x");
    if (!kp_fphook_module_alloc) {
        logkw("module_alloc not found; using vmalloc for fphook memory\n");
    }
    if (!kp_fphook_set_memory_x) {
        logke("set_memory_x not found; fphook unavailable\n");
        return -ENOSYS;
    }
    logki("kp fphook runtime ready\n");
    return 0;
}

static int kp_fphook_chain_prepare(uint32_t *transit, int32_t argno)
{
    uint64_t target;
    switch (argno) {
    case 0:
        target = (uint64_t)_transit0;
        break;
    case 1:
    case 2:
    case 3:
    case 4:
        target = (uint64_t)_transit4;
        break;
    case 5:
    case 6:
    case 7:
    case 8:
        target = (uint64_t)_transit8;
        break;
    default:
        target = (uint64_t)_transit12;
        break;
    }

    transit[0] = ARM64_BTI_JC;
    transit[1] = 0x58000070;
    transit[2] = 0x14000004;
    transit[3] = ARM64_NOP;
    fp_hook_chain_t *chain = (fp_hook_chain_t *)((char *)transit - offsetof(fp_hook_chain_t, transit));
    transit[4] = ((uint64_t)chain) & 0xFFFFFFFF;
    transit[5] = ((uint64_t)chain) >> 32u;
    transit[6] = 0x14000000u | (((target - ((uint64_t)&transit[6])) >> 2) & 0x03FFFFFFu);
    transit[7] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static fp_hook_chain_t *kp_fphook_chain_get(uintptr_t fp_addr)
{
    struct kp_fphook_mem *mem;
    mutex_lock(&kp_fphook_lock);
    list_for_each_entry(mem, &kp_fphook_mems, list) {
        if (mem->fp_addr == fp_addr) {
            mutex_unlock(&kp_fphook_lock);
            return mem->payload;
        }
    }
    mutex_unlock(&kp_fphook_lock);
    return NULL;
}

static void kp_fphook_chain_put(fp_hook_chain_t *chain)
{
    struct kp_fphook_mem *mem, *tmp;
    mutex_lock(&kp_fphook_lock);
    list_for_each_entry_safe(mem, tmp, &kp_fphook_mems, list) {
        if (mem->payload == chain) {
            list_del(&mem->list);
            mutex_unlock(&kp_fphook_lock);
            kp_fphook_exec_free(mem->region);
            kfree(mem);
            return;
        }
    }
    mutex_unlock(&kp_fphook_lock);
}

void fp_hook(uintptr_t fp_addr, void *replace, void **backup)
{
    uint64_t *target = (uint64_t *)fp_addr;
    if (backup)
        *backup = (void *)*target;
    kp_patch_text(target, &replace, sizeof(replace), 1 | 2);
}
EXPORT_SYMBOL(fp_hook);

void fp_unhook(uintptr_t fp_addr, void *backup)
{
    kp_patch_text((void *)fp_addr, &backup, sizeof(backup), 1 | 2);
}
EXPORT_SYMBOL(fp_unhook);

hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before, void *after, void *udata)
{
    fp_hook_chain_t *chain = kp_fphook_chain_get(fp_addr);
    if (chain)
        return hook_chain_add((hook_chain_t *)chain, before, after, udata);

    chain = (fp_hook_chain_t *)kp_fphook_exec_alloc(PAGE_ALIGN(sizeof(fp_hook_chain_t)));
    if (!chain)
        return -HOOK_NO_MEM;
    memset(chain, 0, sizeof(*chain));
    chain->chain_items_max = 0;
    chain->hook.fp_addr = fp_addr;

    struct kp_fphook_mem *mem = kzalloc(sizeof(*mem), GFP_KERNEL);
    if (!mem) {
        kp_fphook_exec_free(chain);
        return -HOOK_NO_MEM;
    }
    mem->fp_addr = fp_addr;
    mem->region = chain;
    mem->payload = chain;
    mutex_lock(&kp_fphook_lock);
    list_add_tail(&mem->list, &kp_fphook_mems);
    mutex_unlock(&kp_fphook_lock);

    hook_err_t err = kp_fphook_chain_prepare(chain->transit, argno);
    if (err) {
        kp_fphook_chain_put(chain);
        return err;
    }
    err = hook_chain_add((hook_chain_t *)chain, before, after, udata);
    if (err) {
        kp_fphook_chain_put(chain);
        return err;
    }
    void *origin = (void *)*((uint64_t *)fp_addr);
    chain->hook.origin_fp = (uint64_t)origin;
    void *replace = (void *)chain->transit;
    kp_patch_text((void *)fp_addr, &replace, sizeof(replace), 1 | 2);
    return HOOK_NO_ERR;
}
EXPORT_SYMBOL(fp_hook_wrap);

void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after)
{
    fp_hook_chain_t *chain = kp_fphook_chain_get(fp_addr);
    if (!chain)
        return;
    hook_chain_remove((hook_chain_t *)chain, before, after);
    for (int i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (chain->states[i] != CHAIN_ITEM_STATE_EMPTY)
            return;
    }
    void *origin = (void *)chain->hook.origin_fp;
    kp_patch_text((void *)fp_addr, &origin, sizeof(origin), 1 | 2);
    kp_fphook_chain_put(chain);
}
EXPORT_SYMBOL(fp_hook_unwrap);