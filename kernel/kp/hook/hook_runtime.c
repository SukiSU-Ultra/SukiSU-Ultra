// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Backing store for the KP inline-hook engine: executable-memory allocator
 * (module_alloc / execmem_alloc / vmalloc fallback) and the resident _transit0/4/8/12
 * chain trampolines that the trampoline slot in each hook_chain_t.branches
 * into. We compile the transit functions into plain module text (not a custom
 * .transit*.text section): the trampoline in hook_chain_t.transit[6] emits an
 * absolute branch to the resident function so the relocation is a single LDR
 * pair instead of a kpimg linker-section copy.
 *
 * GKI BTI note: each chain trampoline starts with ARM64_BTI_JC so a kernel-side
 * BLR (which sets PSTATE.BTYPE=JC) lands on a valid landing pad. The resident
 * transit bodies do not use bti c themselves (they are not the indirect-call
 * target), so they only need to be valid aarch64 text.
 */
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>

#include <hook.h>
#include <ktypes.h>

struct kp_hook_mem {
    struct list_head list;
    uintptr_t origin;
    enum hook_type type;
    void *region;
    union {
        hook_t hook;
        hook_chain_t chain;
        fp_hook_chain_t fp_chain;
    } *payload;
};

static LIST_HEAD(kp_hook_mems);
static DEFINE_MUTEX(kp_hook_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#include <linux/execmem.h>
static void *(*kp_hook_execmem_alloc)(enum execmem_type type, size_t size);
static void (*kp_hook_execmem_free)(void *ptr);
#else
static void *(*kp_hook_execmem_alloc)(int type, size_t size);
static void (*kp_hook_execmem_free)(void *ptr);
#endif
static void *(*kp_hook_module_alloc)(unsigned long size);
static void (*kp_hook_module_memfree)(void *region);
static void (*kp_hook_flush_icache_all)(void);
static int (*kp_hook_set_memory_x)(unsigned long addr, int numpages);

extern unsigned long kp_resolve_symbol(const char *name);
extern int kp_patch_text(void *dst, const void *src, size_t len, int flags);

__attribute__((no_sanitize("cfi"), __noinline__)) static void *kp_hook_exec_alloc(unsigned long size)
{
    void *p = NULL;
    unsigned long pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;

    if (kp_hook_module_alloc)
        p = kp_hook_module_alloc(size);
    else if (kp_hook_execmem_alloc)
        p = kp_hook_execmem_alloc(0 /* EXECMEM_MODULE_TEXT */, size);
    else
        p = vmalloc(size);
    if (p && kp_hook_set_memory_x)
        kp_hook_set_memory_x((unsigned long)p, pages);
    return p;
}

__attribute__((no_sanitize("cfi"), __noinline__)) static void kp_hook_exec_free(void *region)
{
    if (kp_hook_module_memfree)
        kp_hook_module_memfree(region);
    else if (kp_hook_execmem_free)
        kp_hook_execmem_free(region);
    else
        vfree(region);
}

__attribute__((no_sanitize("cfi"))) static void kp_hook_flush_all(void)
{
    if (kp_hook_flush_icache_all)
        kp_hook_flush_icache_all();
}

int kp_hook_runtime_init(void)
{
    kp_hook_module_alloc = (void *)kp_resolve_symbol("module_alloc");
    kp_hook_module_memfree = (void *)kp_resolve_symbol("module_memfree");
    kp_hook_execmem_alloc = (void *)kp_resolve_symbol("execmem_alloc");
    kp_hook_execmem_free = (void *)kp_resolve_symbol("execmem_free");
    kp_hook_flush_icache_all = (void *)kp_resolve_symbol("flush_icache_all");
    kp_hook_set_memory_x = (int (*)(unsigned long, int))kp_resolve_symbol("set_memory_x");
    if (!kp_hook_module_alloc)
        logkw("module_alloc not found; using execmem_alloc/vmalloc for hook memory\n");
    if (!kp_hook_set_memory_x && !kp_hook_execmem_alloc) {
        logke("no executable-memory path (set_memory_x/execmem_alloc missing)\n");
        return -ENOSYS;
    }
    logki("KPM hook runtime ready (module_alloc=%px execmem_alloc=%px set_memory_x=%px)\n",
          kp_hook_module_alloc, kp_hook_execmem_alloc, kp_hook_set_memory_x);
    return 0;
}

void *hook_mem_zalloc(uintptr_t origin, enum hook_type type)
{
    struct kp_hook_mem *mem;
    size_t size;

    switch (type) {
    case INLINE:
        size = sizeof(hook_t);
        break;
    case INLINE_CHAIN:
        size = sizeof(hook_chain_t);
        break;
    case FUNCTION_POINTER_CHAIN:
        size = sizeof(fp_hook_chain_t);
        break;
    default:
        return NULL;
    }

    mem = kzalloc(sizeof(*mem), GFP_KERNEL);
    if (!mem)
        return NULL;
    mem->region = kp_hook_exec_alloc(PAGE_ALIGN(size));
    if (!mem->region) {
        kfree(mem);
        return NULL;
    }
    memset(mem->region, 0, PAGE_ALIGN(size));
    mem->payload = mem->region;
    mem->origin = origin;
    mem->type = type;
    mutex_lock(&kp_hook_lock);
    list_add_tail(&mem->list, &kp_hook_mems);
    mutex_unlock(&kp_hook_lock);
    return mem->payload;
}

void *hook_get_mem_from_origin(uint64_t origin)
{
    struct kp_hook_mem *mem;
    void *result = NULL;

    mutex_lock(&kp_hook_lock);
    list_for_each_entry(mem, &kp_hook_mems, list) {
        if (mem->origin == origin) {
            result = mem->payload;
            break;
        }
    }
    mutex_unlock(&kp_hook_lock);
    return result;
}

void hook_mem_free(void *payload)
{
    struct kp_hook_mem *mem, *tmp;

    mutex_lock(&kp_hook_lock);
    list_for_each_entry_safe(mem, tmp, &kp_hook_mems, list) {
        if (mem->payload == payload) {
            list_del(&mem->list);
            mutex_unlock(&kp_hook_lock);
            kp_hook_exec_free(mem->region);
            kfree(mem);
            return;
        }
    }
    mutex_unlock(&kp_hook_lock);
}

int hotpatch(void *addrs[], u32 values[], int cnt)
{
    int i, start, rc;

    for (start = 0; start < cnt; start = i) {
        for (i = start + 1; i < cnt; i++) {
            if ((char *)addrs[i] != (char *)addrs[start] + (i - start) * sizeof(values[0]))
                break;
        }
        rc = kp_patch_text(addrs[start], &values[start], (i - start) * sizeof(values[0]),
                            /* KP_PATCH_TEXT_FLUSH_DCACHE | KP_PATCH_TEXT_FLUSH_ICACHE */ 1 | 2);
        if (rc)
            return rc;
    }
    return 0;
}

void flush_icache_all(void)
{
    kp_hook_flush_all();
}

/* ---- _transit* trampoline bodies. Each one is a normal noinline function
 * exported to hook.c (which branches to them via the chain->transit[6] stub).
 * The bodies themselves run in the hook trampoline's PSTATE context, so they
 * are NOT BTI landing pads: BTI is satisfied by the BTI_JC at transit[0] and
 * transit[1]..[5] is the LDR X16 + branch that hands control over.
 *
 * Implementation: identical to KP's _transit* functions, but kept as ordinary
 * symbols (no .transit*.text section, no _transit*_end marker). The compiler
 * emits them as standard ELF text and hook.c takes their entry address.
 */
extern hook_chain_t *current_inline_hook_chain(void);

typedef uint64_t (*transit0_func_t)(void);
typedef uint64_t (*transit4_func_t)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*transit8_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*transit12_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t _transit0(void)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain)
        return 0;
    hook_fargs0_t fargs;
    fargs.skip_origin = 0;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY)
            continue;
        hook_chain0_callback func = hook_chain->befores[i];
        if (func)
            func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit0_func_t origin_func = (transit0_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func();
    }
    for (int32_t i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY)
            continue;
        hook_chain0_callback func = hook_chain->afters[i];
        if (func)
            func(&fargs, hook_chain->udata[i]);
    }
    return fargs.ret;
}
EXPORT_SYMBOL(_transit0);

uint64_t _transit4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain)
        return 0;
    hook_fargs4_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY)
            continue;
        hook_chain4_callback func = hook_chain->befores[i];
        if (func)
            func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit4_func_t origin_func = (transit4_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
    }
    for (int32_t i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY)
            continue;
        hook_chain4_callback func = hook_chain->afters[i];
        if (func)
            func(&fargs, hook_chain->udata[i]);
    }
    return fargs.ret;
}
EXPORT_SYMBOL(_transit4);

uint64_t _transit8(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                   uint64_t arg6, uint64_t arg7)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain)
        return 0;
    hook_fargs8_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY)
            continue;
        hook_chain8_callback func = hook_chain->befores[i];
        if (func)
            func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit8_func_t origin_func = (transit8_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6,
                                fargs.arg7);
    }
    for (int32_t i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY)
            continue;
        hook_chain8_callback func = hook_chain->afters[i];
        if (func)
            func(&fargs, hook_chain->udata[i]);
    }
    return fargs.ret;
}
EXPORT_SYMBOL(_transit8);

uint64_t _transit12(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                    uint64_t arg6, uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    if (!hook_chain)
        return 0;
    hook_fargs12_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.arg8 = arg8;
    fargs.arg9 = arg9;
    fargs.arg10 = arg10;
    fargs.arg11 = arg11;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY)
            continue;
        hook_chain12_callback func = hook_chain->befores[i];
        if (func)
            func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit12_func_t origin_func = (transit12_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6,
                                fargs.arg7, fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
    }
    for (int32_t i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY)
            continue;
        hook_chain12_callback func = hook_chain->afters[i];
        if (func)
            func(&fargs, hook_chain->udata[i]);
    }
    return fargs.ret;
}
EXPORT_SYMBOL(_transit12);

hook_chain_t *current_inline_hook_chain(void)
{
    uint64_t chain_va;
    asm volatile("mov %0, x16" : "=r"(chain_va));
    return (hook_chain_t *)chain_va;
}
EXPORT_SYMBOL(current_inline_hook_chain);