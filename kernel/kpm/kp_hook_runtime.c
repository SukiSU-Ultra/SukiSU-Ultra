// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported from KernelPatch to SukiSU-Ultra: 2025 Liankong.
 *
 * SukiSU-Ultra side of the KP inline-hook framework. Mirrors
 * lkm/hook/hook_runtime.c but uses SukiSU's own infrastructure
 * (vmalloc + set_memory_x, kallsyms_lookup_name, ksu_patch_text)
 * instead of the KP-specific helpers.
 */
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/set_memory.h>
#include <asm/cacheflush.h>

#include <hook.h>
#include "../hook/patch_memory.h"
#include "kp_hook_runtime.h"

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

/* On 6.11+ the kernel replaced module_alloc with execmem_alloc;
 * fall through to vmalloc + set_memory_x as the universal last
 * resort. KPMs and KP-built modules target 5.10/5.15/6.1 GKI trees
 * where module_alloc is not exported, so vmalloc + set_memory_x is
 * the primary path. */
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

/* noinline: these are raw resolved function pointers; if inlined into
 * a CFI-instrumented caller, the compiler emits a kCFI type-hash load
 * of [fnptr - 4] that dereferences NULL when the allocator is absent
 * (6.10+ has no module_alloc) and panics. no_sanitize keeps the
 * indirect calls unchecked. */
__attribute__((no_sanitize("cfi"), __noinline__))
static void *kp_hook_exec_alloc(unsigned long size)
{
	void *p = NULL;
	unsigned long pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	if (kp_hook_module_alloc)
		p = kp_hook_module_alloc(size);
	else if (kp_hook_execmem_alloc)
		p = kp_hook_execmem_alloc(0 /* EXECMEM_MODULE_TEXT */, size);
	else
		p = vmalloc(size);

	/* GKI module_alloc returns PAGE_KERNEL (PXN set, NX); vmalloc too.
	 * Hook trampolines live here and must be executable. */
	if (p && kp_hook_set_memory_x)
		kp_hook_set_memory_x((unsigned long)p, pages);
	return p;
}

__attribute__((no_sanitize("cfi"), __noinline__))
static void kp_hook_exec_free(void *region)
{
	if (kp_hook_module_memfree)
		kp_hook_module_memfree(region);
	else if (kp_hook_execmem_free)
		kp_hook_exec_free(region);
	else
		vfree(region);
}

__attribute__((no_sanitize("cfi")))
static void kp_hook_flush_all(void)
{
	if (kp_hook_flush_icache_all)
		kp_hook_flush_icache_all();
}

int kp_hook_runtime_init(void)
{
	kp_hook_module_alloc = (void *)kallsyms_lookup_name("module_alloc");
	kp_hook_module_memfree = (void *)kallsyms_lookup_name("module_memfree");
	kp_hook_execmem_alloc = (void *)kallsyms_lookup_name("execmem_alloc");
	kp_hook_execmem_free = (void *)kallsyms_lookup_name("execmem_free");
	kp_hook_flush_icache_all = (void *)kallsyms_lookup_name("flush_icache_all");
	kp_hook_set_memory_x = (int (*)(unsigned long, int))kallsyms_lookup_name("set_memory_x");
	if (!kp_hook_module_alloc)
		pr_warn("kp_hook_runtime: module_alloc not found; using execmem_alloc/vmalloc for hook memory\n");
	if (!kp_hook_set_memory_x && !kp_hook_execmem_alloc) {
		pr_err("kp_hook_runtime: no executable-memory path (set_memory_x/execmem_alloc missing)\n");
		return -ENOSYS;
	}
	pr_info("kp_hook_runtime: ready (module_alloc=%px execmem_alloc=%px set_memory_x=%px)\n",
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

int hotpatch(void *addrs[], uint32_t values[], int count)
{
	int i, start, rc;

	for (start = 0; start < count; start = i) {
		for (i = start + 1; i < count; i++) {
			if ((char *)addrs[i] != (char *)addrs[start] +
						 (i - start) * sizeof(values[0]))
				break;
		}
		rc = ksu_patch_text(addrs[start], &values[start],
				    (i - start) * sizeof(values[0]),
				    KSU_PATCH_TEXT_FLUSH_DCACHE |
				    KSU_PATCH_TEXT_FLUSH_ICACHE);
		if (rc)
			return rc;
	}
	return 0;
}
