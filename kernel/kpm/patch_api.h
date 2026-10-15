#ifndef __SUKISU_KPM_PATCH_API_H
#define __SUKISU_KPM_PATCH_API_H

#include <linux/types.h>
#include "../hook/patch_memory.h"
#include "../hook/lsm_hook.h"
#include "../hook/syscall_hook.h"
#include "syscall_api.h"

/* KPM runtime patch ABI. All text changes are synchronized by the active
 * architecture backend; KPMs must not write kernel text directly. */
#define KPM_PATCH_FLUSH_DCACHE KSU_PATCH_TEXT_FLUSH_DCACHE
#define KPM_PATCH_FLUSH_ICACHE KSU_PATCH_TEXT_FLUSH_ICACHE

int kpm_patch_text(void *destination, const void *source, size_t length, int flags);
void *kpm_scan_call_to(void *start, size_t size, void *target);
unsigned long kpm_resolve_symbol(const char *name);

int kpm_register_syscall_hook(int nr, ksu_syscall_hook_fn handler);
void kpm_unregister_syscall_hook(int nr);
int kpm_register_lsm_hook(struct ksu_lsm_hook *hook);
int kpm_kstorage_alloc_group(void);
int kpm_kstorage_group_size(int group);
u32 kpm_kstorage_generation(void);
int kpm_kstorage_write(int group, long id, const void *data, int offset, int length);
const struct kpm_kstorage *kpm_kstorage_get(int group, long id);
int kpm_kstorage_read(int group, long id, void *data, int offset, int length);
int kpm_kstorage_list_ids(int group, long *ids, int length);
int kpm_kstorage_remove(int group, long id);
void kpm_unregister_lsm_hook(struct ksu_lsm_hook *hook);

static inline void kpm_compiler_barrier(void)
{
    asm volatile("" ::: "memory");
}

static inline void kpm_instruction_barrier(void)
{
#if defined(__aarch64__)
    asm volatile("dsb ish; isb" ::: "memory");
#elif defined(__riscv)
    asm volatile("fence.i" ::: "memory");
#else
    asm volatile("mfence; lfence" ::: "memory");
#endif
}

#endif
