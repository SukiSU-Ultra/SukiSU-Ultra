/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_KPMALLOC_H_
#define _KP_KPMALLOC_H_
/* When built inside the Linux kernel we delegate to the slab/vmalloc allocator
 * rather than to KP's standalone tlsf heap. */
#include <linux/slab.h>
#include <linux/vmalloc.h>
static inline void *kp_malloc(size_t bytes) { return kmalloc(bytes, GFP_KERNEL); }
static inline void *kp_malloc_exec(size_t bytes) { return kmalloc(bytes, GFP_KERNEL); }
static inline void *kp_memalign(size_t align, size_t bytes) { return kmalloc(bytes, GFP_KERNEL); }
static inline void *kp_memalign_exec(size_t align, size_t bytes) { return kmalloc(bytes, GFP_KERNEL); }
static inline void *kp_realloc(void *ptr, size_t size) { (void)ptr; (void)size; return NULL; }
static inline void *kp_realloc_exec(void *ptr, size_t size) { (void)ptr; (void)size; return NULL; }
static inline void kp_free(void *ptr) { kfree(ptr); }
static inline void kp_free_exec(void *ptr) { kfree(ptr); }
#endif