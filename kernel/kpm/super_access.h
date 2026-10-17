#ifndef __SUKISU_KPM_SUPER_ACCESS_H
#define __SUKISU_KPM_SUPER_ACCESS_H

#include <linux/types.h>
#include <linux/stddef.h>
#include "module.h"
#include "kpmodule.h"

/*
 * Dynamic struct metadata. KPM modules can use these helpers to read or
 * compute member offsets without having to recompile against each kernel
 * version's <linux/...> header layout. Ported from the KernelPatch
 * `super_access` facility.
 *
 * The covered structs are listed in super_access.c and gated by the
 * relevant kernel-version checks. New entries should follow the same
 * DYNAMIC_STRUCT_BEGIN / DEFINE_MEMBER / DYNAMIC_STRUCT_END pattern.
 */

extern int sukisu_super_find_struct(const char *struct_name, size_t *out_size,
                                    int *out_members);
extern int sukisu_super_access(const char *struct_name, const char *member_name,
                               size_t *out_offset, size_t *out_size);
extern int sukisu_super_container_of(const char *struct_name,
                                     const char *member_name, void *ptr,
                                     void **out_ptr);

#endif
