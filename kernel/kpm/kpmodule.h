/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported to SukiSU-Ultra: 2025 Liankong.
 *
 * KernelPatch-compatible KPM module authoring header. The section-based
 * metadata (KPM_NAME/VERSION/INIT/EXIT/...) and the function-pointer
 * types (mod_initcall_t, mod_ctl0call_t, ...) match the layout KP
 * expects, so an out-of-tree KPM can be compiled against either
 * KernelPatch's loader or SukiSU-Ultra's loader without changes.
 *
 * On load, SukiSU-Ultra's kpm/module.c reads the .kpm.* sections, lays
 * out the module image, applies the AArch64 relocations, and calls the
 * KPM_INIT function. KPMs receive the standard KernelPatch entry-point
 * ABI: (const char *args, const char *event, void *reserved).
 */

#ifndef _SUKISU_KPMODULE_H_
#define _SUKISU_KPMODULE_H_

#include <linux/types.h>

/*
 * Section names are kept identical to kpimg.lds so the ELF emitted by a
 * KPM build is portable between the two loaders.
 */
#define KPM_INFO(name, info, limit)                                            \
    _Static_assert(sizeof(info) <= limit, "Info string too long");             \
    static const char __kpm_info_##name[] __attribute__((__used__))            \
    __attribute__((section(".kpm.info"), unused, aligned(1))) = #name "=" info

#define KPM_NAME_LEN 32
#define KPM_VERSION_LEN 32
#define KPM_LICENSE_LEN 32
#define KPM_AUTHOR_LEN 32
#define KPM_DESCRIPTION_LEN 512
#define KPM_ARGS_LEN 1024
#define KPM_LOAD_ERROR_MESSAGE_LEN 160

#define KPM_NAME(x) KPM_INFO(name, x, KPM_NAME_LEN)
#define KPM_VERSION(x) KPM_INFO(version, x, KPM_VERSION_LEN)
#define KPM_LICENSE(x) KPM_INFO(license, x, KPM_LICENSE_LEN)
#define KPM_AUTHOR(x) KPM_INFO(author, x, KPM_AUTHOR_LEN)
#define KPM_DESCRIPTION(x) KPM_INFO(description, x, KPM_DESCRIPTION_LEN)

/* Standard KernelPatch KPM entry-point prototypes. */
typedef long (*mod_initcall_t)(const char *args, const char *event,
                               void *reserved);
typedef long (*mod_ctl0call_t)(const char *ctl_args, char *__user out_msg,
                               int outlen);
typedef long (*mod_ctl1call_t)(void *a1, void *a2, void *a3);
typedef long (*mod_exitcall_t)(void *reserved);
typedef long (*mod_eventcall_t)(const char *event, const char *args,
                                void *reserved);

#define KPM_INIT(fn)                                                           \
    static mod_initcall_t __kpm_initcall_##fn                                  \
        __attribute__((__used__))                                              \
        __attribute__((__section__(".kpm.init"))) = fn

#define KPM_CTL0(fn)                                                           \
    static mod_ctl0call_t __kpm_ctlmodule_##fn                                 \
        __attribute__((__used__))                                              \
        __attribute__((__section__(".kpm.ctl0"))) = fn

#define KPM_CTL1(fn)                                                           \
    static mod_ctl1call_t __kpm_ctlmodule_##fn                                 \
        __attribute__((__used__))                                              \
        __attribute__((__section__(".kpm.ctl1"))) = fn

#define KPM_EXIT(fn)                                                           \
    static mod_exitcall_t __kpm_exitcall_##fn                                  \
        __attribute__((__used__))                                              \
        __attribute__((__section__(".kpm.exit"))) = fn

#define KPM_EVENT(fn)                                                          \
    static mod_eventcall_t __kpm_eventcall_##fn                                \
        __attribute__((__used__))                                              \
        __attribute__((__section__(".kpm.event"))) = fn

/*
 * Result struct returned to userspace via the `reserved` argument of
 * KPM_INIT. Layout must match the userspace definition in
 * userspace/ksud/src/kpm.rs and KernelPatch's uapi/scdefs.h.
 */
#define KPM_LOAD_RESULT_MAGIC 0x4b504d52

struct kpm_load_result {
    unsigned int magic;
    unsigned int size;
    int code;
    char message[KPM_LOAD_ERROR_MESSAGE_LEN];
};

#endif
