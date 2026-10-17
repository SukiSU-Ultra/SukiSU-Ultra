// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * ELF sections that the KP loader reads from a KPM image (.kpm.*) and
 * helper functions that the loader, hook engine and compatibility
 * symbol table share.
 */
#ifndef KSU_KPM_KPM_H
#define KSU_KPM_KPM_H

#include <linux/types.h>

#include <ktypes.h>

struct kpm_module;
typedef int (*kpm_entry_t)(void *reserved, struct kpm_module *mod);

struct kpm_info {
    uint32_t magic;
    uint32_t version;
    char name[KPM_NAME_LEN];
    char author[KPM_AUTHOR_LEN];
    char description[KPM_DESC_LEN];
    kpm_entry_t init;
    kpm_entry_t exit;
    void *ctl0;
    void *ctl1;
    void *event;
    void *reserved;
};

struct kpm_module {
    struct kpm_info info;
    void *image;
    size_t image_size;
    void *text;
    size_t text_size;
    void *data;
    size_t data_size;
    void *bss;
    size_t bss_size;
    void *percpu;
    size_t percpu_size;
    struct kp_symbol *syms;
    int syms_count;
    struct kp_export *exports;
    int exports_count;
    void *priv;
};

#define KPM_MAGIC 0x4B504D47u
#define KPM_VERSION 1u

#endif /* KSU_KPM_KPM_H */