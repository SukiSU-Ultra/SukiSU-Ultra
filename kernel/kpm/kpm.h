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

#include "kp/include/ktypes.h"
#include "kp/include/kpmodule.h"

struct kpm_module;
typedef int (*kpm_entry_t)(void *reserved, struct kpm_module *mod);

int do_kpm(void __user *arg);

struct kpm_info {
    uint32_t magic;
    uint32_t version;
    char name[KPM_NAME_LEN];
    char author[KPM_AUTHOR_LEN];
    char description[KPM_DESCRIPTION_LEN];
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

void sukisu_kpm_init(void);
void sukisu_kpm_exit(void);

/* KP-side KPM loader API (defined in kpm/module.c). */
struct kpm_module *kp_kpm_load(const void *data, size_t size, const char *path);
int kp_kpm_unload_by_name(const char *name);
int kp_kpm_control(const char *name, int cmd, void *arg);
int kp_kpm_event(const char *name, int code, void *arg);
void kp_kpm_unload_all(void);
void kp_kpm_list_modules(struct kpm_module **mods, int *count);

/* Public SukiSU KPM API (defined in kpm/kpm.c, exported). */
int sukisu_kpm_load_module_path(const char *path, void **out_handle);
int sukisu_kpm_unload_module(const char *name);
int sukisu_kpm_control(const char *name, int cmd, void *arg);
int sukisu_kpm_event(const char *name, int code, void *arg);

/* Verification result for kp_module_verify() and the version/flags blob
 * written into the kpm_info header. Defined in kp/secpass.c; declared here
 * so the KPM loader (kpm/module.c) and the verifier agree on layout. */
struct kp_version_info {
    uint32_t version;
    uint32_t flags;
};

#endif /* KSU_KPM_KPM_H */