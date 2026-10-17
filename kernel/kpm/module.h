/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported to SukiSU-Ultra: 2025 Liankong.
 */

#ifndef _SUKISU_KPM_MODULE_H_
#define _SUKISU_KPM_MODULE_H_

#include <linux/elf.h>
#include <linux/types.h>
#include <linux/list.h>
#include "kpmodule.h"

/* Renamed from `struct module` to avoid colliding with the in-tree
 * `struct module` exposed by <linux/module.h>, which a few transitive
 * includes pull into core/init.c on 5.10/5.15 GKI. */
struct kpm_module {
    struct {
        const char *base, *name, *version, *license, *author, *description;
    } info;

    char *args, *ctl_args;
    char load_event[32];
    char load_source[16];

    mod_initcall_t *init;
    mod_ctl0call_t *ctl0;
    mod_ctl1call_t *ctl1;
    mod_exitcall_t *exit;
    mod_eventcall_t *event;

    unsigned int size;
    unsigned int text_size;
    unsigned int ro_size;

    void *start;

    struct list_head list;
};

long kpm_load_module(const void *data, int len, const char *args,
                      const char *event, void *__user reserved);
long kpm_load_module_ex(const void *data, int len, const char *args,
                        const char *event, const char *source,
                        void *__user reserved);
long kpm_load_module_path(const char *path, const char *args,
                          void *__user reserved);
long kpm_load_module_path_event(const char *path, const char *args,
                                const char *event, void *__user reserved);
long kpm_module_control0(const char *name, const char *ctl_args,
                         char *__user out_msg, int outlen);
long kpm_module_control1(const char *name, void *a1, void *a2, void *a3);
long kpm_unload_module(const char *name, void *__user reserved);
struct kpm_module *kpm_find_module(const char *name);
long kpm_notify_modules_event(const char *event, const char *args,
                              void *__user reserved);

int kpm_get_module_nums(void);
int kpm_list_modules(char *out_names, int size);
int kpm_get_module_info(const char *name, char *out_info, int size);
void kpm_module_init(void);

#endif
