/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported to SukiSU-Ultra: 2025 Liankong.
 */

#ifndef _SUKISU_KPM_RELO_H_
#define _SUKISU_KPM_RELO_H_

#include <linux/elf.h>

struct kpm_module;

int kpm_apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab,
                            unsigned int symindex, unsigned int relsec,
                            struct kpm_module *me);
int kpm_apply_relocate(Elf64_Shdr *sechdrs, const char *strtab,
                       unsigned int symindex, unsigned int relsec,
                       struct kpm_module *me);

#endif
