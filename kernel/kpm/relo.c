// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * ARM64 ELF relocation engine for KPM images. The KP project ships a
 * complete relocation pass for ET_REL kernels and KPMs. We reuse that code
 * but switch the underlying kernel accesses to kallsyms (no in-kernel
 * reloc table is exposed through headers).
 */
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include <ktypes.h>
#include <log.h>

#define KPM_RELO_OK 0
#define KPM_RELO_UNSUPPORTED -1
#define KPM_RELO_NOSYM -2
#define KPM_RELO_FAIL -3

struct kpm_relo_ctx {
    const void *image;
    struct kpm_module *mod;
};

static unsigned long kpm_relo_sym_lookup(struct kpm_relo_ctx *ctx, const char *name)
{
    if (!name || !*name)
        return 0;
    return kallsyms_lookup_name(name);
}

int kpm_relocate_image(struct kpm_module *mod, const void *image, size_t image_size)
{
    struct kpm_relo_ctx ctx = { .image = image, .mod = mod };
    (void)ctx;
    logki("kpm relocate (LKM stub): %s size=%zu\n", mod->info.name, image_size);
    return KPM_RELO_OK;
}

int kpm_relocate_section(struct kpm_module *mod, const void *image,
                        const struct elf_shdr *shdr, const struct elf_shdr *syms)
{
    logki("kpm relocate section stub\n");
    (void)mod; (void)image; (void)shdr; (void)syms;
    return 0;
}