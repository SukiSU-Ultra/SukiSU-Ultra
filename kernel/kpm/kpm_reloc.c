#include <linux/errno.h>
#ifdef CONFIG_ARM64
#include <asm/elf.h>
#endif
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#include "kpm_reloc.h"

#ifndef CONFIG_ARM64
int kpm_apply_relocations(Elf64_Shdr *sections, unsigned int sym_index,
                          unsigned int rel_index, struct kpm_module *module)
{
    (void)sections;
    (void)sym_index;
    (void)rel_index;
    (void)module;
    return -ENOEXEC;
}
#else

static int patch_imm(u32 *place, u64 value, unsigned int shift, unsigned int bits,
                     bool page_relative)
{
    u32 insn = le32_to_cpu(*place);
    s64 delta = page_relative ?
        ((s64)(value & ~0xfffULL) - (s64)((unsigned long)place & ~0xfffUL)) :
        (s64)value - (s64)(unsigned long)place;
    s64 scaled = delta >> shift;
    u64 mask = (1ULL << bits) - 1;

    if ((delta & ((1ULL << shift) - 1)) != 0 ||
        (scaled < -(1LL << (bits - 1)) || scaled >= (1LL << (bits - 1))))
        return -ERANGE;

    if (bits == 26)
        insn = (insn & ~GENMASK(25, 0)) | ((u32)scaled & GENMASK(25, 0));
    else if (bits == 21)
        insn = (insn & ~GENMASK(23, 5)) |
               (((u32)scaled & GENMASK(20, 0)) << 5);
    else if (bits == 19)
        insn = (insn & ~GENMASK(23, 5)) |
               (((u32)scaled & GENMASK(18, 0)) << 5);
    else
        insn = (insn & ~(u32)mask) | ((u32)scaled & (u32)mask);

    *place = cpu_to_le32(insn);
    return 0;
}

static int patch_movw(u32 *place, u64 value, unsigned int shift)
{
    u32 insn = le32_to_cpu(*place);
    u32 imm = (value >> shift) & 0xffff;

    insn = (insn & ~GENMASK(20, 5)) | (imm << 5);
    *place = cpu_to_le32(insn);
    return 0;
}

int kpm_apply_relocations(Elf64_Shdr *sections, unsigned int sym_index,
                          unsigned int rel_index, struct kpm_module *module)
{
    Elf64_Rela *rels = (void *)(uintptr_t)sections[rel_index].sh_addr;
    Elf64_Sym *syms = (void *)(uintptr_t)sections[sym_index].sh_addr;
    unsigned int count = sections[rel_index].sh_size / sizeof(*rels);

    for (unsigned int i = 0; i < count; ++i) {
        unsigned int type = ELF64_R_TYPE(rels[i].r_info);
        unsigned long place_addr = sections[sections[rel_index].sh_info].sh_addr + rels[i].r_offset;
        void *place = (void *)(uintptr_t)place_addr;
        u64 value = syms[ELF64_R_SYM(rels[i].r_info)].st_value + rels[i].r_addend;
        int rc = 0;

        switch (type) {
        case R_AARCH64_NONE:
            break;
        case R_AARCH64_ABS64:
            *(u64 *)place = value;
            break;
        case R_AARCH64_ABS32:
            if (value > U32_MAX) return -ERANGE;
            *(u32 *)place = value;
            break;
        case R_AARCH64_PREL32:
            *(u32 *)place = value - place_addr;
            break;
        case R_AARCH64_ADR_PREL_LO21:
            rc = patch_imm(place, value, 0, 21, false);
            break;
        case R_AARCH64_ADR_PREL_PG_HI21:
            rc = patch_imm(place, value, 12, 21, true);
            break;
        case R_AARCH64_ADR_PREL_PG_HI21_NC:
            rc = patch_imm(place, value, 12, 21, true);
            break;
        case R_AARCH64_ADD_ABS_LO12_NC:
            *(u32 *)place = cpu_to_le32((le32_to_cpu(*(u32 *)place) & ~GENMASK(21, 10)) |
                                         (((value & 0xfff) >> 0) << 10));
            break;
        case R_AARCH64_LDST64_ABS_LO12_NC:
            *(u32 *)place = cpu_to_le32((le32_to_cpu(*(u32 *)place) & ~GENMASK(21, 10)) |
                                         (((value & 0xff8) >> 3) << 10));
            break;
        case R_AARCH64_CALL26:
        case R_AARCH64_JUMP26:
            rc = patch_imm(place, value, 2, 26, false);
            break;
        case R_AARCH64_MOVW_UABS_G0_NC:
        case R_AARCH64_MOVW_UABS_G0:
            rc = patch_movw(place, value, 0);
            break;
        case R_AARCH64_MOVW_UABS_G1_NC:
        case R_AARCH64_MOVW_UABS_G1:
            rc = patch_movw(place, value, 16);
            break;
        case R_AARCH64_MOVW_UABS_G2_NC:
        case R_AARCH64_MOVW_UABS_G2:
            rc = patch_movw(place, value, 32);
            break;
        case R_AARCH64_MOVW_UABS_G3:
            rc = patch_movw(place, value, 48);
            break;
        default:
            pr_err("kpm: unsupported AArch64 relocation %u in module\n", type);
            return -ENOEXEC;
        }
        if (rc)
            return rc;
    }
    return 0;
}
#endif

MODULE_LICENSE("GPL");
