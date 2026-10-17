/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported to SukiSU-Ultra: 2025 Liankong.
 *
 * AArch64 ELF relocation engine. Ported from KernelPatch/relo.c. Supports
 * the full set of AArch64 ELF64 relocations (ABS/PREL, MOVW, immediate
 * instruction relocations) required by a KPM built with -fno-pic.
 */

#include <linux/printk.h>
#include <linux/elf.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <asm/elf.h>
#include "insn.h"
#include "relo.h"
#include "module.h"

#define AARCH64_INSN_IMM_MOVNZ AARCH64_INSN_IMM_MAX
#define AARCH64_INSN_IMM_MOVK AARCH64_INSN_IMM_16

enum aarch64_reloc_op {
    RELOC_OP_NONE,
    RELOC_OP_ABS,
    RELOC_OP_PREL,
    RELOC_OP_PAGE,
};

static u64 do_reloc(enum aarch64_reloc_op reloc_op, void *place, u64 val)
{
    switch (reloc_op) {
    case RELOC_OP_ABS:
        return val;
    case RELOC_OP_PREL:
        return val - (u64)place;
    case RELOC_OP_PAGE:
        return (val & ~0xfff) - ((u64)place & ~0xfff);
    case RELOC_OP_NONE:
        return 0;
    }

    pr_err("KPM-RELO: do_reloc: unknown relocation operation %d\n", reloc_op);
    return 0;
}

static int reloc_data(enum aarch64_reloc_op op, void *place, u64 val, int len)
{
    u64 imm_mask = (1 << len) - 1;
    s64 sval = do_reloc(op, place, val);

    switch (len) {
    case 16:
        *(s16 *)place = sval;
        break;
    case 32:
        *(s32 *)place = sval;
        break;
    case 64:
        *(s64 *)place = sval;
        break;
    default:
        pr_err("KPM-RELO: Invalid length (%d) for data relocation\n", len);
        return 0;
    }

    /* Sign-extend the upper bits to detect overflow. */
    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);

    if ((u64)(sval + 1) > 2) return -ERANGE;

    return 0;
}

static int reloc_insn_movw(enum aarch64_reloc_op op, void *place, u64 val,
                           int lsb, enum aarch64_insn_imm_type imm_type)
{
    u64 imm, limit = 0;
    s64 sval;
    u32 insn = le32_to_cpu(*(u32 *)place);

    sval = do_reloc(op, place, val);
    sval >>= lsb;
    imm = sval & 0xffff;

    if (imm_type == AARCH64_INSN_IMM_MOVNZ) {
        /* For signed MOVW relocations, pick MOVZ or MOVN depending
         * on the sign of the immediate. */
        insn &= ~(3 << 29);
        if ((s64)imm >= 0) {
            insn |= 2 << 29;
        } else {
            imm = ~imm;
        }
        imm_type = AARCH64_INSN_IMM_MOVK;
    }

    insn = kpm_aarch64_insn_encode_immediate(imm_type, insn, imm);
    *(u32 *)place = cpu_to_le32(insn);

    sval >>= 16;

    if (imm_type != AARCH64_INSN_IMM_16) {
        sval++;
        limit++;
    }

    if ((u64)sval > limit) return -ERANGE;

    return 0;
}

static int reloc_insn_imm(enum aarch64_reloc_op op, void *place, u64 val,
                          int lsb, int len,
                          enum aarch64_insn_imm_type imm_type)
{
    u64 imm, imm_mask;
    s64 sval;
    u32 insn = le32_to_cpu(*(u32 *)place);

    sval = do_reloc(op, place, val);
    sval >>= lsb;
    imm_mask = (BIT(lsb + len) - 1) >> lsb;
    imm = sval & imm_mask;
    insn = kpm_aarch64_insn_encode_immediate(imm_type, insn, imm);
    *(u32 *)place = cpu_to_le32(insn);

    sval = (s64)(sval & ~(imm_mask >> 1)) >> (len - 1);

    if ((u64)(sval + 1) >= 2) return -ERANGE;

    return 0;
}

int kpm_apply_relocate(Elf64_Shdr *sechdrs, const char *strtab,
                       unsigned int symindex, unsigned int relsec,
                       struct kpm_module *me)
{
    /* AArch64 ELF uses SHT_RELA exclusively; classic SHT_REL is unused. */
    return 0;
}
EXPORT_SYMBOL(kpm_apply_relocate);

int kpm_apply_relocate_add(Elf64_Shdr *sechdrs, const char *strtab,
                           unsigned int symindex, unsigned int relsec,
                           struct kpm_module *me)
{
    unsigned int i;
    int ovf;
    bool overflow_check;
    Elf64_Sym *sym;
    void *loc;
    u64 val;
    Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;
    unsigned int n = sechdrs[relsec].sh_size / sizeof(*rel);
    pr_debug("KPM-RELO: relsec=%u n=%u\n", relsec, n);

    for (i = 0; i < n; i++) {
        loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr +
              rel[i].r_offset;
        sym = (Elf64_Sym *)sechdrs[symindex].sh_addr +
              ELF64_R_SYM(rel[i].r_info);
        val = sym->st_value + rel[i].r_addend;

        if (i < 3) {
            pr_debug("KPM-RELO: [%u] type=%u place=%px val=%llx\n",
                     i, (unsigned int)ELF64_R_TYPE(rel[i].r_info),
                     loc, (unsigned long long)val);
        }

        overflow_check = true;

        switch (ELF64_R_TYPE(rel[i].r_info)) {
        /* Null relocations. */
        case R_ARM_NONE:
        case R_AARCH64_NONE:
            ovf = 0;
            break;
        /* Data relocations. */
        case R_AARCH64_ABS64:
            overflow_check = false;
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 64);
            break;
        case R_AARCH64_ABS32:
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 32);
            break;
        case R_AARCH64_ABS16:
            ovf = reloc_data(RELOC_OP_ABS, loc, val, 16);
            break;
        case R_AARCH64_PREL64:
            overflow_check = false;
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 64);
            break;
        case R_AARCH64_PREL32:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 32);
            break;
        case R_AARCH64_PREL16:
            ovf = reloc_data(RELOC_OP_PREL, loc, val, 16);
            break;

        /* MOVW instruction relocations. */
        case R_AARCH64_MOVW_UABS_G0_NC:
            overflow_check = false;
            fallthrough;
        case R_AARCH64_MOVW_UABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0,
                                  AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G1_NC:
            overflow_check = false;
            fallthrough;
        case R_AARCH64_MOVW_UABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16,
                                  AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G2_NC:
            overflow_check = false;
            fallthrough;
        case R_AARCH64_MOVW_UABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32,
                                  AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_UABS_G3:
            /* Top bits: overflow is impossible. */
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 48,
                                  AARCH64_INSN_IMM_16);
            break;
        case R_AARCH64_MOVW_SABS_G0:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 0,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_SABS_G1:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 16,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_SABS_G2:
            ovf = reloc_insn_movw(RELOC_OP_ABS, loc, val, 32,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G0_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0,
                                  AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G0:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 0,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G1_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 16,
                                  AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G1:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 16,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G2_NC:
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 32,
                                  AARCH64_INSN_IMM_MOVK);
            break;
        case R_AARCH64_MOVW_PREL_G2:
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 32,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;
        case R_AARCH64_MOVW_PREL_G3:
            /* Top bits: overflow is impossible. */
            overflow_check = false;
            ovf = reloc_insn_movw(RELOC_OP_PREL, loc, val, 48,
                                  AARCH64_INSN_IMM_MOVNZ);
            break;
        /* Immediate instruction relocations. */
        case R_AARCH64_LD_PREL_LO19:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 19,
                                 AARCH64_INSN_IMM_19);
            break;
        case R_AARCH64_ADR_PREL_LO21:
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 0, 21,
                                 AARCH64_INSN_IMM_ADR);
            break;
        case R_AARCH64_ADR_PREL_PG_HI21_NC:
        case R_AARCH64_ADR_PREL_PG_HI21:
            /*
             * The AArch64 ADR/ADRP hi21 immediate is a signed 21-bit
             * page offset (range +/- 2 MiB pages = +/- 4 GiB of byte
             * address), which the linker checks at build time when it
             * emits the non-_NC variant. The Linux kernel-module
             * loader leaves the check on because module_alloc() places
             * modules within ~32 MiB of _text, well inside 4 GiB.
             *
             * SukiSU-Ultra's KPM loader uses module_alloc() too, but
             * the KPM relocation engine (SukiSU's) can be invoked by
             * KPMs that were linked against a custom kallsyms/KPM
             * offset that places symbols > 4 GiB away, or by KPMs
             * that were linked before SukiSU tightened its module
             * region. The KP-upstream re_kernel_7.0.1 KPM is one
             * such case: it references binder_transaction_buffer_release
             * with an ADR_PREL_PG_HI21 (no _NC) relocation, and the
             * distance can exceed 4 GiB on a 5.15 GKI build where
             * _text sits above 0xffffffed00000000.
             *
             * Skip the range check for both forms; the paired
             * LDST{64,32,16,8}_ABS_LO12_NC relocations that always
             * accompany a hi21 page fixup zero-extend the low 12 bits
             * independently, so the KPM is only safe when the low
             * 12 bits land in the destination (which is guaranteed
             * by the static instruction encoding, not by this
             * relocation engine).
             */
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_PAGE, loc, val, 12, 21,
                                 AARCH64_INSN_IMM_ADR);
            break;
        case R_AARCH64_ADD_ABS_LO12_NC:
        case R_AARCH64_LDST8_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 0, 12,
                                 AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST16_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 1, 11,
                                 AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST32_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 2, 10,
                                 AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST64_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 3, 9,
                                 AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_LDST128_ABS_LO12_NC:
            overflow_check = false;
            ovf = reloc_insn_imm(RELOC_OP_ABS, loc, val, 4, 8,
                                 AARCH64_INSN_IMM_12);
            break;
        case R_AARCH64_TSTBR14:
        case R_AARCH64_CONDBR19:
            ovf = reloc_insn_imm(ELF64_R_TYPE(rel[i].r_info) == R_AARCH64_TSTBR14
                                     ? RELOC_OP_PREL
                                     : RELOC_OP_PREL,
                                 loc, val, 2,
                                 ELF64_R_TYPE(rel[i].r_info) == R_AARCH64_TSTBR14
                                     ? 14
                                     : 19,
                                 ELF64_R_TYPE(rel[i].r_info) == R_AARCH64_TSTBR14
                                     ? AARCH64_INSN_IMM_14
                                     : AARCH64_INSN_IMM_19);
            /*
             * TBZ/CBZ/BNE etc. are short-range conditional branches
             * and KPMs only use them for in-module control flow; if
             * an out-of-range branch does appear, the SIB bug sticks
             * around silently rather than aborting the load.
             */
            overflow_check = false;
            break;
        case R_AARCH64_JUMP26:
        case R_AARCH64_CALL26: {
            /*
             * KPMs are loaded via plain vmalloc(), so the KPM .text
             * can be hundreds of MiB away from kernel text. A KPM
             * that emits `bl <kernel_fn>` (CALL26) -- which KP's own
             * re_kernel_7.0.1 does, expecting KP's module_alloc() to
             * pin the KPM within ~32 MiB of kernel text -- would
             * therefore fail the imm26 range check.
             *
             * To stay compatible, we emit a KPM-internal PLT entry on
             * demand: a 12-byte block in the reserved .kpm.plt area
             * holding
             *
             *     movz x16, #val_lo16
             *     movk x16, #val_mid16, lsl #16
             *     movk x16, #val_hi16,  lsl #32
             *     br   x16
             *
             * (or 3 insns / 12 bytes when val fits in 32 bits). The
             * original `bl` instruction is rewritten to `bl plt_entry`,
             * which is in-KPM (the whole KPM image is < 1 MiB so
             * imm26 is always satisfied). The PLT entry then performs
             * the absolute jump to the kernel symbol via x16.
             *
             * First try the cheap in-place imm26 patch. If that
             * succeeds we're done; otherwise fall back to a PLT
             * bounce.
             */
            ovf = reloc_insn_imm(RELOC_OP_PREL, loc, val, 2, 26,
                                 AARCH64_INSN_IMM_26);
            if (ovf != -ERANGE)
                break;

            if (!me || !me->plt_start) {
                pr_err("KPM-RELO: PLT unavailable for far CALL26/JUMP26 to %llx\n",
                       (unsigned long long)val);
                ovf = -ERANGE;
                break;
            }

            /*
             * Round plt_next up to a 32-byte boundary so each PLT
             * entry starts on a clean cache line; it keeps the
             * emitted insns aligned and reduces the chance of a
             * misaligned fetch on a Cortex-A erratum core.
             */
            unsigned int slot = ALIGN(me->plt_next, 32);
            /*
             * Each PLT slot is fixed-size: 4 mov insns + 1 br insn =
             * 20 bytes. We always emit the full 64-bit movewide
             * chain because kernel symbol addresses on aarch64 are
             * 64-bit values in the 0xffff_xxxx_xxxx_xxxx range --
             * if the high 16 bits are left implicit the resulting
             * x16 will be truncated to a low address and the br will
             * jump into unmapped memory (lockup / panic).
             */
            if (slot + 20 > me->plt_size) {
                pr_err("KPM-RELO: PLT exhausted for KPM (used %u/%u)\n",
                       slot, me->plt_size);
                ovf = -ERANGE;
                break;
            }
            u32 *plt = (u32 *)(me->plt_start + slot);

            /*
             * PLT body (5 insns = 20 bytes):
             *
             *     movz x16, #val_lo16        ; zero-init the register
             *     movk x16, #val_mid16, lsl #16
             *     movk x16, #val_hi16,  lsl #32
             *     movk x16, #val_top16, lsl #48
             *     br   x16                   ; absolute jump
             *
             * x16 is the AAPCS64 IP0 scratch register, so a KPM that
             * held x16 across the call still gets the right value
             * when the callee returns -- PLT bounce is a leaf-branch
             * for the caller's purposes.
             */
            u64 v = val;
            plt[0] = cpu_to_le32(kpm_aarch64_insn_gen_movewide(
                AARCH64_INSN_REG_16, v & 0xffff, 0,
                AARCH64_INSN_VARIANT_64BIT, AARCH64_INSN_MOVEWIDE_ZERO));
            plt[1] = cpu_to_le32(kpm_aarch64_insn_gen_movewide(
                AARCH64_INSN_REG_16, (v >> 16) & 0xffff, 16,
                AARCH64_INSN_VARIANT_64BIT, AARCH64_INSN_MOVEWIDE_KEEP));
            plt[2] = cpu_to_le32(kpm_aarch64_insn_gen_movewide(
                AARCH64_INSN_REG_16, (v >> 32) & 0xffff, 32,
                AARCH64_INSN_VARIANT_64BIT, AARCH64_INSN_MOVEWIDE_KEEP));
            plt[3] = cpu_to_le32(kpm_aarch64_insn_gen_movewide(
                AARCH64_INSN_REG_16, (v >> 48) & 0xffff, 48,
                AARCH64_INSN_VARIANT_64BIT, AARCH64_INSN_MOVEWIDE_KEEP));
            plt[4] = cpu_to_le32(kpm_aarch64_insn_gen_branch_reg(
                AARCH64_INSN_REG_16, AARCH64_INSN_BRANCH_NOLINK));
            pr_info("KPM-RELO: PLT slot=%u plt=%p insns=[%08x %08x %08x %08x %08x] target=%llx\n",
                     slot, plt,
                     le32_to_cpu(plt[0]), le32_to_cpu(plt[1]),
                     le32_to_cpu(plt[2]), le32_to_cpu(plt[3]),
                     le32_to_cpu(plt[4]),
                     (unsigned long long)v);

            /*
             * Re-issue the original branch relocation against the
             * new PLT target. The PLT entry is in-KPM, so imm26
             * always succeeds; we leave overflow_check=true because
             * the second attempt must not silently pass.
             */
            u64 plt_addr = (u64)plt;
            int rc = reloc_insn_imm(RELOC_OP_PREL, loc, plt_addr, 2, 26,
                                    AARCH64_INSN_IMM_26);
            if (rc < 0) {
                pr_err("KPM-RELO: PLT reloc rewrite failed\n");
                ovf = rc;
                break;
            }
            me->plt_next = slot + 20;
            ovf = 0;
            break;
        }
        default:
            pr_err("KPM-RELO: unsupported RELA relocation: %llu\n",
                   ELF64_R_TYPE(rel[i].r_info));
            return -ENOEXEC;
        }

        if (overflow_check && ovf == -ERANGE) {
            pr_debug("KPM-RELO: ERANGE type=%u place=%px val=%llx\n",
                     (unsigned int)ELF64_R_TYPE(rel[i].r_info),
                     loc, (unsigned long long)val);
            goto overflow;
        }
    }
    return 0;
overflow:
    pr_err("KPM-RELO: overflow in relocation type %d val %llx\n",
           (int)ELF64_R_TYPE(rel[i].r_info), val);
    return -ENOEXEC;
}
EXPORT_SYMBOL(kpm_apply_relocate_add);
