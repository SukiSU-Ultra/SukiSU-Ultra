/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported to SukiSU-Ultra: 2025 Liankong.
 *
 * AArch64 instruction encoder. Ported from KernelPatch/insn.c. The
 * encoding rules are architecture-defined (ARM ARM C3.1) and require
 * only the Linux kernel's uapi <linux/elf.h> + our local aarch64
 * instruction definitions.
 */

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/stop_machine.h>
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/bits.h>
#include <linux/errno.h>
#include <asm/cacheflush.h>
#include <linux/printk.h>
#include <linux/cache.h>

#include "insn.h"

/* KP-style log prefixes mapped onto Linux pr_* helpers. */
#define logkfe(fmt, ...) pr_err("KPM-INS: %s: " fmt, __func__, ##__VA_ARGS__)
#define logke(fmt, ...) pr_err("KPM-INS: " fmt, ##__VA_ARGS__)

#define AARCH64_INSN_SF_BIT BIT(31)
#define AARCH64_INSN_N_BIT BIT(22)

#define AARCH64_BREAK_MON 0xd4200000
#define AARCH64_BREAK_FAULT (AARCH64_BREAK_MON | (0x100 << 5))

static int aarch64_insn_encoding_class[] = {
    AARCH64_INSN_CLS_UNKNOWN, AARCH64_INSN_CLS_UNKNOWN,
    AARCH64_INSN_CLS_UNKNOWN, AARCH64_INSN_CLS_UNKNOWN,
    AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_REG,
    AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_FPSIMD,
    AARCH64_INSN_CLS_DP_IMM,  AARCH64_INSN_CLS_DP_IMM,
    AARCH64_INSN_CLS_BR_SYS,  AARCH64_INSN_CLS_BR_SYS,
    AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_REG,
    AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_FPSIMD,
};

enum aarch64_insn_encoding_class aarch64_get_insn_class(u32 insn)
{
    return aarch64_insn_encoding_class[(insn >> 25) & 0xf];
}
EXPORT_SYMBOL(aarch64_get_insn_class);

bool aarch64_insn_is_nop(u32 insn)
{
    if (!aarch64_insn_is_hint(insn)) return false;

    switch (insn & 0xFE0) {
    case AARCH64_INSN_HINT_YIELD:
    case AARCH64_INSN_HINT_WFE:
    case AARCH64_INSN_HINT_WFI:
    case AARCH64_INSN_HINT_SEV:
    case AARCH64_INSN_HINT_SEVL:
        return false;
    default:
        return true;
    }
}
EXPORT_SYMBOL(aarch64_insn_is_nop);

void aarch64_insn_read(void *addr, u32 *insnp)
{
    *insnp = le32_to_cpu(*(u32 *)addr);
}
EXPORT_SYMBOL(aarch64_insn_read);

void aarch64_insn_write(void *addr, u32 insn)
{
    *(u32 *)addr = cpu_to_le32(insn);
}
EXPORT_SYMBOL(aarch64_insn_write);

static bool __aarch64_insn_hotpatch_safe(u32 insn)
{
    if (aarch64_get_insn_class(insn) != AARCH64_INSN_CLS_BR_SYS) return false;

    return aarch64_insn_is_b(insn) || aarch64_insn_is_bl(insn) ||
           aarch64_insn_is_svc(insn) || aarch64_insn_is_hvc(insn) ||
           aarch64_insn_is_smc(insn) || aarch64_insn_is_brk(insn) ||
           aarch64_insn_is_nop(insn);
}

bool aarch64_insn_hotpatch_safe(u32 old_insn, u32 new_insn)
{
    return __aarch64_insn_hotpatch_safe(old_insn) &&
           __aarch64_insn_hotpatch_safe(new_insn);
}
EXPORT_SYMBOL(aarch64_insn_hotpatch_safe);

int aarch64_insn_patch_text_nosync(void *addr, u32 insn)
{
    u32 *tp = addr;
    int ret = 0;
    if ((uintptr_t)tp & 0x3) return -EINVAL;
    aarch64_insn_write(tp, insn);
    flush_icache_range((uintptr_t)tp, (uintptr_t)tp + AARCH64_INSN_SIZE);
    return ret;
}
EXPORT_SYMBOL(aarch64_insn_patch_text_nosync);

struct aarch64_insn_patch {
    void **text_addrs;
    u32 *new_insns;
    int insn_cnt;
    atomic_t cpu_count;
};

static int aarch64_insn_patch_text_cb(void *arg)
{
    int i, ret = 0;
    struct aarch64_insn_patch *pp = arg;

    if (atomic_inc_return(&pp->cpu_count) == 1) {
        for (i = 0; ret == 0 && i < pp->insn_cnt; i++)
            ret = aarch64_insn_patch_text_nosync(pp->text_addrs[i],
                                                 pp->new_insns[i]);
        /* Master flushes the icache; aarch64_insn_patch_text_nosync
         * already issued a dsb;isb pair for global visibility. */
        atomic_inc(&pp->cpu_count);
    } else {
        /* Other CPUs spin until the master has published the patch. */
        while (atomic_read(&pp->cpu_count) <= num_online_cpus()) cpu_relax();
        isb();
    }

    return ret;
}

int aarch64_insn_patch_text_sync(void *addrs[], u32 insns[], int cnt)
{
    struct aarch64_insn_patch patch = {
        .text_addrs = addrs,
        .new_insns = insns,
        .insn_cnt = cnt,
        .cpu_count = ATOMIC_INIT(0),
    };

    if (cnt <= 0) return -EINVAL;

    return stop_machine(aarch64_insn_patch_text_cb, &patch, cpu_online_mask);
}
EXPORT_SYMBOL(aarch64_insn_patch_text_sync);

int aarch64_insn_patch_text(void *addrs[], u32 insns[], int cnt)
{
    int ret;
    u32 insn;

    if (cnt == 1) {
        aarch64_insn_read(addrs[0], &insn);
        if (aarch64_insn_hotpatch_safe(insn, insns[0])) {
            ret = aarch64_insn_patch_text_nosync(addrs[0], insns[0]);
            return ret;
        }
    }

    return aarch64_insn_patch_text_sync(addrs, insns, cnt);
}
EXPORT_SYMBOL(aarch64_insn_patch_text);

u32 aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type, u32 insn,
                                  u64 imm)
{
    u32 immlo, immhi, lomask, himask, mask;
    int shift;

    switch (type) {
    case AARCH64_INSN_IMM_ADR:
        lomask = 0x3;
        himask = 0x7ffff;
        immlo = imm & lomask;
        imm >>= 2;
        immhi = imm & himask;
        imm = (immlo << 24) | (immhi);
        mask = (lomask << 24) | (himask);
        shift = 5;
        break;
    case AARCH64_INSN_IMM_26:
        mask = BIT(26) - 1;
        shift = 0;
        break;
    case AARCH64_INSN_IMM_19:
        mask = BIT(19) - 1;
        shift = 5;
        break;
    case AARCH64_INSN_IMM_16:
        mask = BIT(16) - 1;
        shift = 5;
        break;
    case AARCH64_INSN_IMM_14:
        mask = BIT(14) - 1;
        shift = 5;
        break;
    case AARCH64_INSN_IMM_12:
        mask = BIT(12) - 1;
        shift = 10;
        break;
    case AARCH64_INSN_IMM_9:
        mask = BIT(9) - 1;
        shift = 12;
        break;
    case AARCH64_INSN_IMM_7:
        mask = BIT(7) - 1;
        shift = 15;
        break;
    case AARCH64_INSN_IMM_6:
    case AARCH64_INSN_IMM_S:
        mask = BIT(6) - 1;
        shift = 10;
        break;
    case AARCH64_INSN_IMM_R:
        mask = BIT(6) - 1;
        shift = 16;
        break;
    default:
        logke("aarch64_insn_encode_immediate: unknown immediate encoding %d\n",
              type);
        return 0;
    }

    insn &= ~(mask << shift);
    insn |= (imm & mask) << shift;

    return insn;
}
EXPORT_SYMBOL(aarch64_insn_encode_immediate);

static u32 aarch64_insn_encode_register(enum aarch64_insn_register_type type,
                                        u32 insn, enum aarch64_insn_register reg)
{
    int shift;

    if (reg < AARCH64_INSN_REG_0 || reg > AARCH64_INSN_REG_SP) {
        logkfe("unknown register encoding %d\n", reg);
        return 0;
    }

    switch (type) {
    case AARCH64_INSN_REGTYPE_RT:
    case AARCH64_INSN_REGTYPE_RD:
        shift = 0;
        break;
    case AARCH64_INSN_REGTYPE_RN:
        shift = 5;
        break;
    case AARCH64_INSN_REGTYPE_RT2:
    case AARCH64_INSN_REGTYPE_RA:
        shift = 10;
        break;
    case AARCH64_INSN_REGTYPE_RM:
        shift = 16;
        break;
    default:
        logkfe("unknown register type encoding %d\n", type);
        return 0;
    }

    insn &= ~(GENMASK(4, 0) << shift);
    insn |= reg << shift;

    return insn;
}

static u32 aarch64_insn_encode_ldst_size(enum aarch64_insn_size_type type,
                                        u32 insn)
{
    u32 size;

    switch (type) {
    case AARCH64_INSN_SIZE_8:
        size = 0;
        break;
    case AARCH64_INSN_SIZE_16:
        size = 1;
        break;
    case AARCH64_INSN_SIZE_32:
        size = 2;
        break;
    case AARCH64_INSN_SIZE_64:
        size = 3;
        break;
    default:
        logkfe("unknown size encoding %d\n", type);
        return 0;
    }

    insn &= ~GENMASK(31, 30);
    insn |= size << 30;

    return insn;
}

static inline long branch_imm_common(unsigned long pc, unsigned long addr,
                                      long range)
{
    long offset;

    BUG_ON((pc & 0x3) || (addr & 0x3));

    offset = ((long)addr - (long)pc);
    BUG_ON(offset < -range || offset >= range);

    return offset;
}

u32 aarch64_insn_gen_branch_imm(unsigned long pc, unsigned long addr,
                                enum aarch64_insn_branch_type type)
{
    u32 insn;
    long offset;

    /* B/BL support [-128M, 128M) offset; ARM64 VA layout guarantees
     * all kernel and module text are within +/-128M. */
    offset = branch_imm_common(pc, addr, SZ_128M);

    switch (type) {
    case AARCH64_INSN_BRANCH_LINK:
        insn = aarch64_insn_get_bl_value();
        break;
    case AARCH64_INSN_BRANCH_NOLINK:
        insn = aarch64_insn_get_b_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_26, insn,
                                         offset >> 2);
}
EXPORT_SYMBOL(aarch64_insn_gen_branch_imm);

u32 aarch64_insn_gen_comp_branch_imm(unsigned long pc, unsigned long addr,
                                     enum aarch64_insn_register reg,
                                     enum aarch64_insn_variant variant,
                                     enum aarch64_insn_branch_type type)
{
    u32 insn;
    long offset;

    offset = branch_imm_common(pc, addr, SZ_1M);

    switch (type) {
    case AARCH64_INSN_BRANCH_COMP_ZERO:
        insn = aarch64_insn_get_cbz_value();
        break;
    case AARCH64_INSN_BRANCH_COMP_NONZERO:
        insn = aarch64_insn_get_cbnz_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT, insn, reg);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_19, insn,
                                         offset >> 2);
}
EXPORT_SYMBOL(aarch64_insn_gen_comp_branch_imm);

u32 aarch64_insn_gen_cond_branch_imm(unsigned long pc, unsigned long addr,
                                     enum aarch64_insn_condition cond)
{
    u32 insn;
    long offset;

    offset = branch_imm_common(pc, addr, SZ_1M);

    insn = aarch64_insn_get_bcond_value();

    BUG_ON(cond < AARCH64_INSN_COND_EQ || cond > AARCH64_INSN_COND_AL);
    insn |= cond;

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_19, insn,
                                         offset >> 2);
}
EXPORT_SYMBOL(aarch64_insn_gen_cond_branch_imm);

u32 aarch64_insn_gen_hint(enum aarch64_insn_hint_op op)
{
    return aarch64_insn_get_hint_value() | op;
}
EXPORT_SYMBOL(aarch64_insn_gen_hint);

u32 aarch64_insn_gen_nop(void)
{
    return aarch64_insn_gen_hint(AARCH64_INSN_HINT_NOP);
}
EXPORT_SYMBOL(aarch64_insn_gen_nop);

u32 aarch64_insn_gen_branch_reg(enum aarch64_insn_register reg,
                                enum aarch64_insn_branch_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_BRANCH_NOLINK:
        insn = aarch64_insn_get_br_value();
        break;
    case AARCH64_INSN_BRANCH_LINK:
        insn = aarch64_insn_get_blr_value();
        break;
    case AARCH64_INSN_BRANCH_RETURN:
        insn = aarch64_insn_get_ret_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, reg);
}
EXPORT_SYMBOL(aarch64_insn_gen_branch_reg);

u32 aarch64_insn_gen_load_store_reg(enum aarch64_insn_register reg,
                                    enum aarch64_insn_register base,
                                    enum aarch64_insn_register offset,
                                    enum aarch64_insn_size_type size,
                                    enum aarch64_insn_ldst_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_LDST_LOAD_REG_OFFSET:
        insn = aarch64_insn_get_ldr_reg_value();
        break;
    case AARCH64_INSN_LDST_STORE_REG_OFFSET:
        insn = aarch64_insn_get_str_reg_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_ldst_size(size, insn);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT, insn, reg);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, base);

    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, offset);
}
EXPORT_SYMBOL(aarch64_insn_gen_load_store_reg);

u32 aarch64_insn_gen_load_store_pair(enum aarch64_insn_register reg1,
                                     enum aarch64_insn_register reg2,
                                     enum aarch64_insn_register base,
                                     int offset,
                                     enum aarch64_insn_variant variant,
                                     enum aarch64_insn_ldst_type type)
{
    u32 insn;
    int shift;

    switch (type) {
    case AARCH64_INSN_LDST_LOAD_PAIR_PRE_INDEX:
        insn = aarch64_insn_get_ldp_pre_value();
        break;
    case AARCH64_INSN_LDST_STORE_PAIR_PRE_INDEX:
        insn = aarch64_insn_get_stp_pre_value();
        break;
    case AARCH64_INSN_LDST_LOAD_PAIR_POST_INDEX:
        insn = aarch64_insn_get_ldp_post_value();
        break;
    case AARCH64_INSN_LDST_STORE_PAIR_POST_INDEX:
        insn = aarch64_insn_get_stp_post_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        /* offset must be multiples of 4 in the range [-256, 252] */
        BUG_ON(offset & 0x3);
        BUG_ON(offset < -256 || offset > 252);
        shift = 2;
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        /* offset must be multiples of 8 in the range [-512, 504] */
        BUG_ON(offset & 0x7);
        BUG_ON(offset < -512 || offset > 504);
        shift = 3;
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT, insn, reg1);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RT2, insn, reg2);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, base);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_7, insn,
                                         offset >> shift);
}
EXPORT_SYMBOL(aarch64_insn_gen_load_store_pair);

u32 aarch64_insn_gen_add_sub_imm(enum aarch64_insn_register dst,
                                 enum aarch64_insn_register src, int imm,
                                 enum aarch64_insn_variant variant,
                                 enum aarch64_insn_adsb_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_ADSB_ADD:
        insn = aarch64_insn_get_add_imm_value();
        break;
    case AARCH64_INSN_ADSB_SUB:
        insn = aarch64_insn_get_sub_imm_value();
        break;
    case AARCH64_INSN_ADSB_ADD_SETFLAGS:
        insn = aarch64_insn_get_adds_imm_value();
        break;
    case AARCH64_INSN_ADSB_SUB_SETFLAGS:
        insn = aarch64_insn_get_subs_imm_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    BUG_ON(imm & ~(SZ_4K - 1));

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_12, insn, imm);
}
EXPORT_SYMBOL(aarch64_insn_gen_add_sub_imm);

u32 aarch64_insn_gen_bitfield(enum aarch64_insn_register dst,
                              enum aarch64_insn_register src, int immr,
                              int imms, enum aarch64_insn_variant variant,
                              enum aarch64_insn_bitfield_type type)
{
    u32 insn;
    u32 mask;

    switch (type) {
    case AARCH64_INSN_BITFIELD_MOVE:
        insn = aarch64_insn_get_bfm_value();
        break;
    case AARCH64_INSN_BITFIELD_MOVE_UNSIGNED:
        insn = aarch64_insn_get_ubfm_value();
        break;
    case AARCH64_INSN_BITFIELD_MOVE_SIGNED:
        insn = aarch64_insn_get_sbfm_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        mask = GENMASK(4, 0);
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT | AARCH64_INSN_N_BIT;
        mask = GENMASK(5, 0);
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    BUG_ON(immr & ~mask);
    BUG_ON(imms & ~mask);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);

    insn = aarch64_insn_encode_immediate(AARCH64_INSN_IMM_R, insn, immr);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_S, insn, imms);
}
EXPORT_SYMBOL(aarch64_insn_gen_bitfield);

u32 aarch64_insn_gen_movewide(enum aarch64_insn_register dst, int imm,
                              int shift, enum aarch64_insn_variant variant,
                              enum aarch64_insn_movewide_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_MOVEWIDE_ZERO:
        insn = aarch64_insn_get_movz_value();
        break;
    case AARCH64_INSN_MOVEWIDE_KEEP:
        insn = aarch64_insn_get_movk_value();
        break;
    case AARCH64_INSN_MOVEWIDE_INVERSE:
        insn = aarch64_insn_get_movn_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    BUG_ON(imm & ~(SZ_64K - 1));

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        BUG_ON(shift != 0 && shift != 16);
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        BUG_ON(shift != 0 && shift != 16 && shift != 32 && shift != 48);
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    insn |= (shift >> 4) << 21;

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);

    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_16, insn, imm);
}
EXPORT_SYMBOL(aarch64_insn_gen_movewide);

u32 aarch64_insn_gen_add_sub_shifted_reg(enum aarch64_insn_register dst,
                                         enum aarch64_insn_register src,
                                         enum aarch64_insn_register reg,
                                         int shift,
                                         enum aarch64_insn_variant variant,
                                         enum aarch64_insn_adsb_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_ADSB_ADD:
        insn = aarch64_insn_get_add_value();
        break;
    case AARCH64_INSN_ADSB_SUB:
        insn = aarch64_insn_get_sub_value();
        break;
    case AARCH64_INSN_ADSB_ADD_SETFLAGS:
        insn = aarch64_insn_get_adds_value();
        break;
    case AARCH64_INSN_ADSB_SUB_SETFLAGS:
        insn = aarch64_insn_get_subs_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        BUG_ON(shift & ~(SZ_32 - 1));
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        BUG_ON(shift & ~(SZ_64 - 1));
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);
    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);
    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, reg);
    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_6, insn, shift);
}
EXPORT_SYMBOL(aarch64_insn_gen_add_sub_shifted_reg);

u32 aarch64_insn_gen_data1(enum aarch64_insn_register dst,
                           enum aarch64_insn_register src,
                           enum aarch64_insn_variant variant,
                           enum aarch64_insn_data1_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_DATA1_REVERSE_16:
        insn = aarch64_insn_get_rev16_value();
        break;
    case AARCH64_INSN_DATA1_REVERSE_32:
        insn = aarch64_insn_get_rev32_value();
        break;
    case AARCH64_INSN_DATA1_REVERSE_64:
        BUG_ON(variant != AARCH64_INSN_VARIANT_64BIT);
        insn = aarch64_insn_get_rev64_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);
    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);
}
EXPORT_SYMBOL(aarch64_insn_gen_data1);

u32 aarch64_insn_gen_data2(enum aarch64_insn_register dst,
                           enum aarch64_insn_register src,
                           enum aarch64_insn_register reg,
                           enum aarch64_insn_variant variant,
                           enum aarch64_insn_data2_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_DATA2_UDIV:
        insn = aarch64_insn_get_udiv_value();
        break;
    case AARCH64_INSN_DATA2_SDIV:
        insn = aarch64_insn_get_sdiv_value();
        break;
    case AARCH64_INSN_DATA2_LSLV:
        insn = aarch64_insn_get_lslv_value();
        break;
    case AARCH64_INSN_DATA2_LSRV:
        insn = aarch64_insn_get_lsrv_value();
        break;
    case AARCH64_INSN_DATA2_ASRV:
        insn = aarch64_insn_get_asrv_value();
        break;
    case AARCH64_INSN_DATA2_RORV:
        insn = aarch64_insn_get_rorv_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);
    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);
    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, reg);
}
EXPORT_SYMBOL(aarch64_insn_gen_data2);

u32 aarch64_insn_gen_data3(enum aarch64_insn_register dst,
                           enum aarch64_insn_register src,
                           enum aarch64_insn_register reg1,
                           enum aarch64_insn_register reg2,
                           enum aarch64_insn_variant variant,
                           enum aarch64_insn_data3_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_DATA3_MADD:
        insn = aarch64_insn_get_madd_value();
        break;
    case AARCH64_INSN_DATA3_MSUB:
        insn = aarch64_insn_get_msub_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);
    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RA, insn, src);
    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, reg1);
    return aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, reg2);
}
EXPORT_SYMBOL(aarch64_insn_gen_data3);

u32 aarch64_insn_gen_logical_shifted_reg(enum aarch64_insn_register dst,
                                         enum aarch64_insn_register src,
                                         enum aarch64_insn_register reg,
                                         int shift,
                                         enum aarch64_insn_variant variant,
                                         enum aarch64_insn_logic_type type)
{
    u32 insn;

    switch (type) {
    case AARCH64_INSN_LOGIC_AND:
        insn = aarch64_insn_get_and_value();
        break;
    case AARCH64_INSN_LOGIC_BIC:
        insn = aarch64_insn_get_bic_value();
        break;
    case AARCH64_INSN_LOGIC_ORR:
        insn = aarch64_insn_get_orr_value();
        break;
    case AARCH64_INSN_LOGIC_ORN:
        insn = aarch64_insn_get_orn_value();
        break;
    case AARCH64_INSN_LOGIC_EOR:
        insn = aarch64_insn_get_eor_value();
        break;
    case AARCH64_INSN_LOGIC_EON:
        insn = aarch64_insn_get_eon_value();
        break;
    case AARCH64_INSN_LOGIC_AND_SETFLAGS:
        insn = aarch64_insn_get_ands_value();
        break;
    case AARCH64_INSN_LOGIC_BIC_SETFLAGS:
        insn = aarch64_insn_get_bics_value();
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    switch (variant) {
    case AARCH64_INSN_VARIANT_32BIT:
        BUG_ON(shift & ~(SZ_32 - 1));
        break;
    case AARCH64_INSN_VARIANT_64BIT:
        insn |= AARCH64_INSN_SF_BIT;
        BUG_ON(shift & ~(SZ_64 - 1));
        break;
    default:
        BUG_ON(1);
        return AARCH64_BREAK_FAULT;
    }

    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RD, insn, dst);
    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RN, insn, src);
    insn = aarch64_insn_encode_register(AARCH64_INSN_REGTYPE_RM, insn, reg);
    return aarch64_insn_encode_immediate(AARCH64_INSN_IMM_6, insn, shift);
}
EXPORT_SYMBOL(aarch64_insn_gen_logical_shifted_reg);
