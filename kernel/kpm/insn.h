/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported to SukiSU-Ultra: 2025 Liankong.
 *
 * SukiSU-Ultra port of KernelPatch's AArch64 instruction encoder. All
 * enums, encoding-class constants, and the __AARCH64_INSN_FUNCS macro
 * (which generates `aarch64_insn_is_*` / `aarch64_insn_get_*_value`
 * inline helpers) come from the kernel's <asm/insn.h> on GKI 2.0.
 * This header only declares the KPM-side helpers, which all carry a
 * `kpm_` prefix to avoid colliding with vmlinux-exported symbols.
 */

#ifndef _SUKISU_KPM_INSN_H_
#define _SUKISU_KPM_INSN_H_

#include <asm/insn.h>

bool kpm_aarch64_insn_is_nop(u32 insn);

void kpm_aarch64_insn_read(void *addr, u32 *insnp);
void kpm_aarch64_insn_write(void *addr, u32 insn);

/*
 * GKI 5.15+ no longer exports `enum aarch64_insn_encoding_class` nor
 * the `AARCH64_INSN_CLS_*` enumerators. The numeric values themselves
 * are architecture-defined by the ARM ARM (C3.1) and have not changed
 * since they were first introduced, so KPM keeps a local mirror of
 * the six values it actually needs (UNKNOWN / DP_IMM / DP_REG /
 * DP_FPSIMD / LDST / BR_SYS).
 *
 * `kpm_aarch64_get_insn_class()` wraps the kernel's
 * `aarch64_get_insn_class()` (still exported on 5.15/6.6) and returns
 * one of these values. Callers should compare against the
 * `KPM_AARCH64_INSN_CLS_*` constants below instead of any
 * `<asm/insn.h>` symbol.
 */
enum kpm_aarch64_insn_encoding_class {
	KPM_AARCH64_INSN_CLS_UNKNOWN	= 0,
	KPM_AARCH64_INSN_CLS_DP_IMM	= 1,
	KPM_AARCH64_INSN_CLS_DP_REG	= 2,
	KPM_AARCH64_INSN_CLS_DP_FPSIMD	= 3,
	KPM_AARCH64_INSN_CLS_LDST	= 4,
	KPM_AARCH64_INSN_CLS_BR_SYS	= 5,
};

int kpm_aarch64_get_insn_class(u32 insn);

u32 kpm_aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type, u32 insn,
                                      u64 imm);
u32 kpm_aarch64_insn_gen_branch_imm(unsigned long pc, unsigned long addr,
                                    enum aarch64_insn_branch_type type);
u32 kpm_aarch64_insn_gen_comp_branch_imm(unsigned long pc, unsigned long addr,
                                         enum aarch64_insn_register reg,
                                         enum aarch64_insn_variant variant,
                                         enum aarch64_insn_branch_type type);
u32 kpm_aarch64_insn_gen_cond_branch_imm(unsigned long pc, unsigned long addr,
                                         enum aarch64_insn_condition cond);
u32 kpm_aarch64_insn_gen_hint(enum aarch64_insn_hint_cr_op op);
u32 kpm_aarch64_insn_gen_nop(void);
u32 kpm_aarch64_insn_gen_branch_reg(enum aarch64_insn_register reg,
                                    enum aarch64_insn_branch_type type);
u32 kpm_aarch64_insn_gen_load_store_reg(enum aarch64_insn_register reg,
                                        enum aarch64_insn_register base,
                                        enum aarch64_insn_register offset,
                                        enum aarch64_insn_size_type size,
                                        enum aarch64_insn_ldst_type type);
u32 kpm_aarch64_insn_gen_load_store_pair(enum aarch64_insn_register reg1,
                                         enum aarch64_insn_register reg2,
                                         enum aarch64_insn_register base,
                                         int offset,
                                         enum aarch64_insn_variant variant,
                                         enum aarch64_insn_ldst_type type);
u32 kpm_aarch64_insn_gen_add_sub_imm(enum aarch64_insn_register dst,
                                     enum aarch64_insn_register src, int imm,
                                     enum aarch64_insn_variant variant,
                                     enum aarch64_insn_adsb_type type);
u32 kpm_aarch64_insn_gen_bitfield(enum aarch64_insn_register dst,
                                  enum aarch64_insn_register src, int immr,
                                  int imms,
                                  enum aarch64_insn_variant variant,
                                  enum aarch64_insn_bitfield_type type);
u32 kpm_aarch64_insn_gen_movewide(enum aarch64_insn_register dst, int imm,
                                  int shift,
                                  enum aarch64_insn_variant variant,
                                  enum aarch64_insn_movewide_type type);
u32 kpm_aarch64_insn_gen_add_sub_shifted_reg(enum aarch64_insn_register dst,
                                             enum aarch64_insn_register src,
                                             enum aarch64_insn_register reg,
                                             int shift,
                                             enum aarch64_insn_variant variant,
                                             enum aarch64_insn_adsb_type type);
u32 kpm_aarch64_insn_gen_data1(enum aarch64_insn_register dst,
                               enum aarch64_insn_register src,
                               enum aarch64_insn_variant variant,
                               enum aarch64_insn_data1_type type);
u32 kpm_aarch64_insn_gen_data2(enum aarch64_insn_register dst,
                               enum aarch64_insn_register src,
                               enum aarch64_insn_register reg,
                               enum aarch64_insn_variant variant,
                               enum aarch64_insn_data2_type type);
u32 kpm_aarch64_insn_gen_data3(enum aarch64_insn_register dst,
                               enum aarch64_insn_register src,
                               enum aarch64_insn_register reg1,
                               enum aarch64_insn_register reg2,
                               enum aarch64_insn_variant variant,
                               enum aarch64_insn_data3_type type);
u32 kpm_aarch64_insn_gen_logical_shifted_reg(enum aarch64_insn_register dst,
                                             enum aarch64_insn_register src,
                                             enum aarch64_insn_register reg,
                                             int shift,
                                             enum aarch64_insn_variant variant,
                                             enum aarch64_insn_logic_type type);

bool kpm_aarch64_insn_hotpatch_safe(u32 old_insn, u32 new_insn);

int kpm_aarch64_insn_patch_text_nosync(void *addr, u32 insn);
int kpm_aarch64_insn_patch_text_sync(void *addrs[], u32 insns[], int cnt);
int kpm_aarch64_insn_patch_text(void *addrs[], u32 insns[], int cnt);

#endif
