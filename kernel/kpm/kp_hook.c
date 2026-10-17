/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported from KernelPatch to SukiSU-Ultra: 2025 Liankong.
 *
 * Inline-hook engine for SukiSU-Ultra KPM. Verbatim port of
 * kernel/base/hook.c from upstream KernelPatch. The runtime
 * backends (hotpatch / hook_mem_zalloc / hook_mem_free) that
 * kernel/base/hook.c relies on live in kp_hook_runtime.c; the
 * KP .kp.symbol-section EXPORT macro is replaced with the
 * kernel's standard EXPORT_SYMBOL so the helpers are visible
 * through kallsyms as well.
 *
 * Linux module linking has no _transit*_end markers (the kpimg
 * linker script provides them, the Linux kbuild does not). The
 * companion kp_hook_engine.c therefore supplies the
 * hook_chain_prepare() override and absolute-branches the
 * trampolines to the resident LKM _transit* functions. We define
 * KP_HOOK_EXTERNAL_CHAIN_PREPARE here so the static fallback
 * implementation in this file (which would try to take the size
 * of the _transit* functions) is compiled out.
 */
#define KP_HOOK_EXTERNAL_CHAIN_PREPARE

#include <hook.h>                 /* SukiSU kernel/include/hook.h */
#include <linux/io.h>             /* was <io.h> */
#include <linux/kallsyms.h>       /* was <symbol.h> */
#include <asm/pgtable.h>          /* was <pgtable.h> */
#include "../hook/patch_memory.h" /* was <hotpatch.h> -- SukiSU ksu_patch_text */
#include <linux/vmalloc.h>        /* was <kpmalloc.h> */
#include "kp_hook_runtime.h"      /* was "hmem.h" -- SukiSU hook backend */

/* KP's `__noinline` is shorthand for `noinline`. <linux/compiler.h>
 * defines it on 5.10+ but the alias is not always re-exported through
 * the headers we transitively pull in. Provide a fallback that matches
 * the upstream KP LKM hook_engine.c. */
#ifndef __noinline
#define __noinline noinline
#endif

/* When KP_HOOK_EXTERNAL_CHAIN_PREPARE is defined (it is, see above)
 * the static hook_chain_prepare() body in this file is compiled out
 * and the symbol is provided by kp_hook_engine.c instead. kp_hook.c
 * is a separate translation unit from kp_hook_engine.c, so the symbol
 * must be extern -- it is exactly this extern that the upstream KP
 * LKM sidesteps by #include-ing hook.c directly into hook_engine.c. */
extern hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno);

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)
#define align_ceil(x, align) (((u64)(x) + (u64)(align) - 1) & ~((u64)(align) - 1))

typedef uint32_t inst_type_t;
typedef uint32_t inst_mask_t;

#define INST_B 0x14000000
#define INST_BC 0x54000000
#define INST_BL 0x94000000
#define INST_ADR 0x10000000
#define INST_ADRP 0x90000000
#define INST_LDR_32 0x18000000
#define INST_LDR_64 0x58000000
#define INST_LDRSW_LIT 0x98000000
#define INST_PRFM_LIT 0xD8000000
#define INST_LDR_SIMD_32 0x1C000000
#define INST_LDR_SIMD_64 0x5C000000
#define INST_LDR_SIMD_128 0x9C000000
#define INST_CBZ 0x34000000
#define INST_CBNZ 0x35000000
#define INST_TBZ 0x36000000
#define INST_TBNZ 0x37000000
#define INST_HINT 0xD503201F
#define INST_IGNORE 0x0

#define MASK_B 0xFC000000
#define MASK_BC 0xFF000010
#define MASK_BL 0xFC000000
#define MASK_ADR 0x9F000000
#define MASK_ADRP 0x9F000000
#define MASK_LDR_32 0xFF000000
#define MASK_LDR_64 0xFF000000
#define MASK_LDRSW_LIT 0xFF000000
#define MASK_PRFM_LIT 0xFF000000
#define MASK_LDR_SIMD_32 0xFF000000
#define MASK_LDR_SIMD_64 0xFF000000
#define MASK_LDR_SIMD_128 0xFF000000
#define MASK_CBZ 0x7F000000u
#define MASK_CBNZ 0x7F000000u
#define MASK_TBZ 0x7F000000u
#define MASK_TBNZ 0x7F000000u
#define MASK_HINT 0xFFFFF01F
#define MASK_IGNORE 0x0

static inst_mask_t masks[] = {
    MASK_B,      MASK_BC,        MASK_BL,       MASK_ADR,         MASK_ADRP,        MASK_LDR_32,
    MASK_LDR_64, MASK_LDRSW_LIT, MASK_PRFM_LIT, MASK_LDR_SIMD_32, MASK_LDR_SIMD_64, MASK_LDR_SIMD_128,
    MASK_CBZ,    MASK_CBNZ,      MASK_TBZ,      MASK_TBNZ,        MASK_IGNORE,
};
static inst_type_t types[] = {
    INST_B,      INST_BC,        INST_BL,       INST_ADR,         INST_ADRP,        INST_LDR_32,
    INST_LDR_64, INST_LDRSW_LIT, INST_PRFM_LIT, INST_LDR_SIMD_32, INST_LDR_SIMD_64, INST_LDR_SIMD_128,
    INST_CBZ,    INST_CBNZ,      INST_TBZ,      INST_TBNZ,        INST_IGNORE,
};

static int32_t relo_len[] = { 6, 8, 8, 4, 4, 6, 6, 6, 8, 8, 8, 8, 6, 6, 6, 6, 2 };

// static uint64_t sign_extend(uint64_t x, uint32_t len)
// {
//     char sign_bit = bit(x, len - 1);
//     unsigned long sign_mask = 0 - sign_bit;
//     x |= ((sign_mask >> len) << len);
//     return x;
// }

static int is_in_tramp(hook_t *hook, uint64_t addr)
{
    uint64_t tramp_start = hook->origin_addr;
    uint64_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (addr >= tramp_start && addr < tramp_end) {
        return 1;
    }
    return 0;
}

static uint64_t relo_in_tramp(hook_t *hook, uint64_t addr)
{
    uint64_t tramp_start = hook->origin_addr;
    uint64_t tramp_end = tramp_start + hook->tramp_insts_num * 4;
    if (!(addr >= tramp_start && addr < tramp_end)) return addr;
    uint32_t addr_inst_index = (addr - tramp_start) / 4;
    uint64_t fix_addr = hook->relo_addr;
    for (int i = 0; i < addr_inst_index; i++) {
        inst_type_t inst = hook->origin_insts[i];
        for (int j = 0; j < sizeof(relo_len) / sizeof(relo_len[0]); j++) {
            if ((inst & masks[j]) == types[j]) {
                fix_addr += relo_len[j] * 4;
                break;
            }
        }
    }
    return fix_addr;
}

#ifdef HOOK_INTO_BRANCH_FUNC

static uint64_t branch_func_addr_once(uint64_t addr)
{
    uint64_t ret = addr;
    uint32_t inst = *(uint32_t *)addr;
    if ((inst & MASK_B) == INST_B) {
        uint64_t imm26 = bits32(inst, 25, 0);
        uint64_t imm64 = sign64_extend(imm26 << 2u, 28u);
        ret = addr + imm64;
    } else if (inst == ARM64_BTI_C || inst == ARM64_BTI_J ||
               (inst == ARM64_BTI_JC && !hook_get_mem_from_origin(addr))) {
        ret = addr + 4;
    } else {
    }
    return ret;
}

uint64_t branch_func_addr(uint64_t addr)
{
    uint64_t ret;
    for (;;) {
        ret = branch_func_addr_once(addr);
        if (ret == addr) break;
        addr = ret;
    }
    return ret;
}

#endif

static __noinline hook_err_t relo_b(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    uint64_t imm64;
    if (type == INST_BC) {
        uint64_t imm19 = bits32(inst, 23, 5);
        imm64 = sign64_extend(imm19 << 2u, 21u);
    } else {
        uint64_t imm26 = bits32(inst, 25, 0);
        imm64 = sign64_extend(imm26 << 2u, 28u);
    }
    uint64_t addr = inst_addr + imm64;
    addr = relo_in_tramp(hook, addr);

    uint32_t idx = 0;
    if (type == INST_BC) {
        buf[idx++] = (inst & 0xFF00001F) | 0x40u; // B.<cond> #8
        buf[idx++] = 0x14000006; // B #24
    }
    buf[idx++] = 0x58000051; // LDR X17, #8
    buf[idx++] = 0x14000003; // B #12
    buf[idx++] = addr & 0xFFFFFFFF;
    buf[idx++] = addr >> 32u;
    if (type == INST_BL) {
        buf[idx++] = 0x1000001E; // ADR X30, .
        buf[idx++] = 0x910033DE; // ADD X30, X30, #12
        buf[idx++] = 0xD65F0220; // RET X17
    } else {
        buf[idx++] = 0xD65F0220; // RET X17
    }
    buf[idx++] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_adr(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t xd = bits32(inst, 4, 0);
    uint64_t immlo = bits32(inst, 30, 29);
    uint64_t immhi = bits32(inst, 23, 5);
    uint64_t addr;

    if (type == INST_ADR) {
        addr = inst_addr + sign64_extend((immhi << 2u) | immlo, 21u);
    } else {
        addr = (inst_addr + sign64_extend((immhi << 14u) | (immlo << 12u), 33u)) & 0xFFFFFFFFFFFFF000;
        if (is_in_tramp(hook, addr)) return -HOOK_BAD_RELO;
    }
    buf[0] = 0x58000040u | xd; // LDR Xd, #8
    buf[1] = 0x14000003; // B #12
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_ldr(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint32_t rt = bits32(inst, 4, 0);
    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uint64_t addr = inst_addr + offset;

    if (is_in_tramp(hook, addr) && type != INST_PRFM_LIT) return -HOOK_BAD_RELO;

    addr = relo_in_tramp(hook, addr);

    if (type == INST_LDR_32 || type == INST_LDR_64 || type == INST_LDRSW_LIT) {
        buf[0] = 0x58000060u | rt; // LDR Xt, #12
        if (type == INST_LDR_32) {
            buf[1] = 0xB9400000 | rt | (rt << 5u); // LDR Wt, [Xt]
        } else if (type == INST_LDR_64) {
            buf[1] = 0xF9400000 | rt | (rt << 5u); // LDR Xt, [Xt]
        } else {
            // LDRSW_LIT
            buf[1] = 0xB9800000 | rt | (rt << 5u); // LDRSW Xt, [Xt]
        }
        buf[2] = 0x14000004; // B #16
        buf[3] = ARM64_NOP;
        buf[4] = addr & 0xFFFFFFFF;
        buf[5] = addr >> 32u;
    } else {
        buf[0] = 0xA93F47F0; // STP X16, X17, [SP, -0x10]
        buf[1] = 0x58000091; // LDR X17, #16
        if (type == INST_PRFM_LIT) {
            buf[2] = 0xF9800220 | rt; // PRFM Rt, [X17]
        } else if (type == INST_LDR_SIMD_32) {
            buf[2] = 0xBD400220 | rt; // LDR St, [X17]
        } else if (type == INST_LDR_SIMD_64) {
            buf[2] = 0xFD400220 | rt; // LDR Dt, [X17]
        } else {
            // LDR_SIMD_128
            buf[2] = 0x3DC00220u | rt; // LDR Qt, [X17]
        }
        buf[3] = 0xF85F83F1; // LDR X17, [SP, -0x8]
        buf[4] = 0x14000004; // B #16
        buf[5] = ARM64_NOP;
        buf[6] = addr & 0xFFFFFFFF;
        buf[7] = addr >> 32u;
    }
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_cb(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint64_t imm19 = bits32(inst, 23, 5);
    uint64_t offset = sign64_extend((imm19 << 2u), 21u);
    uint64_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFF00001F) | 0x40u; // CB(N)Z Rt, #8
    buf[1] = 0x14000005; // B #20
    buf[2] = 0x58000051; // LDR X17, #8
    buf[3] = 0xD65F0220; // RET X17
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_tb(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;

    uint64_t imm14 = bits32(inst, 18, 5);
    uint64_t offset = sign64_extend((imm14 << 2u), 16u);
    uint64_t addr = inst_addr + offset;
    addr = relo_in_tramp(hook, addr);

    buf[0] = (inst & 0xFFF8001F) | 0x40u; // TB(N)Z Rt, #<imm>, #8
    buf[1] = 0x14000005; // B #20
    buf[2] = 0x58000051; // LDR X17, #8
    buf[3] = 0xd61f0220; // RET X17
    buf[4] = addr & 0xFFFFFFFF;
    buf[5] = addr >> 32u;
    return HOOK_NO_ERR;
}

static __noinline hook_err_t relo_ignore(hook_t *hook, uint64_t inst_addr, uint32_t inst, inst_type_t type)
{
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    buf[0] = inst;
    buf[1] = ARM64_NOP;
    return HOOK_NO_ERR;
}

static uint32_t can_b_rel(uint64_t src_addr, uint64_t dst_addr)
{
#define B_REL_RANGE ((1 << 25) << 2)
    return ((dst_addr >= src_addr) & (dst_addr - src_addr <= B_REL_RANGE)) ||
           ((src_addr >= dst_addr) & (src_addr - dst_addr <= B_REL_RANGE));
}

int32_t branch_relative(uint32_t *buf, uint64_t src_addr, uint64_t dst_addr)
{
    if (can_b_rel(src_addr, dst_addr)) {
        buf[0] = 0x14000000u | (((dst_addr - src_addr) & 0x0FFFFFFFu) >> 2u); // B <label>
        buf[1] = ARM64_NOP;
        return 2;
    }
    return 0;
}
EXPORT_SYMBOL(branch_relative);

int32_t branch_absolute(uint32_t *buf, uint64_t addr)
{
    buf[0] = 0x58000051; // LDR X17, #8
    buf[1] = 0xd61f0220; // BR X17
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 4;
}
EXPORT_SYMBOL(branch_absolute);

int32_t ret_absolute(uint32_t *buf, uint64_t addr)
{
    buf[0] = 0x58000051; // LDR X17, #8
    buf[1] = 0xD65F0220; // RET X17
    buf[2] = addr & 0xFFFFFFFF;
    buf[3] = addr >> 32u;
    return 4;
}
EXPORT_SYMBOL(ret_absolute);

int32_t branch_from_to(uint32_t *tramp_buf, uint64_t src_addr, uint64_t dst_addr)
{
    int32_t len = branch_relative(tramp_buf, src_addr, dst_addr);
    if (len) return len;
    return ret_absolute(tramp_buf, dst_addr);
}

// transit0
typedef uint64_t (*transit0_func_t)();

#define current_inline_hook_chain() ({ \
    uint64_t chain_va; \
    asm volatile("mov %0, x16" : "=r"(chain_va)); \
    (hook_chain_t *)chain_va; \
})

uint64_t __attribute__((__noinline__)) _transit0(void)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    int32_t i;
    if (!hook_chain) return 0;
    hook_fargs0_t fargs;
    fargs.skip_origin = 0;
    fargs.chain = hook_chain;
    for (i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain0_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit0_func_t origin_func = (transit0_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func();
    }
    for (i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain0_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    return fargs.ret;
}
#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit0_end();
#endif

// transit4
typedef uint64_t (*transit4_func_t)(uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((__noinline__))
_transit4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    int32_t i;
    if (!hook_chain) return 0;
    hook_fargs4_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.chain = hook_chain;
    for (i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain4_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit4_func_t origin_func = (transit4_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
    }
    for (i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain4_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    return fargs.ret;
}

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit4_end();
#endif

// transit8:
typedef uint64_t (*transit8_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((__noinline__))
_transit8(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
          uint64_t arg7)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    int32_t i;
    if (!hook_chain) return 0;
    hook_fargs8_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.chain = hook_chain;
    for (i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain8_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit8_func_t origin_func = (transit8_func_t)hook_chain->hook.relo_addr;
        fargs.ret =
            origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7);
    }
    for (i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain8_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    return fargs.ret;
}

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit8_end();
#endif

// transit12:
typedef uint64_t (*transit12_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((__noinline__))
_transit12(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
           uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11)
{
    hook_chain_t *hook_chain = current_inline_hook_chain();
    int32_t i;
    if (!hook_chain) return 0;
    hook_fargs12_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.arg8 = arg8;
    fargs.arg9 = arg9;
    fargs.arg10 = arg10;
    fargs.arg11 = arg11;
    fargs.chain = hook_chain;
    for (i = 0; i < hook_chain->chain_items_max; i++) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain12_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit12_func_t origin_func = (transit12_func_t)hook_chain->hook.relo_addr;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6,
                                fargs.arg7, fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
    }
    for (i = hook_chain->chain_items_max - 1; i >= 0; i--) {
        if (hook_chain->states[i] != CHAIN_ITEM_STATE_READY) continue;
        hook_chain12_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    return fargs.ret;
}

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
extern void _transit12_end();
#endif

static __noinline hook_err_t relocate_inst(hook_t *hook, uint64_t inst_addr, uint32_t inst)
{
    hook_err_t rc = HOOK_NO_ERR;
    inst_type_t it = INST_IGNORE;
    int len = 1;

    for (int j = 0; j < sizeof(relo_len) / sizeof(relo_len[0]); j++) {
        if ((inst & masks[j]) == types[j]) {
            it = types[j];
            len = relo_len[j];
            break;
        }
    }

    switch (it) {
    case INST_B:
    case INST_BC:
    case INST_BL:
        rc = relo_b(hook, inst_addr, inst, it);
        break;
    case INST_ADR:
    case INST_ADRP:
        rc = relo_adr(hook, inst_addr, inst, it);
        break;
    case INST_LDR_32:
    case INST_LDR_64:
    case INST_LDRSW_LIT:
    case INST_PRFM_LIT:
    case INST_LDR_SIMD_32:
    case INST_LDR_SIMD_64:
    case INST_LDR_SIMD_128:
        rc = relo_ldr(hook, inst_addr, inst, it);
        break;
    case INST_CBZ:
    case INST_CBNZ:
        rc = relo_cb(hook, inst_addr, inst, it);
        break;
    case INST_TBZ:
    case INST_TBNZ:
        rc = relo_tb(hook, inst_addr, inst, it);
        break;
    case INST_IGNORE:
    default:
        rc = relo_ignore(hook, inst_addr, inst, it);
        break;
    }

    hook->relo_insts_num += len;

    return rc;
}

hook_err_t hook_prepare(hook_t *hook)
{
    int i;
    if (is_bad_address((void *)hook->func_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->origin_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->replace_addr)) return -HOOK_BAD_ADDRESS;
    if (is_bad_address((void *)hook->relo_addr)) return -HOOK_BAD_ADDRESS;

    // backup origin instruction
    for (i = 0; i < TRAMPOLINE_MAX_NUM; i++) {
        hook->origin_insts[i] = *((uint32_t *)hook->origin_addr + i);
    }
    // trampline to replace_addr
    if (hook->origin_insts[0] == ARM64_PACIASP || hook->origin_insts[0] == ARM64_PACIBSP) {
        hook->tramp_insts_num = branch_absolute(&hook->tramp_insts[1], hook->replace_addr);
        hook->tramp_insts[0] = ARM64_BTI_JC;
        hook->tramp_insts_num++;
    } else {
        hook->tramp_insts_num = branch_absolute(hook->tramp_insts, hook->replace_addr);
    }

    // relocate
    for (i = 0; i < sizeof(hook->relo_insts) / sizeof(hook->relo_insts[0]); i++) {
        hook->relo_insts[i] = ARM64_NOP;
    }

    for (i = 0; i < hook->tramp_insts_num; i++) {
        uint64_t inst_addr = hook->origin_addr + i * 4;
        uint32_t inst = hook->origin_insts[i];
        hook_err_t relo_res = relocate_inst(hook, inst_addr, inst);
        if (relo_res) {
            return -HOOK_BAD_RELO;
        }
    }

    // jump back
    uint64_t back_src_addr = hook->relo_addr + hook->relo_insts_num * 4;
    uint64_t back_dst_addr = hook->origin_addr + hook->tramp_insts_num * 4;
    uint32_t *buf = hook->relo_insts + hook->relo_insts_num;
    hook->relo_insts_num += branch_from_to(buf, back_src_addr, back_dst_addr);
    return HOOK_NO_ERR;
}
EXPORT_SYMBOL(hook_prepare);

void hook_install(hook_t *hook)
{
    void *addrs[TRAMPOLINE_MAX_NUM];
    for (int32_t i = 0; i < hook->tramp_insts_num; ++i) {
        addrs[i] = (uint32_t *)hook->origin_addr + i;
    }
    hotpatch(addrs, hook->tramp_insts, hook->tramp_insts_num);
}
EXPORT_SYMBOL(hook_install);

void hook_uninstall(hook_t *hook)
{
    void *addrs[TRAMPOLINE_MAX_NUM];
    for (int32_t i = 0; i < hook->tramp_insts_num; ++i) {
        addrs[i] = (uint32_t *)hook->origin_addr + i;
    }
    hotpatch(addrs, hook->origin_insts, hook->tramp_insts_num);
}
EXPORT_SYMBOL(hook_uninstall);

hook_err_t hook(void *func, void *replace, void **backup)
{
    hook_err_t err = HOOK_NO_ERR;
    if (!func || !replace || !backup) {
        return -HOOK_BAD_ADDRESS;
    }
    uint64_t origin_addr = branch_func_addr((uintptr_t)func);
    hook_t *hook = (hook_t *)hook_mem_zalloc(origin_addr, INLINE);
    if (!hook) return -HOOK_NO_MEM;
    hook->func_addr = (uint64_t)func;
    hook->origin_addr = origin_addr;
    hook->replace_addr = (uint64_t)replace;
    hook->relo_addr = (uint64_t)hook->relo_insts;
    *backup = (void *)hook->relo_addr;
    pr_debug("Hook func: %llx, origin: %llx, replace: %llx, relocate: %llx, chain: %llx\n", hook->func_addr,
          hook->origin_addr, hook->replace_addr, hook->relo_addr, (uint64_t)hook);
    err = hook_prepare(hook);
    if (err) goto out;
    hook_install(hook);
    pr_debug("Hook func: %llx succsseed\n", hook->func_addr);
    return HOOK_NO_ERR;
out:
    hook_mem_free(hook);
    pr_debug("Hook func: %llx failed, err: %d\n", hook->func_addr, err);
    return err;
}
EXPORT_SYMBOL(hook);

void unhook(void *func)
{
    uint64_t origin = branch_func_addr((uint64_t)func);
    hook_t *hook = hook_get_mem_from_origin(origin);
    if (!hook) return;
    hook_uninstall(hook);
    hook_mem_free(hook);
    pr_debug("Unhook func: %llx\n", (uint64_t)func);
}
EXPORT_SYMBOL(unhook);

#ifndef KP_HOOK_EXTERNAL_CHAIN_PREPARE
static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno)
{
    uint64_t transit_start, transit_end;
    switch (argno) {
    case 0:
        transit_start = (uint64_t)_transit0;
        transit_end = (uint64_t)_transit0_end;
        break;
    case 1:
    case 2:
    case 3:
    case 4:
        transit_start = (uint64_t)_transit4;
        transit_end = (uint64_t)_transit4_end;
        break;
    case 5:
    case 6:
    case 7:
    case 8:
        transit_start = (uint64_t)_transit8;
        transit_end = (uint64_t)_transit8_end;
        break;
    default:
        transit_start = (uint64_t)_transit12;
        transit_end = (uint64_t)_transit12_end;
        break;
    }

    int32_t transit_num = (transit_end - transit_start) / 4;
    // todo:assert
    if (transit_num + 6 > TRANSIT_INST_NUM) return -HOOK_TRANSIT_NO_MEM;

    transit[0] = ARM64_BTI_JC;
    transit[1] = 0x58000070; // LDR X16, #12
    transit[2] = 0x14000004; // B #16
    transit[3] = ARM64_NOP;
    hook_chain_t *chain = local_container_of(transit, hook_chain_t, transit);
    transit[4] = ((uint64_t)chain) & 0xFFFFFFFF;
    transit[5] = ((uint64_t)chain) >> 32u;
    for (int i = 0; i < transit_num; i++) {
        transit[i + 6] = ((uint32_t *)transit_start)[i];
    }
    return HOOK_NO_ERR;
}
#endif
/* When KP_HOOK_EXTERNAL_CHAIN_PREPARE is defined (see top of file)
 * the static `hook_chain_prepare` body above is excluded, and the
 * extern declaration near the top of the file binds to the real
 * (non-static) implementation provided by kp_hook_engine.c. The
 * upstream KP LKM sidesteps the extern by #include-ing hook.c
 * directly into hook_engine.c; SukiSU keeps them as separate
 * translation units and uses extern instead. */

hook_err_t hook_chain_add(hook_chain_t *chain, void *before, void *after, void *udata)
{
    for (int i = 0; i < HOOK_CHAIN_NUM; i++) {
        if ((before && chain->befores[i] == before) || (after && chain->afters[i] == after)) return -HOOK_DUPLICATED;

        // todo: atomic or lock
        if (chain->states[i] == CHAIN_ITEM_STATE_EMPTY) {
            chain->states[i] = CHAIN_ITEM_STATE_BUSY;
            dsb(ish);
            chain->udata[i] = udata;
            chain->befores[i] = before;
            chain->afters[i] = after;
            if (i + 1 > chain->chain_items_max) {
                chain->chain_items_max = i + 1;
            }
            dsb(ish);
            chain->states[i] = CHAIN_ITEM_STATE_READY;
            pr_debug("Wrap chain add: %llx, %llx, %llx successed\n", chain->hook.func_addr, (uint64_t)before, (uint64_t)after);
            return HOOK_NO_ERR;
        }
    }
    pr_debug("Wrap chain add: %llx, %llx, %llx failed\n", chain->hook.func_addr, (uint64_t)before, (uint64_t)after);
    return -HOOK_CHAIN_FULL;
}
EXPORT_SYMBOL(hook_chain_add);

void hook_chain_remove(hook_chain_t *chain, void *before, void *after)
{
    for (int i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (chain->states[i] == CHAIN_ITEM_STATE_READY)
            if ((before && chain->befores[i] == before) || (after && chain->afters[i] == after)) {
                chain->states[i] = CHAIN_ITEM_STATE_BUSY;
                dsb(ish);
                chain->udata[i] = 0;
                chain->befores[i] = 0;
                chain->afters[i] = 0;
                dsb(ish);
                chain->states[i] = CHAIN_ITEM_STATE_EMPTY;
                break;
            }
    }
    pr_debug("Wrap chain remove: %llx, %llx, %llx\n", chain->hook.func_addr, (uint64_t)before, (uint64_t)after);
}
EXPORT_SYMBOL(hook_chain_remove);

// todo: lock
hook_err_t hook_wrap(void *func, int32_t argno, void *before, void *after, void *udata)
{
    if (is_bad_address(func)) return -HOOK_BAD_ADDRESS;
    uint64_t faddr = (uint64_t)func;
    uint64_t origin = branch_func_addr(faddr);
    if (is_bad_address(func)) return -HOOK_BAD_ADDRESS;
    hook_chain_t *chain = (hook_chain_t *)hook_get_mem_from_origin(origin);
    if (chain) return hook_chain_add(chain, before, after, udata);
    chain = (hook_chain_t *)hook_mem_zalloc(origin, INLINE_CHAIN);
    if (!chain) return -HOOK_NO_MEM;
    chain->chain_items_max = 0;
    hook_t *hook = &chain->hook;
    hook->func_addr = faddr;
    hook->origin_addr = origin;
    hook->replace_addr = (uint64_t)chain->transit;
    hook->relo_addr = (uint64_t)hook->relo_insts;
    pr_debug("Wrap func: %llx, origin: %llx, replace: %llx, relocate: %llx, chain: %llx\n", hook->func_addr,
          hook->origin_addr, hook->replace_addr, hook->relo_addr, (uint64_t)chain);
    hook_err_t err = hook_prepare(hook);
    if (err) goto err;
    err = hook_chain_prepare(chain->transit, argno);
    if (err) goto err;
    err = hook_chain_add(chain, before, after, udata);
    if (err) goto err;
    hook_chain_install(chain);
    pr_debug("Wrap func: %llx succsseed\n", hook->func_addr);
    return HOOK_NO_ERR;
err:
    hook_mem_free(chain);
    pr_debug("Wrap func: %llx failed, err: %d\n", hook->func_addr, err);
    return err;
}
EXPORT_SYMBOL(hook_wrap);

void hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
    if (is_bad_address(func)) return;
    uint64_t faddr = (uint64_t)func;
    uint64_t origin = branch_func_addr(faddr);
    if (is_bad_address(func)) return;
    hook_chain_t *chain = (hook_chain_t *)hook_get_mem_from_origin(origin);
    if (!chain) return;
    hook_chain_remove(chain, before, after);
    if (!remove) return;
    // todo:
    for (int i = 0; i < HOOK_CHAIN_NUM; i++) {
        if (chain->states[i] != CHAIN_ITEM_STATE_EMPTY) return;
    }
    hook_chain_uninstall(chain);
    // todo: unsafe
    hook_mem_free(chain);
    pr_debug("Unwrap func: %llx\n", (uint64_t)func);
}
EXPORT_SYMBOL(hook_unwrap_remove);
