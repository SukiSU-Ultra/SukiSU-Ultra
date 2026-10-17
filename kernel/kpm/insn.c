// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * ARM64 instruction patching helpers used by the inline hook engine. Only
 * a small subset is needed for the LKM build: the hook engine rewrites the
 * destination prologue and emits a BTI trampoline. We pull this out so the
 * hook engine does not depend on a specific GKI build of
 * aarch64_insn_write.
 */
#include <linux/types.h>

#include <ktypes.h>

static inline uint32_t insn_nop(void) { return 0xd503201fu; }
static inline uint32_t insn_ret(void) { return 0xd65f03c0u; }
static inline uint32_t insn_b(uint64_t dst, uint64_t pc)
{
    int64_t off = (dst - pc) >> 2;
    if (off < -(1 << 25) || off >= (1 << 25))
        return 0;
    return 0x14000000u | (off & 0x03FFFFFFu);
}

void kp_insn_reset_slot(void *slot)
{
    uint32_t *s = (uint32_t *)slot;
    s[0] = insn_nop();
    s[1] = insn_nop();
    s[2] = insn_nop();
    s[3] = insn_nop();
}

void kp_insn_make_branch(void *slot, void *target, size_t prologue_size)
{
    uint32_t *s = (uint32_t *)slot;
    uint64_t pc = (uint64_t)slot + 8ull * prologue_size;
    for (size_t i = 0; i < prologue_size; i++)
        s[i] = insn_b((uint64_t)target, pc);
}

void kp_insn_write_b(void *slot, void *target)
{
    uint32_t *s = (uint32_t *)slot;
    s[0] = insn_b((uint64_t)target, (uint64_t)slot);
}