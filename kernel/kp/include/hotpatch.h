/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_HOTPATCH_H_
#define _KP_HOTPATCH_H_
/* KP's standalone hotpatch.c is freestanding (uses its own pgtable_entry /
 * aarch64_insn_patch_text trampoline). Inside the Linux kernel module we
 * delegate to kp_patch_text() (already provided by patch_memory.c). */
#include <linux/types.h>
int hotpatch(void *addrs[], u32 values[], int cnt);
int hotpatch_nosync(void *addr, u32 value);
#endif