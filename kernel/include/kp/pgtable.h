/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_PGTABLE_H_
#define _KP_PGTABLE_H_
/* The KP pgtable.h expects a freestanding patch environment with custom
 * pgd_va / page_shift / etc. globals. Inside the kernel we just use the real
 * <asm/pgtable.h> / <linux/pgtable.h>. The hotpatch-ns.c PTE bits are not
 * needed for the LKM port (hotpatch goes through kp_patch_text()). */
#include <asm/pgtable.h>
#include <linux/pgtable.h>
#endif