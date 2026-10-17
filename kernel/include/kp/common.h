/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_COMMON_H_
#define _KP_COMMON_H_
#include <linux/types.h>
#define VERSION(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))
/* kver / kpver / kernel patch start/end symbols are freestanding-only. */
static inline int is_kp_text_area(unsigned long addr) { (void)addr; return 0; }
static inline int is_kp_hook_area(unsigned long addr) { (void)addr; return 0; }
static inline int is_kpm_rox_area(unsigned long addr) { (void)addr; return 0; }
#endif