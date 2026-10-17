/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_SYMBOL_H_
#define _KP_SYMBOL_H_
/* Kernel-module build: KP_EXPORT_SYMBOL expands to EXPORT_SYMBOL. The custom
 * kp_symbol_t / _kp_symbol_start / _kp_symbol_end block in patch-mode is unused
 * here (the running kernel exports its own kallsyms). */
#include <linux/module.h>
#define KP_SYMBOL_LEN 64

#define KP_EXPORT_SYMBOL(sym) EXPORT_SYMBOL(sym)

static inline unsigned long link2runtime(unsigned long addr) { return addr; }
static inline int kp_symbol_count(void) { return 0; }
static inline int kp_symbol_list(char *out, int size) { (void)out; (void)size; return 0; }
static inline const char *kp_feature_list(void) { return ""; }
#endif