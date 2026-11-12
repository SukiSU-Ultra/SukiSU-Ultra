// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __KSU_H_SYSCALL_TABLE_COMMON
#define __KSU_H_SYSCALL_TABLE_COMMON

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && defined(CONFIG_ARM)
// arch/arm/include/asm/syscall.h
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
extern const unsigned long sys_call_table[];
#else
extern void *sys_call_table[];
#endif
#endif // < 4.19, ARM

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && defined(CONFIG_COMPAT)
extern const void *compat_sys_call_table[];
#endif

static void *native_sct __read_mostly = (void *)sys_call_table;
#if defined(CONFIG_COMPAT)
static void *compat_sct __read_mostly = (void *)compat_sys_call_table;
#endif

#endif // __KSU_H_SYSCALL_TABLE_COMMON
