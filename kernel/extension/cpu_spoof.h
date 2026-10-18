/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION_CPU_SPOOF
#define __KSU_H_EXTENSION_CPU_SPOOF

#include <linux/types.h>

#include "extension.h"
#include "uapi/supercall.h"

/*
 * CPU spoof extension.
 *
 * Sticky state (u64, low bit): whether spoofing is "armed". Toggling this
 * bit just flips a soft switch — actual per-CPU MIDR writes only happen
 * on demand via the io op (which carries the full struct
 * ksu_set_spoof_cpu_cmd).
 *
 * The original KSU_IOCTL_SET_SPOOF_CPU shaped command is forwarded
 * verbatim, so manager UI keeping its existing payload keeps working.
 */
int ksu_extension_cpu_spoof_get(u32 id, u64 *value);
int ksu_extension_cpu_spoof_set(u32 id, u64 value);
int ksu_extension_cpu_spoof_io(u32 id, void __user *raw);

extern const struct ksu_extension_handler_ops ksu_extension_cpu_spoof_ops;

#endif /* __KSU_H_EXTENSION_CPU_SPOOF */
