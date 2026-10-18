/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION_CPU_SPOOF
#define __KSU_H_EXTENSION_CPU_SPOOF

#include <linux/types.h>

#include "uapi/supercall.h"

int ksu_extension_cpu_spoof_io(u32 id, void __user *raw);

#endif /* __KSU_H_EXTENSION_CPU_SPOOF */
