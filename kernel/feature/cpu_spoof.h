/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_CPU_SPOOF
#define __KSU_H_CPU_SPOOF

#include "uapi/supercall.h"

int ksu_set_spoof_cpu(const struct ksu_set_spoof_cpu_cmd *cmd);

#endif /* __KSU_H_CPU_SPOOF */
