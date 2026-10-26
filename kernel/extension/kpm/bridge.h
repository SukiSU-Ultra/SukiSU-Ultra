/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SUKISU_KPM_BRIDGE_H_
#define _SUKISU_KPM_BRIDGE_H_

/* Kernel-only ABI v2, mirrored in KernelPatch patch/sukisu/supercall.h.
 * op 1..7 are the existing SUKISU_KPM_* extension operations. Op 8 is an
 * optional event-aware file load for boot-stage modules.
 * LOAD(path,args,user_reserved), UNLOAD(name,user_reserved), NUM(),
 * LIST(kernel_buf,size), INFO(name,kernel_buf,size),
 * CONTROL(name,args,user_output,size), VERSION(kernel_buf,size).
 */
/* Public framing tags: ALL must match. These are not authentication. */
#define SUKISU_KPM_SUPERCALL_MAGIC 0x53554b504d000002UL
#define SUKISU_KPM_SUPERCALL_MAGIC2 0x4b504d4252494447UL
#define SUKISU_KPM_SUPERCALL_MAGIC3 0x53554b494e544552UL
/* x6=magic2, x7=magic3, x8=ABI version; x9..x30 reserved (zero).
 * Internal synthetic pt_regs only; the userspace extension ABI is unchanged.
 * Event-aware loading is optional so newer ksud can fall back to LOAD on
 * older KernelPatch builds that return -EOPNOTSUPP for op 8.
 */
#define SUKISU_KPM_ABI_VERSION 2
#define SUKISU_KPM_PROBE 0
#define SUKISU_KPM_OUTPUT_MAX 4096

long sukisu_kpm_bridge(unsigned long op, unsigned long a1, unsigned long a2,
                       unsigned long a3, unsigned long a4);
#endif
