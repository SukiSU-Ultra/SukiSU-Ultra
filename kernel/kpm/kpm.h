#ifndef __SUKISU_KPM_H
#define __SUKISU_KPM_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include "uapi/supercall.h"

/*
 * SukiSU-Ultra KPM (KernelPatch Module) IOCTL layer.
 *
 * Implements the seven SUKISU_KPM_* control codes (defined in
 * uapi/supercall.h) and routes them to the KP-style module loader in
 * module.c. The 7 codes map onto KernelPatch's SUPERCALL_KPM_* as:
 *
 *   SUKISU_KPM_LOAD     = SUPERCALL_KPM_LOAD
 *   SUKISU_KPM_UNLOAD   = SUPERCALL_KPM_UNLOAD
 *   SUKISU_KPM_NUM      = SUPERCALL_KPM_NUMS
 *   SUKISU_KPM_LIST     = SUPERCALL_KPM_LIST
 *   SUKISU_KPM_INFO     = SUPERCALL_KPM_INFO
 *   SUKISU_KPM_CONTROL  = SUPERCALL_KPM_CONTROL
 *   SUKISU_KPM_VERSION  = KPM loader version
 */

int sukisu_handle_kpm(unsigned long control_code, unsigned long arg1,
                      unsigned long arg2, unsigned long result_code);
int sukisu_is_kpm_control_code(unsigned long control_code);
int do_kpm(void __user *arg);

/* KPM Control Code range (matches SUKISU_KPM_* in uapi/supercall.h) */
#define CMD_KPM_CONTROL 1
#define CMD_KPM_CONTROL_MAX 10

#endif
