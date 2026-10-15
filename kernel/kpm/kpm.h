#ifndef __SUKISU_KPM_H
#define __SUKISU_KPM_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include "uapi/supercall.h"

int do_kpm(void __user *arg);

/* KPM control codes are carried in struct ksu_kpm_cmd.control_code. */
#define CMD_KPM_CONTROL 1
#define CMD_KPM_CONTROL_MAX 10

#endif
