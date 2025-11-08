#ifndef __SUKISU_KPM_H
#define __SUKISU_KPM_H

#include <linux/types.h>
#include <linux/ioctl.h>

struct ksu_kpm_cmd {
    __aligned_u64 __user control_code;
    __aligned_u64 __user arg1;
    __aligned_u64 __user arg2;
    __aligned_u64 __user result_code;
};

int sukisu_handle_kpm(unsigned long control_code, unsigned long arg1, unsigned long arg2, unsigned long result_code);
int sukisu_is_kpm_control_code(unsigned long control_code);
int do_kpm(void __user *arg);

#define KSU_IOCTL_KPM _IOC(_IOC_READ|_IOC_WRITE, 'K', 200, 0)

/* KPM Control Code */
#define CMD_KPM_CONTROL 1
#define CMD_KPM_CONTROL_MAX 10

/* Control Code */
/*
 * prctl(xxx, 1, "PATH", "ARGS")
 * success return 0, error return -N
 */
#define SUKISU_KPM_LOAD 1

/*
 * prctl(xxx, 2, "NAME")
 * success return 0, error return -N
 */
#define SUKISU_KPM_UNLOAD 2

/*
 * num = prctl(xxx, 3)
 * error return -N
 * success return +num or 0
 */
#define SUKISU_KPM_NUM 3

/*
 * prctl(xxx, 4, Buffer, BufferSize)
 * success return +out, error return -N
 */
#define SUKISU_KPM_LIST 4

/*
 * prctl(xxx, 5, "NAME", Buffer[256])
 * success return +out, error return -N
 */
#define SUKISU_KPM_INFO 5

/*
 * prctl(xxx, 6, "NAME", "ARGS")
 * success return KPM's result value
 * error return -N
 */
#define SUKISU_KPM_CONTROL 6

/*
 * prctl(xxx, 7, buffer, bufferSize)
 * success return KPM's result value
 * error return -N
 */
#define SUKISU_KPM_VERSION 7

#endif
