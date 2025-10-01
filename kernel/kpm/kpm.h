#ifndef ___SUKISU_KPM_H
#define ___SUKISU_KPM_H

int sukisu_handle_kpm(unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
int sukisu_is_kpm_control_code(unsigned long arg2);

// KPM控制代码
#define CMD_KPM_CONTROL 28
#define CMD_KPM_CONTROL_MAX 35

// 控制代码

// prctl(xxx, 28, "PATH", "ARGS")
// success return 0, error return -N
#define SUKISU_KPM_LOAD 28

// prctl(xxx, 29, "NAME")
// success return 0, error return -N
#define SUKISU_KPM_UNLOAD 29

// num = prctl(xxx, 30)
// error return -N
// success return +num or 0
#define SUKISU_KPM_NUM 30

// prctl(xxx, 31, Buffer, BufferSize)
// success return +out, error return -N
#define SUKISU_KPM_LIST 31

// prctl(xxx, 32, "NAME", Buffer[256])
// success return +out, error return -N
#define SUKISU_KPM_INFO 32

// prctl(xxx, 33, "NAME", "ARGS")
// success return KPM's result value
// error return -N
#define SUKISU_KPM_CONTROL 33

// prctl(xxx, 34, buffer, bufferSize)
// success return KPM's result value
// error return -N
#define SUKISU_KPM_VERSION 34

#endif