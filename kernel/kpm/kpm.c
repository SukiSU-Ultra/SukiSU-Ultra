/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2025 Liankong (xhsw.new@outlook.com). All Rights Reserved.
 * 本代码由GPL-2授权
 * 
 * 适配KernelSU的KPM 内核模块加载器兼容实现
 * 
 * 集成了 ELF 解析、内存布局、符号处理、重定位（支持 ARM64 重定位类型）
 * 并参照KernelPatch的标准KPM格式实现加载和控制
 */
#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kernfs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <asm/elf.h>    /* 包含 ARM64 重定位类型定义 */
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <linux/version.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <asm/insn.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#include <linux/kallsyms.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0) && defined(CONFIG_MODULES)
#include <linux/moduleloader.h> // 需要启用 CONFIG_MODULES
#endif
#include "kpm.h"
#include "compact.h"

#ifndef NO_OPTIMIZE
#if defined(__GNUC__) && !defined(__clang__)
    #define NO_OPTIMIZE __attribute__((optimize("O0")))
#elif defined(__clang__)
    #define NO_OPTIMIZE __attribute__((optnone))
#else
    #define NO_OPTIMIZE
#endif
#endif

// ============================================================================================

noinline
NO_OPTIMIZE
void sukisu_kpm_load_module_path(const char* path, const char* args, void* ptr, void __user* result) {
    // This is a KPM module stub.
    int res = -1;
    printk("KPM: Stub function called (sukisu_kpm_load_module_path). path=%s args=%s ptr=%p\n", path, args, ptr);
    __asm__ volatile("nop");  // 精确控制循环不被优化
    if(copy_to_user(result, &res, sizeof(res)) < 1) printk("KPM: Copy to user faild.");
}

noinline
NO_OPTIMIZE
void sukisu_kpm_unload_module(const char* name, void* ptr, void __user* result) {
    // This is a KPM module stub.
    int res = -1;
    printk("KPM: Stub function called (sukisu_kpm_unload_module). name=%s ptr=%p\n", name, ptr);
    __asm__ volatile("nop");  // 精确控制循环不被优化
    if(copy_to_user(result, &res, sizeof(res)) < 1) printk("KPM: Copy to user faild.");
}

noinline
NO_OPTIMIZE
void sukisu_kpm_num(void __user* result) {
    // This is a KPM module stub.
    int res = 0;
    printk("KPM: Stub function called (sukisu_kpm_num).\n");
    __asm__ volatile("nop");  // 精确控制循环不被优化
    if(copy_to_user(result, &res, sizeof(res)) < 1) printk("KPM: Copy to user faild.");
}

noinline
NO_OPTIMIZE
void sukisu_kpm_info(const char* name, void __user* out, void __user* result) {
    // This is a KPM module stub.
    int res = -1;
    printk("KPM: Stub function called (sukisu_kpm_info). name=%s buffer=%p\n", name, out);
    __asm__ volatile("nop");  // 精确控制循环不被优化
    if(copy_to_user(result, &res, sizeof(res)) < 1) printk("KPM: Copy to user faild.");
}

noinline
NO_OPTIMIZE
void sukisu_kpm_list(void __user* out, unsigned int bufferSize, void __user* result) {
    // This is a KPM module stub.
    int res = -1;
    printk("KPM: Stub function called (sukisu_kpm_list). buffer=%p size=%d\n", out, bufferSize);
    if(copy_to_user(result, &res, sizeof(res)) < 1) printk("KPM: Copy to user faild.");
}

noinline
NO_OPTIMIZE
void sukisu_kpm_control(void __user* name, void __user* args, void __user* result) {
    // This is a KPM module stub.
    int res = -1;
    printk("KPM: Stub function called (sukisu_kpm_control). name=%p args=%p\n", name, args);
    __asm__ volatile("nop");  // 精确控制循环不被优化
    if(copy_to_user(result, &res, sizeof(res)) < 1) printk("KPM: Copy to user faild.");
}

noinline
NO_OPTIMIZE
void sukisu_kpm_version(void __user* out, unsigned int bufferSize, void __user* result) {
    int res = -1;
    printk("KPM: Stub function called (sukisu_kpm_version). buffer=%p size=%d\n", out, bufferSize);
    if(copy_to_user(result, &res, sizeof(res)) < 1) printk("KPM: Copy to user faild.");
}

EXPORT_SYMBOL(sukisu_kpm_load_module_path);
EXPORT_SYMBOL(sukisu_kpm_unload_module);
EXPORT_SYMBOL(sukisu_kpm_num);
EXPORT_SYMBOL(sukisu_kpm_info);
EXPORT_SYMBOL(sukisu_kpm_list);
EXPORT_SYMBOL(sukisu_kpm_version);
EXPORT_SYMBOL(sukisu_kpm_control);

noinline
int sukisu_handle_kpm(unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    if(arg2 == SUKISU_KPM_LOAD) {
        char kernel_load_path[256] = { 0 };
        char kernel_args_buffer[256] = { 0 };

        if(arg3 == 0) {
            return -1;
        }
        
        strncpy_from_user((char*)&kernel_load_path, (const char __user *)arg3, 255);
        if(arg4 != 0) {
            strncpy_from_user((char*)&kernel_args_buffer, (const char __user *)arg4, 255);
        }
        sukisu_kpm_load_module_path((const char*)&kernel_load_path, (const char*) &kernel_args_buffer, NULL, (void __user*) arg5);
    } else if(arg2 == SUKISU_KPM_UNLOAD) {
        char kernel_name_buffer[256] = { 0 };

        if(arg3 == 0) {
            return -1;
        }
        
        strncpy_from_user((char*)&kernel_name_buffer, (const char __user *)arg3, 255);
        sukisu_kpm_unload_module((const char*) &kernel_name_buffer, NULL, (void __user*) arg5);
    } else if(arg2 == SUKISU_KPM_NUM) {
        sukisu_kpm_num((void __user*) arg5);
    } else if(arg2 == SUKISU_KPM_INFO) {
        char kernel_name_buffer[256] = { 0 };

        if(arg3 == 0 || arg4 == 0) {
            return -1;
        }
        
        strncpy_from_user((char*)&kernel_name_buffer, (const char __user *)arg3, 255);
        sukisu_kpm_info((const char*) &kernel_name_buffer, (char __user*) arg4, (void __user*) arg5);
    } else if(arg2 == SUKISU_KPM_LIST) {
        sukisu_kpm_list((char __user*) arg3, (unsigned int) arg4, (void __user*) arg5);
    } else if(arg2 == SUKISU_KPM_VERSION) {
        sukisu_kpm_version((char __user*) arg3, (unsigned int) arg4, (void __user*) arg5);
    } else if(arg2 == SUKISU_KPM_CONTROL) {
        sukisu_kpm_control((char __user*) arg3, (char __user*) arg4, (void __user*) arg5);
    }
    return 0;
}

int sukisu_is_kpm_control_code(unsigned long arg2) {
    return (arg2 >= CMD_KPM_CONTROL && arg2 <= CMD_KPM_CONTROL_MAX) ? 1 : 0;
}

EXPORT_SYMBOL(sukisu_handle_kpm);