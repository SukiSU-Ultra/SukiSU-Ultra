/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Liankong. All Rights Reserved.
 *
 * KPM IOCTL dispatcher. Accepts the seven SUKISU_KPM_* control codes
 * from uapi/supercall.h and dispatches them to the KP-style
 * load/unload/control/list/info/num helpers in module.c.
 *
 * The user-space ABI is `struct ksu_kpm_cmd`:
 *
 *   struct ksu_kpm_cmd {
 *       __u64 control_code;  // SUKISU_KPM_* constant (1..7)
 *       __u64 arg1;          // path / name / buffer address
 *       __u64 arg2;          // args / buffer length
 *       __u64 result_code;   // user pointer to int (return value)
 *   };
 *
 * `arg1` and `arg2` are interpreted as userspace pointers, except for
 * SUKISU_KPM_NUM and SUKISU_KPM_VERSION (where they are buffer /
 * length pairs).
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kernfs.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/set_memory.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <asm/elf.h>
#include <linux/errno.h>

#include "module.h"
#include "kpmodule.h"
#include "kpm.h"

#define KPM_NAME_LEN 32
#define KPM_ARGS_LEN 1024

#define KPM_LOADER_VERSION "SukiSU-Ultra KPM 1.0 (KP-compatible)"

#ifndef NO_OPTIMIZE
#if defined(__GNUC__) && !defined(__clang__)
#define NO_OPTIMIZE __attribute__((optimize("O0")))
#elif defined(__clang__)
#define NO_OPTIMIZE __attribute__((optnone))
#else
#define NO_OPTIMIZE
#endif
#endif

/*
 * The KP loader passes a `reserved` user pointer to receive the
 * kpm_load_result struct. We hand the same pointer through, so userspace
 * gets the loader's own error code and message verbatim.
 */
noinline NO_OPTIMIZE long sukisu_kpm_load_module_path(const char *path,
                                                     const char *args,
                                                     void *ptr, int *result)
{
    long rc;
    if (!path || !result) {
        if (result) *result = -EINVAL;
        return -EINVAL;
    }
    rc = kpm_load_module_path(path, args, (__user void *)ptr);
    *result = (int)rc;
    return rc;
}
EXPORT_SYMBOL(sukisu_kpm_load_module_path);

noinline NO_OPTIMIZE long sukisu_kpm_unload_module(const char *name, void *ptr,
                                                   int *result)
{
    long rc;
    if (!name || !result) {
        if (result) *result = -EINVAL;
        return -EINVAL;
    }
    rc = kpm_unload_module(name, (__user void *)ptr);
    *result = (int)rc;
    return rc;
}
EXPORT_SYMBOL(sukisu_kpm_unload_module);

noinline NO_OPTIMIZE long sukisu_kpm_num(int *result)
{
    if (!result) return -EINVAL;
    *result = kpm_get_module_nums();
    return *result;
}
EXPORT_SYMBOL(sukisu_kpm_num);

noinline NO_OPTIMIZE long sukisu_kpm_info(const char *name, char *buf,
                                         int bufferSize, int *size)
{
    int sz;
    if (!name || !buf || bufferSize <= 0 || !size) {
        if (size) *size = 0;
        return -EINVAL;
    }
    sz = kpm_get_module_info(name, buf, bufferSize);
    *size = sz;
    return sz;
}
EXPORT_SYMBOL(sukisu_kpm_info);

noinline NO_OPTIMIZE long sukisu_kpm_list(void *out, int bufferSize, int *result)
{
    int sz;
    if (!out || bufferSize <= 0 || !result) {
        if (result) *result = -EINVAL;
        return -EINVAL;
    }
    sz = kpm_list_modules((char *)out, bufferSize);
    *result = sz;
    return sz;
}
EXPORT_SYMBOL(sukisu_kpm_list);

noinline NO_OPTIMIZE long sukisu_kpm_control(const char *name, const char *args,
                                            long arg_len, int *result)
{
    long rc;
    if (!name || !args || !result) {
        if (result) *result = -EINVAL;
        return -EINVAL;
    }
    rc = kpm_module_control0(name, args, NULL, 0);
    *result = (int)rc;
    return rc;
}
EXPORT_SYMBOL(sukisu_kpm_control);

noinline NO_OPTIMIZE long sukisu_kpm_version(char *buf, int bufferSize)
{
    if (!buf || bufferSize <= 0) return -EINVAL;
    strscpy(buf, KPM_LOADER_VERSION, bufferSize);
    return (long)strlen(KPM_LOADER_VERSION);
}
EXPORT_SYMBOL(sukisu_kpm_version);

static noinline int sukisu_kpm_handle_load(unsigned long arg1, unsigned long arg2);
static noinline int sukisu_kpm_handle_unload(unsigned long arg1);
static noinline int sukisu_kpm_handle_info(unsigned long arg1, unsigned long arg2);
static noinline int sukisu_kpm_handle_list(unsigned long arg1, unsigned long arg2);
static noinline int sukisu_kpm_handle_control(unsigned long arg1, unsigned long arg2);
static noinline int sukisu_kpm_handle_version(unsigned long arg1, unsigned long arg2);

noinline long sukisu_handle_kpm(unsigned long control_code, unsigned long arg1,
                                unsigned long arg2, unsigned long result_code)
{
    int res = -ENOSYS;

    /*
     * Each branch carries a non-trivial stack buffer (up to 4 KiB for
     * the LIST buffer alone). Folding them into a single function
     * makes the compiler sum the worst case per branch and bust
     * -Wframe-larger-than on 6.1+, so we keep every branch in its own
     * noinline helper. `sukisu_handle_kpm` itself stays trivial and
     * only needs to be noinline to prevent the IOCTL dispatcher from
     * pulling the whole ladder into the syscall.
     */
    switch (control_code) {
    case SUKISU_KPM_LOAD:
        res = sukisu_kpm_handle_load(arg1, arg2);
        break;
    case SUKISU_KPM_UNLOAD:
        res = sukisu_kpm_handle_unload(arg1);
        break;
    case SUKISU_KPM_NUM:
        res = kpm_get_module_nums();
        break;
    case SUKISU_KPM_INFO:
        res = sukisu_kpm_handle_info(arg1, arg2);
        break;
    case SUKISU_KPM_LIST:
        res = sukisu_kpm_handle_list(arg1, arg2);
        break;
    case SUKISU_KPM_CONTROL:
        res = sukisu_kpm_handle_control(arg1, arg2);
        break;
    case SUKISU_KPM_VERSION:
        res = sukisu_kpm_handle_version(arg1, arg2);
        break;
    default:
        break;
    }

    if (copy_to_user((void __user *)result_code, &res, sizeof(res)) != 0)
        pr_warn("KPM: copy_to_user result failed\n");

    return 0;
}
EXPORT_SYMBOL(sukisu_handle_kpm);

static noinline int sukisu_kpm_handle_load(unsigned long arg1, unsigned long arg2)
{
    char kernel_load_path[256];
    char kernel_args_buffer[1024];

    if (arg1 == 0)
        return -EINVAL;

    if (!access_ok(arg1, sizeof(kernel_load_path)))
        return -EFAULT;

    if (strncpy_from_user(kernel_load_path, (const char __user *)arg1,
                          sizeof(kernel_load_path)) < 0)
        return -EFAULT;
    kernel_load_path[sizeof(kernel_load_path) - 1] = '\0';

    kernel_args_buffer[0] = '\0';
    if (arg2 != 0) {
        if (!access_ok(arg2, sizeof(kernel_args_buffer)))
            return -EFAULT;
        if (strncpy_from_user(kernel_args_buffer, (const char __user *)arg2,
                              sizeof(kernel_args_buffer)) < 0)
            return -EFAULT;
        kernel_args_buffer[sizeof(kernel_args_buffer) - 1] = '\0';
    }

    return (int)kpm_load_module_path(kernel_load_path,
                                    kernel_args_buffer[0] ?
                                        kernel_args_buffer :
                                        NULL,
                                    (void __user *)arg1);
}

static noinline int sukisu_kpm_handle_unload(unsigned long arg1)
{
    char kernel_name_buffer[KPM_NAME_LEN];

    if (arg1 == 0)
        return -EINVAL;

    if (!access_ok(arg1, sizeof(kernel_name_buffer)))
        return -EFAULT;

    if (strncpy_from_user(kernel_name_buffer, (const char __user *)arg1,
                          sizeof(kernel_name_buffer)) < 0)
        return -EFAULT;
    kernel_name_buffer[sizeof(kernel_name_buffer) - 1] = '\0';

    return (int)kpm_unload_module(kernel_name_buffer, NULL);
}

static noinline int sukisu_kpm_handle_info(unsigned long arg1, unsigned long arg2)
{
    char kernel_name_buffer[KPM_NAME_LEN];
    char *buf;
    int size;
    int res;

    if (arg1 == 0 || arg2 == 0)
        return -EINVAL;

    if (!access_ok(arg1, sizeof(kernel_name_buffer)))
        return -EFAULT;

    if (strncpy_from_user(kernel_name_buffer, (const char __user *)arg1,
                          sizeof(kernel_name_buffer)) < 0)
        return -EFAULT;
    kernel_name_buffer[sizeof(kernel_name_buffer) - 1] = '\0';

    buf = kmalloc(2048, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    size = kpm_get_module_info(kernel_name_buffer, buf, 2048);
    if (size < 0) {
        res = size;
        goto out;
    }

    if ((unsigned long)size > arg2) {
        res = -ENOBUFS;
        goto out;
    }

    if (copy_to_user((void __user *)arg2, buf, size))
        res = -EFAULT;
    else
        res = 0;

out:
    kfree(buf);
    return res;
}

static noinline int sukisu_kpm_handle_list(unsigned long arg1, unsigned long arg2)
{
    char *buf;
    int len = (int)arg2;
    int res;

    if (len <= 0)
        return -EINVAL;

    if (!access_ok(arg2, len))
        return -EFAULT;

    buf = kmalloc(4096, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    res = kpm_list_modules(buf, 4096);
    if (res < 0)
        goto out;
    if (res > len) {
        res = -ENOBUFS;
        goto out;
    }

    if (copy_to_user((void __user *)arg1, buf, res))
        res = -EFAULT;
    else
        res = 0;

out:
    kfree(buf);
    return res;
}

static noinline int sukisu_kpm_handle_control(unsigned long arg1, unsigned long arg2)
{
    char kpm_name[KPM_NAME_LEN] = { 0 };
    char kpm_args[KPM_ARGS_LEN] = { 0 };
    long name_len, arg_len;

    if (arg1 == 0 || arg2 == 0)
        return -EINVAL;

    if (!access_ok(arg1, sizeof(kpm_name)))
        return -EFAULT;

    if (!access_ok(arg2, sizeof(kpm_args)))
        return -EFAULT;

    name_len = strncpy_from_user(kpm_name, (const char __user *)arg1,
                                 sizeof(kpm_name));
    if (name_len <= 0)
        return -EINVAL;

    arg_len = strncpy_from_user(kpm_args, (const char __user *)arg2,
                                sizeof(kpm_args));
    if (arg_len < 0)
        return -EINVAL;

    return (int)kpm_module_control0(kpm_name, kpm_args, NULL, 0);
}

static noinline int sukisu_kpm_handle_version(unsigned long arg1, unsigned long arg2)
{
    char buffer[256] = { 0 };
    int len;
    unsigned int outlen = (unsigned int)arg2;

    sukisu_kpm_version(buffer, sizeof(buffer));

    len = (int)strlen(buffer);
    if ((unsigned int)len >= outlen && outlen > 0)
        len = (int)outlen - 1;
    if (len < 0) len = 0;

    if (copy_to_user((void __user *)arg1, buffer, len + 1))
        return -EFAULT;
    return 0;
}

int sukisu_is_kpm_control_code(unsigned long control_code)
{
    return (control_code >= SUKISU_KPM_LOAD &&
            control_code <= SUKISU_KPM_VERSION) ?
               1 :
               0;
}
EXPORT_SYMBOL(sukisu_is_kpm_control_code);

int do_kpm(void __user *arg)
{
    struct ksu_kpm_cmd cmd;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        pr_err("kpm: copy_from_user failed\n");
        return -EFAULT;
    }

    if (!access_ok((void __user *)cmd.control_code, sizeof(int))) {
        pr_err("kpm: invalid control_code pointer %llx\n",
               (unsigned long long)cmd.control_code);
        return -EFAULT;
    }

    if (!access_ok((void __user *)cmd.result_code, sizeof(int))) {
        pr_err("kpm: invalid result_code pointer %llx\n",
               (unsigned long long)cmd.result_code);
        return -EFAULT;
    }

    return sukisu_handle_kpm(cmd.control_code, cmd.arg1, cmd.arg2,
                             cmd.result_code);
}
EXPORT_SYMBOL(do_kpm);
