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
    rc = load_module_path(path, args, (__user void *)ptr);
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
    rc = unload_module(name, (__user void *)ptr);
    *result = (int)rc;
    return rc;
}
EXPORT_SYMBOL(sukisu_kpm_unload_module);

noinline NO_OPTIMIZE long sukisu_kpm_num(int *result)
{
    if (!result) return -EINVAL;
    *result = get_module_nums();
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
    sz = get_module_info(name, buf, bufferSize);
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
    sz = list_modules((char *)out, bufferSize);
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
    rc = module_control0(name, args, NULL, 0);
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

noinline long sukisu_handle_kpm(unsigned long control_code, unsigned long arg1,
                                unsigned long arg2, unsigned long result_code)
{
    int res = -ENOSYS;
    if (control_code == SUKISU_KPM_LOAD) {
        char kernel_load_path[256];
        char kernel_args_buffer[1024];

        if (arg1 == 0) {
            res = -EINVAL;
            goto exit;
        }

        if (!access_ok(arg1, sizeof(kernel_load_path))) {
            goto invalid_arg;
        }

        strncpy_from_user((char *)&kernel_load_path, (const char *)arg1,
                          sizeof(kernel_load_path));
        kernel_load_path[sizeof(kernel_load_path) - 1] = '\0';

        kernel_args_buffer[0] = '\0';
        if (arg2 != 0) {
            if (!access_ok(arg2, sizeof(kernel_args_buffer))) {
                goto invalid_arg;
            }
            strncpy_from_user((char *)&kernel_args_buffer,
                              (const char *)arg2,
                              sizeof(kernel_args_buffer));
            kernel_args_buffer[sizeof(kernel_args_buffer) - 1] = '\0';
        }

        res = (int)load_module_path(kernel_load_path,
                                    kernel_args_buffer[0] ?
                                        kernel_args_buffer :
                                        NULL,
                                    (void __user *)arg1);
    } else if (control_code == SUKISU_KPM_UNLOAD) {
        char kernel_name_buffer[KPM_NAME_LEN];

        if (arg1 == 0) {
            res = -EINVAL;
            goto exit;
        }

        if (!access_ok(arg1, sizeof(kernel_name_buffer))) {
            goto invalid_arg;
        }

        strncpy_from_user((char *)&kernel_name_buffer, (const char *)arg1,
                          sizeof(kernel_name_buffer));
        kernel_name_buffer[sizeof(kernel_name_buffer) - 1] = '\0';

        res = (int)unload_module(kernel_name_buffer, NULL);
    } else if (control_code == SUKISU_KPM_NUM) {
        res = get_module_nums();
    } else if (control_code == SUKISU_KPM_INFO) {
        char kernel_name_buffer[KPM_NAME_LEN];
        char buf[2048];
        int size;

        if (arg1 == 0 || arg2 == 0) {
            res = -EINVAL;
            goto exit;
        }

        if (!access_ok(arg1, sizeof(kernel_name_buffer))) {
            goto invalid_arg;
        }

        strncpy_from_user((char *)&kernel_name_buffer, (const char *)arg1,
                          sizeof(kernel_name_buffer));
        kernel_name_buffer[sizeof(kernel_name_buffer) - 1] = '\0';

        size = get_module_info(kernel_name_buffer, buf, sizeof(buf));
        if (size < 0) {
            res = size;
            goto exit;
        }

        if ((unsigned long)size > arg2) {
            res = -ENOBUFS;
            goto exit;
        }

        if (copy_to_user((void *)arg2, buf, size)) {
            goto invalid_arg;
        }
        res = 0;
    } else if (control_code == SUKISU_KPM_LIST) {
        char buf[4096];
        int len = (int)arg2;

        if (len <= 0) {
            res = -EINVAL;
            goto exit;
        }

        if (!access_ok(arg2, len)) {
            goto invalid_arg;
        }

        res = list_modules(buf, sizeof(buf));
        if (res < 0) goto exit;
        if (res > len) {
            res = -ENOBUFS;
            goto exit;
        }

        if (copy_to_user((void *)arg1, buf, res)) {
            goto invalid_arg;
        }
    } else if (control_code == SUKISU_KPM_CONTROL) {
        char kpm_name[KPM_NAME_LEN] = { 0 };
        char kpm_args[KPM_ARGS_LEN] = { 0 };

        if (arg1 == 0 || arg2 == 0) {
            res = -EINVAL;
            goto exit;
        }

        if (!access_ok(arg1, sizeof(kpm_name))) {
            goto invalid_arg;
        }

        if (!access_ok(arg2, sizeof(kpm_args))) {
            goto invalid_arg;
        }

        long name_len = strncpy_from_user((char *)&kpm_name,
                                          (const char __user *)arg1,
                                          sizeof(kpm_name));
        if (name_len <= 0) {
            res = -EINVAL;
            goto exit;
        }

        long arg_len = strncpy_from_user((char *)&kpm_args,
                                         (const char __user *)arg2,
                                         sizeof(kpm_args));
        if (arg_len < 0) {
            res = -EINVAL;
            goto exit;
        }

        res = (int)module_control0(kpm_name, kpm_args, NULL, 0);
    } else if (control_code == SUKISU_KPM_VERSION) {
        char buffer[256] = { 0 };
        int len;

        sukisu_kpm_version((char *)&buffer, sizeof(buffer));

        unsigned int outlen = (unsigned int)arg2;
        len = (int)strlen(buffer);
        if ((unsigned int)len >= outlen && outlen > 0)
            len = (int)outlen - 1;
        if (len < 0) len = 0;

        if (copy_to_user((void *)arg1, buffer, len + 1)) {
            goto invalid_arg;
        }
        res = 0;
    }

exit:
    if (copy_to_user((void __user *)result_code, &res, sizeof(res)) != 0)
        pr_warn("KPM: copy_to_user result failed\n");

    return 0;
invalid_arg:
    pr_err("KPM: invalid pointer detected! arg1: %llx arg2: %llx\n",
           (unsigned long long)arg1, (unsigned long long)arg2);
    res = -EFAULT;
    goto exit;
}
EXPORT_SYMBOL(sukisu_handle_kpm);

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
