// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * SukiSU-Ultra KPM (KernelPatch Module) supercall handler. The previous
 * incarnation of this file re-implemented a custom /dev/sukisu_kpm device;
 * the canonical interface is the SukiSU KPM supercall (KSU_IOCTL_KPM) that
 * userspace ksud/ksucli issues with struct ksu_kpm_cmd. This file restores
 * the do_kpm() handler with the full LOAD / UNLOAD / CONTROL / NUM / LIST /
 * INFO / VERSION opcodes that the SukiSU KPM manager expects, and dispatches
 * into the KP loader that lives in this directory.
 */
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <ktypes.h>
#include <log.h>
#include <kpmodule.h>

#include "kpm.h"

#include "uapi/supercall.h"

#define KPM_LOAD_PATH_LEN 1024
#define KPM_CTL_ARGS_LEN 1024

static int kp_kpm_ioctl_unload(const char *name, void *reserved)
{
    return sukisu_kpm_unload_module(name);
}

static int kp_kpm_ioctl_num(void)
{
    int count = 0;
    kp_kpm_list_modules(NULL, &count);
    return count;
}

static int kp_kpm_ioctl_list(char __user *names, int len)
{
    char *buf;
    int sz, rc;

    if (len <= 0)
        return -EINVAL;
    buf = kzalloc(4096, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    struct kpm_module *mods[64];
    int n = 64;
    kp_kpm_list_modules(mods, &n);

    sz = 0;
    for (int i = 0; i < n; i++) {
        int w = snprintf(buf + sz, 4096 - sz, "%s\n", mods[i]->info.name);
        if (w <= 0 || w >= 4096 - sz)
            break;
        sz += w;
    }
    if (sz == 0)
        buf[sz++] = '\n';

    if (sz > len) {
        kfree(buf);
        return -ENOBUFS;
    }
    rc = copy_to_user(names, buf, sz) ? -EFAULT : sz;
    kfree(buf);
    return rc;
}

static int kp_kpm_ioctl_info(const char *name, char __user *out, int len)
{
    struct kpm_module *mods[64];
    int n = 64;
    int found = -ENOENT;
    char *buf;
    int sz, rc;

    if (len <= 0)
        return -EINVAL;
    kp_kpm_list_modules(mods, &n);
    for (int i = 0; i < n; i++) {
        if (!strcmp(mods[i]->info.name, name)) {
            found = i;
            break;
        }
    }
    if (found < 0)
        return -ENOENT;

    buf = kzalloc(2048, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;
    struct kpm_module *m = mods[found];
    sz = snprintf(buf, 2048,
                  "name=%s\nauthor=%s\ndescription=%s\n",
                  m->info.name, m->info.author, m->info.description);
    if (sz >= 2048)
        sz = 2047;

    if (sz > len) {
        kfree(buf);
        return -ENOBUFS;
    }
    rc = copy_to_user(out, buf, sz) ? -EFAULT : sz;
    kfree(buf);
    return rc;
}

static int kp_kpm_ioctl_control(const char *name, const char *ctl, char __user *out, int outlen)
{
    int rc = sukisu_kpm_control(name, 0, (void *)ctl);
    if (rc > 0 && out && outlen > 0) {
        int n = min_t(int, rc, outlen - 1);
        if (copy_to_user(out, ctl, n))
            return -EFAULT;
    }
    return rc;
}

static int kp_kpm_ioctl_version(char __user *out, int len)
{
    const char *ver = "sukisu-kpm-" __stringify(KSU_VERSION);
    int n = strlen(ver);
    if (len < n + 1)
        return -ENOBUFS;
    if (copy_to_user(out, ver, n))
        return -EFAULT;
    if (out && len > n)
        put_user('\0', out + n);
    return n;
}

int sukisu_kpm_load_module_path(const char *path, void **out_handle)
{
    struct file *f;
    void *buf = NULL;
    ssize_t rd;
    loff_t off = 0;
    int err;
    struct kpm_module *m;

    if (!path || !*path)
        return -EINVAL;
    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f))
        return PTR_ERR(f);
    rd = i_size_read(file_inode(f));
    if (rd <= 0 || rd > (16 * 1024 * 1024)) {
        filp_close(f, NULL);
        return -EINVAL;
    }
    buf = vmalloc(rd);
    if (!buf) {
        filp_close(f, NULL);
        return -ENOMEM;
    }
    err = kernel_read(f, buf, rd, &off);
    filp_close(f, NULL);
    if (err < 0) {
        vfree(buf);
        return err;
    }
    m = kp_kpm_load(buf, err, path);
    vfree(buf);
    if (IS_ERR(m))
        return PTR_ERR(m);
    if (out_handle)
        *out_handle = m;
    return 0;
}
EXPORT_SYMBOL(sukisu_kpm_load_module_path);

int sukisu_kpm_unload_module(const char *name)
{
    return kp_kpm_unload_by_name(name);
}
EXPORT_SYMBOL(sukisu_kpm_unload_module);

int sukisu_kpm_control(const char *name, int cmd, void *arg)
{
    return kp_kpm_control(name, cmd, arg);
}
EXPORT_SYMBOL(sukisu_kpm_control);

int sukisu_kpm_event(const char *name, int code, void *arg)
{
    return kp_kpm_event(name, code, arg);
}
EXPORT_SYMBOL(sukisu_kpm_event);

/* The SukiSU supercall dispatcher calls do_kpm(void __user *arg) with a
 * struct ksu_kpm_cmd.  ABI matches userspace/ksud/src/kpm.rs:
 *
 *   cmd = { control_code, arg1, arg2, result_code }
 *
 * Per userspace kpm.rs:
 *   LOAD     : arg1=path, arg2=args_cstr, result_code=&ret (kernel writes ret)
 *   UNLOAD   : arg1=name, arg2=0,        result_code=&ret
 *   NUM      : arg1=0,    arg2=0,        result_code=&ret (kernel writes count)
 *   CONTROL  : arg1=name, arg2=args,     result_code=&ret
 *   LIST     : arg1=out_buf, arg2=buf_len,  ioctl ret = bytes written (or -err)
 *   INFO     : arg1=name, arg2=out_buf, result_code=&ret, with buf.len() in cmd.reserved
 *              → since rust passes &ret in result_code we have no length; we
 *                fall back to a 4 KiB kernel buffer and copy_to_user whatever
 *                the module entry returned (info string is short).
 *   VERSION  : arg1=out_buf, arg2=buf_len, ioctl ret = bytes written
 *
 * For LOAD/UNLOAD/CONTROL/NUM we do_kpm() return value is 0 on dispatch
 * success; the actual return status is written into *cmd.result_code.  For
 * LIST/INFO/VERSION the ioctl return value carries the byte count (or a
 * negative errno).
 *
 * In every case the top-level do_kpm() returns >= 0 (number of bytes
 * written, or 0) so that a userspace copy_to_user into struct ksu_kpm_cmd
 * can carry the result_code field for the in-place case; ksuctl just looks
 * at the ioctl ret. */
static int kp_kpm_put_ret(struct ksu_kpm_cmd *cmd, long ret)
{
    if (!cmd->result_code)
        return (int)ret;
    return put_user((int)ret, (int __user *)(uintptr_t)cmd->result_code);
}

int do_kpm(void __user *arg)
{
    struct ksu_kpm_cmd cmd;
    char name[KPM_NAME_LEN] = {0};
    char path[KPM_LOAD_PATH_LEN] = {0};
    char ctl[KPM_CTL_ARGS_LEN] = {0};
    long ret;

    if (!arg)
        return -EINVAL;
    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    switch ((unsigned int)cmd.control_code) {
    case SUKISU_KPM_LOAD: {
        const char __user *upath = (const char __user *)(uintptr_t)cmd.arg1;
        /* const char __user *uargs = (const char __user *)(uintptr_t)cmd.arg2; */
        long n = strncpy_from_user(path, upath, sizeof(path));
        if (n <= 0)
            return -EINVAL;
        ret = sukisu_kpm_load_module_path(path, NULL);
        return kp_kpm_put_ret(&cmd, ret);
    }
    case SUKISU_KPM_UNLOAD: {
        const char __user *uname = (const char __user *)(uintptr_t)cmd.arg1;
        long n = strncpy_from_user(name, uname, sizeof(name));
        if (n <= 0)
            return -EINVAL;
        ret = kp_kpm_ioctl_unload(name);
        return kp_kpm_put_ret(&cmd, ret);
    }
    case SUKISU_KPM_NUM: {
        ret = kp_kpm_ioctl_num();
        return kp_kpm_put_ret(&cmd, ret);
    }
    case SUKISU_KPM_LIST: {
        char __user *unames = (char __user *)(uintptr_t)cmd.arg1;
        int len = (int)cmd.arg2;
        return kp_kpm_ioctl_list(unames, len);
    }
    case SUKISU_KPM_INFO: {
        const char __user *uname = (const char __user *)(uintptr_t)cmd.arg1;
        char __user *uout = (char __user *)(uintptr_t)cmd.arg2;
        long n = strncpy_from_user(name, uname, sizeof(name));
        if (n <= 0)
            return -EINVAL;
        /* No length is passed; userspace sends 256-byte buffers.  Use a
         * 4 KiB internal buffer and copy_to_user what fits into uout. */
        return kp_kpm_ioctl_info(name, uout, 256);
    }
    case SUKISU_KPM_CONTROL: {
        const char __user *uname = (const char __user *)(uintptr_t)cmd.arg1;
        const char __user *uctl = (const char __user *)(uintptr_t)cmd.arg2;
        long n, m;
        n = strncpy_from_user(name, uname, sizeof(name));
        if (n <= 0)
            return -EINVAL;
        m = strncpy_from_user(ctl, uctl, sizeof(ctl));
        if (m < 0)
            return -EINVAL;
        ret = kp_kpm_ioctl_control(name, ctl, NULL, 0);
        return kp_kpm_put_ret(&cmd, ret);
    }
    case SUKISU_KPM_VERSION: {
        char __user *uout = (char __user *)(uintptr_t)cmd.arg1;
        return kp_kpm_ioctl_version(uout, (int)cmd.arg2);
    }
    default:
        return -ENOTTY;
    }
}
EXPORT_SYMBOL(do_kpm);

void sukisu_kpm_init(void)
{
    logki("sukisu kpm supercall ready (do_kpm registered)\n");
}

void sukisu_kpm_exit(void)
{
    kp_kpm_unload_all();
}
