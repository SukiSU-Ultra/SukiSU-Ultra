/* SPDX-License-Identifier: GPL-2.0 */
/* Both built-in and LKM modes use the same KernelPatch kernel-only bridge.
 * The public extension ioctl and ksu_kpm_cmd layout are unchanged.
 */
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#ifdef CONFIG_ARM64
#include <asm/ptrace.h>
#endif
#include "kpm.h"
#include "bridge.h"

#define KPM_NAME_LEN 32
#define KPM_ARGS_LEN 1024
#define KPM_PATH_LEN 1024
#define KPM_EVENT_LEN 64
/* Legacy INFO has no capacity argument. Existing ksud allocates 256 bytes. */
#define KPM_INFO_LEN 256

long __nocfi sukisu_kpm_bridge(unsigned long op, unsigned long a1, unsigned long a2,
                              unsigned long a3, unsigned long a4)
{
#ifdef CONFIG_ARM64
    typedef long (*handler_t)(const struct pt_regs *);
    static handler_t handler;
    struct pt_regs regs = { 0 };
    handler_t fn = READ_ONCE(handler);

    if (!fn) {
        fn = (handler_t)find_kernel_symbol_exact("__arm64_sys_truncate");
        if (!fn) fn = (handler_t)find_kernel_symbol_exact("__arm64_sys_truncate.cfi_jt");
        if (!fn) fn = (handler_t)find_kernel_symbol_exact("__arm64_sys_truncate.cfi");
        if (!fn) return -EOPNOTSUPP;
        WRITE_ONCE(handler, fn);
    }
    regs.pstate = PSR_MODE_EL1h;
    regs.regs[0] = SUKISU_KPM_SUPERCALL_MAGIC;
    regs.regs[6] = SUKISU_KPM_SUPERCALL_MAGIC2;
    regs.regs[7] = SUKISU_KPM_SUPERCALL_MAGIC3;
    regs.regs[8] = SUKISU_KPM_ABI_VERSION;
    regs.regs[1] = SUKISU_KPM_PROBE;
    /* Without KP this is a real truncate handler: the magic is a non-userspace
     * address and yields an error, not a function pointer. */
    if (fn(&regs) != SUKISU_KPM_ABI_VERSION) return -EOPNOTSUPP;
    regs.regs[1] = op;
    regs.regs[2] = a1;
    regs.regs[3] = a2;
    regs.regs[4] = a3;
    regs.regs[5] = a4;
    return fn(&regs);
#else
    return -EOPNOTSUPP;
#endif
}

static int copy_string(char *buf, const char __user *src, size_t size, bool optional)
{
    long len;
    buf[0] = '\0';
    if (!src) return optional ? 0 : -EINVAL;
    len = strncpy_from_user(buf, src, size);
    if (len < 0) return len;
    if (len >= size) return -ENAMETOOLONG;
    if (!optional && !len) return -EINVAL;
    return 0;
}

static int copy_output(void __user *out, const char *buf, long len, size_t size)
{
    if (len < 0) return len;
    if (len >= size) return -ENOBUFS;
    return copy_to_user(out, buf, len + 1) ? -EFAULT : 0;
}

static int handle_kpm_load_event(const struct ksu_kpm_cmd *cmd)
{
    struct ksu_kpm_load_event_cmd load;
    char *path, *args, *event;
    int rc;

    if (copy_from_user(&load, u64_to_user_ptr(cmd->arg2), sizeof(load))) return -EFAULT;

    path = kzalloc(KPM_PATH_LEN, GFP_KERNEL);
    args = kzalloc(KPM_ARGS_LEN, GFP_KERNEL);
    event = kzalloc(KPM_EVENT_LEN, GFP_KERNEL);
    if (!path || !args || !event) {
        rc = -ENOMEM;
        goto out;
    }

    rc = copy_string(path, u64_to_user_ptr(cmd->arg1), KPM_PATH_LEN, false);
    if (!rc) rc = copy_string(args, u64_to_user_ptr(load.args), KPM_ARGS_LEN, true);
    if (!rc) rc = copy_string(event, u64_to_user_ptr(load.event), KPM_EVENT_LEN, false);
    if (!rc) {
        rc = sukisu_kpm_bridge(SUKISU_KPM_LOAD_EVENT, (unsigned long)path,
                               (unsigned long)args, (unsigned long)event, 0);
    }

out:
    kfree(event);
    kfree(args);
    kfree(path);
    return rc;
}

static int handle_kpm(const struct ksu_kpm_cmd *cmd)
{
    const char __user *arg1 = u64_to_user_ptr(cmd->arg1);
    const char __user *arg2 = u64_to_user_ptr(cmd->arg2);
    char *buf, *name, *args;
    long rc;
    size_t size;

    if (cmd->control_code == SUKISU_KPM_NUM)
        return sukisu_kpm_bridge(SUKISU_KPM_NUM, 0, 0, 0, 0);

    if (cmd->control_code == SUKISU_KPM_LOAD_EVENT)
        return handle_kpm_load_event(cmd);

    if (cmd->control_code == SUKISU_KPM_LOAD ||
        cmd->control_code == SUKISU_KPM_CONTROL) {
        size = cmd->control_code == SUKISU_KPM_LOAD ? KPM_PATH_LEN : KPM_NAME_LEN;
        buf = kzalloc(size + KPM_ARGS_LEN, GFP_KERNEL);
        if (!buf) return -ENOMEM;
        args = buf + size;
        rc = copy_string(buf, arg1, size, false);
        if (!rc) rc = copy_string(args, arg2, KPM_ARGS_LEN,
                                  cmd->control_code == SUKISU_KPM_LOAD);
        if (!rc) rc = sukisu_kpm_bridge(cmd->control_code, (unsigned long)buf,
                                        (unsigned long)args, 0, 0);
        kfree(buf);
        return rc;
    }
    if (cmd->control_code == SUKISU_KPM_UNLOAD) {
        name = kmalloc(KPM_NAME_LEN, GFP_KERNEL);
        if (!name) return -ENOMEM;
        rc = copy_string(name, arg1, KPM_NAME_LEN, false);
        if (!rc) rc = sukisu_kpm_bridge(SUKISU_KPM_UNLOAD, (unsigned long)name, 0, 0, 0);
        kfree(name);
        return rc;
    }
    if (cmd->control_code == SUKISU_KPM_INFO) {
        name = kmalloc(KPM_NAME_LEN + KPM_INFO_LEN, GFP_KERNEL);
        if (!name) return -ENOMEM;
        buf = name + KPM_NAME_LEN;
        rc = copy_string(name, arg1, KPM_NAME_LEN, false);
        if (!rc) {
            rc = sukisu_kpm_bridge(SUKISU_KPM_INFO, (unsigned long)name,
                                    (unsigned long)buf, KPM_INFO_LEN, 0);
            rc = copy_output((void __user *)arg2, buf, rc, KPM_INFO_LEN);
        }
        kfree(name);
        return rc;
    }
    if (cmd->control_code != SUKISU_KPM_LIST &&
        cmd->control_code != SUKISU_KPM_VERSION) return -EOPNOTSUPP;
    if (!cmd->arg2 || cmd->arg2 > SUKISU_KPM_OUTPUT_MAX) return -EINVAL;
    size = cmd->arg2;
    buf = kzalloc(size, GFP_KERNEL);
    if (!buf) return -ENOMEM;
    rc = sukisu_kpm_bridge(cmd->control_code, (unsigned long)buf, size, 0, 0);
    if (rc >= 0) {
        long length = rc;
        rc = copy_output((void __user *)arg1, buf, length, size);
        /* LIST historically returns its length; VERSION returns status. */
        if (!rc && cmd->control_code == SUKISU_KPM_LIST) rc = length;
    }
    kfree(buf);
    return rc;
}

int do_kpm(void __user *arg)
{
    struct ksu_kpm_cmd cmd;
    int result;
    /* Called only through the manager_or_root-authorized extension ioctl. */
    if (copy_from_user(&cmd, arg, sizeof(cmd))) return -EFAULT;
    if (!access_ok(u64_to_user_ptr(cmd.result_code), sizeof(result))) return -EFAULT;
    result = handle_kpm(&cmd);
    return copy_to_user(u64_to_user_ptr(cmd.result_code), &result, sizeof(result)) ? -EFAULT : 0;
}
