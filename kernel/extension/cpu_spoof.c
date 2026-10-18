// SPDX-License-Identifier: GPL-2.0
/*
 * CPU spoof extension implementation.
 *
 * This file consolidates what used to live in:
 *   - kernel/feature/cpu_spoof.c (the per-CPU MIDR/lpj/hwcap rewrite)
 *   - the ioctl dispatcher in kernel/supercall/dispatch.c (do_set_spoof_cpu)
 *
 * The sticky-state get/set only flips an "armed" bit. The actual
 * per-CPU MIDR / lpj / hwcap rewrite happens when an io op carries a
 * struct ksu_set_spoof_cpu_cmd copied from userspace.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/clocksource.h>
#include <linux/errno.h>
#include <linux/version.h>

#include "extension.h"
#include "uapi/supercall.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep

#if defined(CONFIG_ARM64) || defined(__aarch64__)
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/cpufeature.h>
#include <vdso/datapage.h>
#include <vdso/clocksource.h>

#ifndef MIDR_PARTNUM_SHIFT
#define MIDR_PARTNUM_SHIFT 4
#endif

#ifndef MIDR_PARTNUM_MASK
#define MIDR_PARTNUM_MASK (0xfff << MIDR_PARTNUM_SHIFT)
#endif

#ifndef MIDR_PARTNUM
#define MIDR_PARTNUM(midr) (((midr) & MIDR_PARTNUM_MASK) >> MIDR_PARTNUM_SHIFT)
#endif

#ifndef ARM_CPU_PART_NEOVERSE_N1
#define ARM_CPU_PART_NEOVERSE_N1 0xd0c
#endif

#ifndef ARM_CPU_PART_CORTEX_A76
#define ARM_CPU_PART_CORTEX_A76 0xd0b
#endif

#ifndef QCOM_CPU_PART_KRYO_4XX_GOLD
#define QCOM_CPU_PART_KRYO_4XX_GOLD 0x804
#endif

#ifndef CS_HRES_COARSE
#define CS_HRES_COARSE 0
#endif

#ifndef CS_RAW
#define CS_RAW 1
#endif

#ifndef VDSO_CLOCKMODE_ARCHTIMER
#define VDSO_CLOCKMODE_ARCHTIMER 1
#endif

#ifndef ARM64_WORKAROUND_1418040
#define ARM64_WORKAROUND_1418040 37
#endif

#endif

static bool cpu_spoof_armed = false;

static int set_spoof_cpu(const struct ksu_set_spoof_cpu_cmd *cmd)
{
    if (!cmd)
        return -EINVAL;

    if (cmd->cpu_index >= num_possible_cpus()) {
        pr_warn("ksu: set_spoof_cpu out-of-bounds cpu_index %u\n",
                cmd->cpu_index);
        return -EINVAL;
    }

#if defined(CONFIG_ARM64) || defined(__aarch64__)
    {
        unsigned long cpu_data_base = find_kernel_symbol_exact("cpu_data");
        if (cpu_data_base) {
            struct cpuinfo_arm64 *info =
                per_cpu_ptr((struct cpuinfo_arm64 *)cpu_data_base,
                            cmd->cpu_index);
            if (info)
                info->reg_midr = cmd->midr;
        } else {
            pr_warn("ksu: set_spoof_cpu failed to resolve 'cpu_data'\n");
        }
    }

    if (cmd->cpu_index == 0) {
        unsigned long *lpj =
            (unsigned long *)find_kernel_symbol_exact("loops_per_jiffy");
        if (lpj) {
            *lpj = ((unsigned long)cmd->bogomips * 500000) / (100 * HZ);
        } else {
            pr_warn("ksu: set_spoof_cpu failed to resolve 'loops_per_jiffy'\n");
        }

        unsigned long *elf_hwcap_bitmap =
            (unsigned long *)find_kernel_symbol_exact("elf_hwcap");
        if (elf_hwcap_bitmap) {
            elf_hwcap_bitmap[0] = cmd->hwcap;
            elf_hwcap_bitmap[1] = cmd->hwcap2;
        } else {
            pr_warn("ksu: set_spoof_cpu failed to resolve 'elf_hwcap'\n");
        }

        {
            unsigned int part = MIDR_PARTNUM(cmd->midr);
            if (part != ARM_CPU_PART_NEOVERSE_N1 &&
                part != ARM_CPU_PART_CORTEX_A76 &&
                part != QCOM_CPU_PART_KRYO_4XX_GOLD) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)
                struct vdso_time_data **vdso_time_data_ptr =
                    (struct vdso_time_data **)find_kernel_symbol_exact(
                        "vdso_time_data");
                if (!vdso_time_data_ptr)
                    vdso_time_data_ptr =
                        (struct vdso_time_data **)find_kernel_symbol_exact(
                            "_vdso_time_data");
                if (!vdso_time_data_ptr)
                    vdso_time_data_ptr =
                        (struct vdso_time_data **)find_kernel_symbol_exact(
                            "vdso_data");
                if (vdso_time_data_ptr && *vdso_time_data_ptr) {
                    struct vdso_time_data *vdso = *vdso_time_data_ptr;
                    vdso->clock_data[CS_HRES_COARSE].clock_mode =
                        VDSO_CLOCKMODE_ARCHTIMER;
                    vdso->clock_data[CS_RAW].clock_mode =
                        VDSO_CLOCKMODE_ARCHTIMER;
                }
#else
                struct vdso_data **vdso_data_ptr =
                    (struct vdso_data **)find_kernel_symbol_exact("vdso_data");
                if (vdso_data_ptr && *vdso_data_ptr) {
                    struct vdso_data *vdso = *vdso_data_ptr;
                    vdso[CS_HRES_COARSE].clock_mode =
                        VDSO_CLOCKMODE_ARCHTIMER;
                    vdso[CS_RAW].clock_mode = VDSO_CLOCKMODE_ARCHTIMER;
                }
#endif

                {
                    struct clocksource **curr_cs_ptr =
                        (struct clocksource **)find_kernel_symbol_exact(
                            "curr_clocksource");
                    if (curr_cs_ptr && *curr_cs_ptr)
                        (*curr_cs_ptr)->vdso_clock_mode =
                            VDSO_CLOCKMODE_ARCHTIMER;
                }

                {
                    enum vdso_clock_mode *vd_default =
                        (enum vdso_clock_mode *)find_kernel_symbol_exact(
                            "vdso_default");
                    if (vd_default)
                        *vd_default = VDSO_CLOCKMODE_ARCHTIMER;
                }

                {
                    unsigned long *caps =
                        (unsigned long *)find_kernel_symbol_exact("cpu_hwcaps");
                    if (!caps)
                        caps = (unsigned long *)find_kernel_symbol_exact(
                            "system_cpucaps");
                    if (caps)
                        clear_bit(ARM64_WORKAROUND_1418040, caps);
                }
            }
        }
    }
#endif

    pr_info("KernelSU Stealth: CPU %u identity spoofed (MIDR: 0x%08x)\n",
            cmd->cpu_index, cmd->midr);
    return 0;
}

int ksu_extension_cpu_spoof_get(u32 id, u64 *value)
{
    *value = cpu_spoof_armed ? 1 : 0;
    return 0;
}

int ksu_extension_cpu_spoof_set(u32 id, u64 value)
{
    cpu_spoof_armed = value != 0;
    pr_info("extension/cpu_spoof: armed=%u\n", cpu_spoof_armed);
    return 0;
}

const struct ksu_extension_handler_ops ksu_extension_cpu_spoof_ops = {
    .get = ksu_extension_cpu_spoof_get,
    .set = ksu_extension_cpu_spoof_set,
};

int ksu_extension_cpu_spoof_io(u32 id, void __user *raw)
{
    struct ksu_set_spoof_cpu_cmd cmd;

    if (copy_from_user(&cmd, raw, sizeof(cmd)))
        return -EFAULT;

    if (!cpu_spoof_armed)
        return 0;

    return set_spoof_cpu(&cmd);
}
