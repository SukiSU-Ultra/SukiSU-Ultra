// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/clocksource.h>
#include <linux/errno.h>

#include "cpu_spoof.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

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

int ksu_set_spoof_cpu(const struct ksu_set_spoof_cpu_cmd *cmd)
{
    if (!cmd)
        return -EINVAL;

    /* Boundary Enforcement to prevent out-of-bounds per-CPU page dereferencing */
    if (cmd->cpu_index >= num_possible_cpus()) {
        pr_warn("ksu: set_spoof_cpu out-of-bounds cpu_index %u\n", cmd->cpu_index);
        return -EINVAL;
    }

#if defined(CONFIG_ARM64) || defined(__aarch64__)
    /* 1. Resolve 'cpu_data' and overwrite target core MIDR (executed for each CPU) */
    {
        unsigned long cpu_data_base = find_kernel_symbol_exact("cpu_data");
        if (cpu_data_base) {
            struct cpuinfo_arm64 *info = per_cpu_ptr((struct cpuinfo_arm64 *)cpu_data_base, cmd->cpu_index);
            if (info) {
                info->reg_midr = cmd->midr;
            }
        } else {
            pr_warn("ksu: set_spoof_cpu failed to resolve 'cpu_data'\n");
        }
    }

    /* 2. Global modifications (executed exactly once on CPU 0) */
    if (cmd->cpu_index == 0) {
        /* A. Override global dynamic timing metric */
        unsigned long *lpj = (unsigned long *)find_kernel_symbol_exact("loops_per_jiffy");
        if (lpj) {
            pr_info("ksu: set_spoof_cpu current global loops_per_jiffy: %lu\n", *lpj);
            *lpj = ((unsigned long)cmd->bogomips * 500000) / (100 * HZ);
            pr_info("ksu: set_spoof_cpu updated global loops_per_jiffy: %lu\n", *lpj);
        } else {
            pr_warn("ksu: set_spoof_cpu failed to resolve 'loops_per_jiffy'\n");
        }

        /* B. Globally overwrite hardware capabilities */
        unsigned long *elf_hwcap_bitmap = (unsigned long *)find_kernel_symbol_exact("elf_hwcap");
        if (elf_hwcap_bitmap) {
            pr_info("ksu: set_spoof_cpu current elf_hwcap: 0x%lx, elf_hwcap2: 0x%lx\n", elf_hwcap_bitmap[0],
                    elf_hwcap_bitmap[1]);
            elf_hwcap_bitmap[0] = cmd->hwcap; /* Primary hwcap */
            elf_hwcap_bitmap[1] = cmd->hwcap2; /* Secondary hwcap2 (index 1 of the bitmap) */
            pr_info("ksu: set_spoof_cpu updated elf_hwcap: 0x%lx, elf_hwcap2: 0x%lx\n", elf_hwcap_bitmap[0],
                    elf_hwcap_bitmap[1]);
        } else {
            pr_warn("ksu: set_spoof_cpu failed to resolve 'elf_hwcap'\n");
        }

        /* C. Erratum Reversal and Clock Mode Alignment (Clean Cores Only) */
        {
            unsigned int part = MIDR_PARTNUM(cmd->midr);
            if (part != ARM_CPU_PART_NEOVERSE_N1 && part != ARM_CPU_PART_CORTEX_A76 &&
                part != QCOM_CPU_PART_KRYO_4XX_GOLD) {
                /* Resolve 'vdso_data' double pointer and align clock mode */
                struct vdso_data **vdso_data_ptr = (struct vdso_data **)find_kernel_symbol_exact("vdso_data");
                if (vdso_data_ptr && *vdso_data_ptr) {
                    struct vdso_data *vdso = *vdso_data_ptr;
                    pr_info("ksu: set_spoof_cpu found 'vdso_data' (current CS_HRES_COARSE clock_mode: %d)\n",
                            vdso[CS_HRES_COARSE].clock_mode);
                    vdso[CS_HRES_COARSE].clock_mode = VDSO_CLOCKMODE_ARCHTIMER;
                    vdso[CS_RAW].clock_mode = VDSO_CLOCKMODE_ARCHTIMER;
                    pr_info("ksu: set_spoof_cpu updated 'vdso_data' clock_mode to %d\n",
                            vdso[CS_HRES_COARSE].clock_mode);
                } else {
                    pr_warn("ksu: set_spoof_cpu failed to resolve 'vdso_data'\n");
                }

                /* Resolve 'curr_clocksource' double pointer and overwrite active clock mode */
                {
                    struct clocksource **curr_cs_ptr =
                        (struct clocksource **)find_kernel_symbol_exact("curr_clocksource");
                    if (curr_cs_ptr && *curr_cs_ptr) {
                        struct clocksource *cs = *curr_cs_ptr;
                        pr_info("ksu: set_spoof_cpu found active clocksource '%s' (current vdso_clock_mode: %d)\n",
                                cs->name ? cs->name : "unknown", cs->vdso_clock_mode);
                        cs->vdso_clock_mode = VDSO_CLOCKMODE_ARCHTIMER;
                        pr_info("ksu: set_spoof_cpu updated clocksource '%s' vdso_clock_mode to %d\n",
                                cs->name ? cs->name : "unknown", cs->vdso_clock_mode);
                    } else {
                        pr_warn("ksu: set_spoof_cpu failed to resolve 'curr_clocksource'\n");
                    }
                }

                /* Overwrite fallback default clock mode variable */
                {
                    enum vdso_clock_mode *vd_default = (enum vdso_clock_mode *)find_kernel_symbol_exact("vdso_default");
                    if (vd_default) {
                        pr_info("ksu: set_spoof_cpu found 'vdso_default' (current value: %d)\n", *vd_default);
                        *vd_default = VDSO_CLOCKMODE_ARCHTIMER;
                        pr_info("ksu: set_spoof_cpu updated 'vdso_default' to %d\n", *vd_default);
                    } else {
                        pr_warn("ksu: set_spoof_cpu failed to resolve 'vdso_default'\n");
                    }
                }

                /* Resolve and clear capability bitmap (handles cpu_hwcaps / system_cpucaps fallback) */
                {
                    unsigned long *caps = (unsigned long *)find_kernel_symbol_exact("cpu_hwcaps");
                    if (!caps) {
                        caps = (unsigned long *)find_kernel_symbol_exact("system_cpucaps");
                    }
                    if (caps) {
                        pr_info("ksu: set_spoof_cpu current ARM64_WORKAROUND_1418040 capability state: %d\n",
                                test_bit(ARM64_WORKAROUND_1418040, caps));
                        clear_bit(ARM64_WORKAROUND_1418040, caps);
                        pr_info("ksu: set_spoof_cpu updated ARM64_WORKAROUND_1418040 capability state: %d\n",
                                test_bit(ARM64_WORKAROUND_1418040, caps));
                    } else {
                        pr_warn("ksu: set_spoof_cpu failed to resolve 'cpu_hwcaps' or 'system_cpucaps'\n");
                    }
                }
            }
        }
    }
#endif

    pr_info("KernelSU Stealth: CPU %u identity spoofed (MIDR: 0x%08x)\n", cmd->cpu_index, cmd->midr);
    return 0;
}
