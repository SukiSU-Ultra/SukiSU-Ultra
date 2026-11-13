// SPDX-License-Identifier: GPL-2.0
/*
 * CPU spoof extension. io-only: ops = NULL, no sticky enable bit.
 *
 * GET  -> supported=true, value=0 (handler presence is the signal).
 * SET  -> -EOPNOTSUPP (no sticky bit).
 * IO   -> MIDR/lpj/hwcap/vDSO rewrite via userspace ksu_set_spoof_cpu_cmd.
 *
 * Works on arm64 kernels from the 3.4/3.10 vendor trees through current.
 * The kernel interfaces this needs differ per release and are selected by
 * LINUX_VERSION_CODE below:
 *   - MIDR: per-CPU cpuinfo_arm64::reg_midr on 3.18+, the global
 *     processor_id on older trees.
 *   - BogoMIPS: loops_per_jiffy (all versions).
 *   - HWCAP: unsigned int on < 3.18, unsigned long on 3.18-5.1, a single
 *     unsigned long packing HWCAP/HWCAP2 on 5.2-5.19, and a two-word
 *     DECLARE_BITMAP on 6.0+.
 *   - vDSO/clock mode: only the erratum 1418040 workaround (5.7+) needs
 *     undoing; older kernels always use the arch timer fast path.
 *
 * Forced-by-config is not wired: a force_extension=cpu_spoof:N entry
 * is rejected with a dmesg warning and clears the forced-pending bit.
 * The default force semantics are not obvious (per-device MIDR).
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/jiffies.h>
#include <linux/delay.h>
#include <linux/clocksource.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/version.h>


#if defined(CONFIG_ARM64) || defined(__aarch64__)
#include <asm/cputype.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
#include <asm/cpu.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#include <asm/cpufeature.h>
#include <vdso/datapage.h>
#include <vdso/clocksource.h>
#endif

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

#endif

#if defined(CONFIG_ARM64) || defined(__aarch64__)
/*
 * The kernel-side HWCAP representation changed twice:
 *   - 3.10-3.17: single unsigned int (HWCAP only)
 *   - 3.18-5.1 : single unsigned long (HWCAP only)
 *   - 5.2-5.19 : single unsigned long, HWCAP in the low 32 bits and
 *                HWCAP2 in the high 32 bits
 *   - 6.0+     : DECLARE_BITMAP(elf_hwcap, MAX_CPU_FEATURES), i.e. two
 *                unsigned longs on arm64
 * Writing one layout into another would either clear HWCAP2 or corrupt
 * the word after elf_hwcap, so keep the layout decision in one place.
 */
static int spoof_elf_hwcap(u64 hwcap, u64 hwcap2)
{
	unsigned long addr = find_kernel_symbol_exact("elf_hwcap");

	if (!addr) {
		pr_warn("ksu: set_spoof_cpu failed to resolve 'elf_hwcap'\n");
		return -ENXIO;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	((unsigned long *)addr)[0] = (unsigned long)(u32)hwcap;
	((unsigned long *)addr)[1] = (unsigned long)(u32)hwcap2;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	*(unsigned long *)addr = (unsigned long)(u32)hwcap |
		((unsigned long)(u32)hwcap2 << 32);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	*(unsigned long *)addr = (unsigned long)(u32)hwcap;
#else
	*(unsigned int *)addr = (u32)hwcap;
#endif

	return 0;
}

/*
 * cpuinfo_arm64 and its per-CPU cpu_data appeared in 3.18. Older arm64
 * trees (3.7-3.17, mostly vendor backports) only keep the global
 * processor_id; /proc/cpuinfo there reads MIDR_EL1 directly, so this is
 * the best the kernel-side copy can do.
 */
static int spoof_cpu_midr(u32 cpu_index, u32 midr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
	unsigned long cpu_data_base = find_kernel_symbol_exact("cpu_data");
	struct cpuinfo_arm64 *info;

	if (!cpu_data_base) {
		pr_warn("ksu: set_spoof_cpu failed to resolve 'cpu_data'\n");
		return -ENXIO;
	}

	info = per_cpu_ptr((struct cpuinfo_arm64 *)cpu_data_base, cpu_index);
	if (!info) {
		pr_warn("ksu: set_spoof_cpu per_cpu_ptr failed for cpu_index %u\n",
				cpu_index);
		return -ENXIO;
	}
	info->reg_midr = midr;
#else
	unsigned long processor_id = find_kernel_symbol_exact("processor_id");

	if (!processor_id) {
		pr_warn("ksu: set_spoof_cpu failed to resolve 'processor_id'\n");
		return -ENXIO;
	}
	*(unsigned int *)processor_id = midr;
#endif

	return 0;
}
#endif /* CONFIG_ARM64 || __aarch64__ */

static int set_spoof_cpu(const struct ksu_set_spoof_cpu_cmd *cmd)
{
	int missing = 0;

	if (!cmd)
		return -EINVAL;

	if (cmd->cpu_index >= num_possible_cpus()) {
		pr_warn("ksu: set_spoof_cpu out-of-bounds cpu_index %u\n",
				cmd->cpu_index);
		return -EINVAL;
	}

#if !defined(CONFIG_ARM64) && !defined(__aarch64__)
	/*
	 * MIDR, loops_per_jiffy and the arm64 ELF hwcaps have no arm32
	 * counterpart here; refuse instead of reporting a spoof that never
	 * happened.
	 */
	pr_warn("ksu: set_spoof_cpu is only supported on arm64\n");
	return -EOPNOTSUPP;
#else
	if (spoof_cpu_midr(cmd->cpu_index, cmd->midr))
		++missing;

	if (cmd->cpu_index == 0) {
		unsigned long *lpj =
			(unsigned long *)find_kernel_symbol_exact("loops_per_jiffy");

		if (lpj) {
			*lpj = ((unsigned long)cmd->bogomips * 500000) / (100 * HZ);
		} else {
			pr_warn("ksu: set_spoof_cpu failed to resolve 'loops_per_jiffy'\n");
			++missing;
		}

		if (spoof_elf_hwcap(cmd->hwcap, cmd->hwcap2))
			++missing;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
		/*
		 * Only kernels with the erratum 1418040 workaround can have
		 * switched the vDSO to the syscall fallback; everything older
		 * always uses the arch timer fast path, so there is nothing
		 * to undo there.
		 */
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
				} else {
					pr_warn("ksu: set_spoof_cpu failed to resolve vDSO time data\n");
					++missing;
				}
#else
				struct vdso_data **vdso_data_ptr =
					(struct vdso_data **)find_kernel_symbol_exact("vdso_data");
				if (vdso_data_ptr && *vdso_data_ptr) {
					struct vdso_data *vdso = *vdso_data_ptr;
					vdso[CS_HRES_COARSE].clock_mode =
						VDSO_CLOCKMODE_ARCHTIMER;
					vdso[CS_RAW].clock_mode = VDSO_CLOCKMODE_ARCHTIMER;
				} else {
					pr_warn("ksu: set_spoof_cpu failed to resolve 'vdso_data'\n");
					++missing;
				}
#endif

				{
					struct clocksource **curr_cs_ptr =
						(struct clocksource **)find_kernel_symbol_exact(
							"curr_clocksource");
					if (curr_cs_ptr && *curr_cs_ptr) {
						(*curr_cs_ptr)->vdso_clock_mode =
							VDSO_CLOCKMODE_ARCHTIMER;
					} else {
						pr_warn("ksu: set_spoof_cpu failed to resolve 'curr_clocksource'\n");
						++missing;
					}
				}

				{
					enum vdso_clock_mode *vd_default =
						(enum vdso_clock_mode *)find_kernel_symbol_exact(
							"vdso_default");
					if (vd_default) {
						*vd_default = VDSO_CLOCKMODE_ARCHTIMER;
					} else {
						pr_warn("ksu: set_spoof_cpu failed to resolve 'vdso_default'\n");
						++missing;
					}
				}

				{
					unsigned long *caps =
						(unsigned long *)find_kernel_symbol_exact("cpu_hwcaps");
					if (!caps)
						caps = (unsigned long *)find_kernel_symbol_exact(
							"system_cpucaps");
					if (caps) {
#ifdef ARM64_WORKAROUND_1418040
						clear_bit(ARM64_WORKAROUND_1418040, caps);
#endif
					} else {
						pr_warn("ksu: set_spoof_cpu failed to resolve 'cpu_hwcaps' / 'system_cpucaps'\n");
						++missing;
					}
				}
			}
		}
#endif /* >= 5.7 */
	}
#endif

	/*
	 * If any of the kallsyms lookups failed, refuse to claim success.
	 * Previously the function silently returned 0 even when none of
	 * the writes had taken effect, which made callers (and users)
	 * think CPU spoof was active when only partial — or no —
	 * rewrites had happened. -ENXIO distinguishes "subsystem
	 * missing on this build" from a generic -EINVAL.
	 */
	if (missing) {
		pr_warn("ksu: set_spoof_cpu for cpu %u incomplete (%d symbol(s) unresolved)\n",
				cmd->cpu_index, missing);
		return -ENXIO;
	}

	pr_info("KernelSU Stealth: CPU %u identity spoofed (MIDR: 0x%08x)\n",
			cmd->cpu_index, cmd->midr);
	return 0;
}

int ksu_extension_cpu_spoof_io(u32 id, void __user *raw)
{
	struct ksu_set_spoof_cpu_cmd cmd;

	if (copy_from_user(&cmd, raw, sizeof(cmd)))
		return -EFAULT;

	return set_spoof_cpu(&cmd);
}
