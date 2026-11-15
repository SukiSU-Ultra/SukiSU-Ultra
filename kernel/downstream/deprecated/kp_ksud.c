// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

// sys_newfstat rp
// upstream: https://github.com/tiann/KernelSU/commit/df640917d11dd0eff1b34ea53ec3c0dc49667002

static int sys_newfstat_handler_pre(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);

	// grab ptr on entry
	uintptr_t *arg = (uintptr_t *)p->data;
	arg[0] = (uintptr_t)PT_REGS_SYSCALL_PARM1(real_regs); 
	arg[1] = (uintptr_t)PT_REGS_PARM2(real_regs); 

	return 0;
}

static int sys_newfstat_handler_post(struct kretprobe_instance *p, struct pt_regs *regs)
{
	uintptr_t *arg = (uintptr_t *)p->data;
	unsigned int fd = (unsigned int)arg[0];
	struct stat __user *statbuf = (struct stat __user *)arg[1];

	ksu_handle_newfstat_ret(&fd, &statbuf);

	return 0;
}

static struct kretprobe sys_newfstat_rp = {
	.kp.symbol_name = SYS_NEWFSTAT_SYMBOL,
	.entry_handler = sys_newfstat_handler_pre,
	.handler = sys_newfstat_handler_post,
	.data_size = sizeof(uintptr_t) * 2, // int + ptr, should fit
};

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
static int sys_fstat64_handler_pre(struct kretprobe_instance *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);

	// grab ptr on entry
	uintptr_t *arg = (uintptr_t *)p->data;
	arg[0] = (uintptr_t)PT_REGS_SYSCALL_PARM1(real_regs); 
	arg[1] = (uintptr_t)PT_REGS_PARM2(real_regs); 

	return 0;
}

static int sys_fstat64_handler_post(struct kretprobe_instance *p, struct pt_regs *regs)
{
	uintptr_t *arg = (uintptr_t *)p->data;
	unsigned long fd = (unsigned long)arg[0];
	struct stat64 __user *statbuf = (struct stat64 __user *)arg[1];

	ksu_handle_fstat64_ret(&fd, &statbuf);

	return 0;
}

static struct kretprobe sys_fstat64_rp = {
	.kp.symbol_name = SYS_FSTAT64_SYMBOL,
	.entry_handler = sys_fstat64_handler_pre,
	.handler = sys_fstat64_handler_post,
	.data_size = sizeof(uintptr_t) * 2, // long + ptr, should fit
};
#endif

// sys_reboot
static int sys_reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int *magic1 = (int *)&PT_REGS_SYSCALL_PARM1(real_regs); // ptr so we can mutate this
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	int cmd = (int)PT_REGS_PARM3(real_regs);
	void __user **arg = (void __user **)&PT_REGS_SYSCALL_PARM4(real_regs);

	if (*magic1 != KSU_INSTALL_MAGIC1)
		return 0;

	// HACK: flip preempt status inside kp
	// checking not really needed but its cool
	bool got_flipped = false;
	if (likely(!preemptible())) {
		preempt_enable();
		got_flipped = true;
	}

	ksu_handle_sys_reboot(*magic1, magic2, cmd, arg);

	if (got_flipped)
		preempt_disable();

	// to prevent double hooking
	*magic1 = 0;

	return 0;
}

static struct kprobe sys_reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = sys_reboot_handler_pre,
};

static int unregister_kprobe_function(void *data)
{
	set_user_nice(current, 19); // low prio

loop_start:

	msleep(1000);

	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;

	pr_info("kp_ksud: unregistering kprobes...\n");

	unregister_kretprobe(&sys_newfstat_rp);
	pr_info("kp_ksud: unregister sys_newfstat_rp!\n");

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
	unregister_kretprobe(&sys_fstat64_rp);
	pr_info("kp_ksud: unregister sys_fstat64_rp!\n");
#endif

	return 0;
}

static __init int kp_ksud_init()
{
	int ret = register_kprobe(&sys_reboot_kp); // dont unreg this one
	pr_info("kp_ksud: sys_reboot_kp: %d\n", ret);

	int ret2 = register_kretprobe(&sys_newfstat_rp);
	pr_info("kp_ksud: sys_newfstat_rp: %d\n", ret2);

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
	int ret3 = register_kretprobe(&sys_fstat64_rp);
	pr_info("kp_ksud: sys_fstat64_rp: %d\n", ret3);
#endif

	kthread_run(unregister_kprobe_function, NULL, "kp_unreg");
	return 0;
}
