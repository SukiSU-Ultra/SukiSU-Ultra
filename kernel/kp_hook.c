#include <linux/kprobes.h>
#include <linux/compat.h>
#include <linux/workqueue.h>

#include "arch.h"
#include "kp_hook.h"
#include "ksu.h"
#include "ksud.h"
#include "kernel_compat.h"
#include "supercalls.h"
#include "kp_util.h"

#define DECL_KP(name, sym, pre)												\
	struct kprobe name = {												 \
		.symbol_name = sym,											\
		.pre_handler = pre,											\
	}

// ksud.c

static struct work_struct stop_vfs_read_work, stop_execve_hook_work,
	stop_input_hook_work;

#ifndef CONFIG_KSU_SUSFS
static int sys_execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	const char __user **filename_user =
		(const char **)&PT_REGS_PARM1(real_regs);
	const char __user *const __user *__argv =
		(const char __user *const __user *)PT_REGS_PARM2(real_regs);
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct filename filename_in, *filename_p;
	char path[32];

	if (!filename_user)
		return 0;
	if (!ksu_retry_filename_access(filename_user, path, 32, false))
		return 0;

	filename_in.name = path;
	filename_p = &filename_in;
	return ksu_handle_execveat_ksud(AT_FDCWD, &filename_p, &argv, NULL,
					NULL);
}

static int sys_read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	unsigned int fd = PT_REGS_PARM1(real_regs);
	char __user **buf_ptr = (char __user **)&PT_REGS_PARM2(real_regs);
	size_t count_ptr = (size_t *)&PT_REGS_PARM3(real_regs);

	return ksu_handle_sys_read(fd, buf_ptr, count_ptr);
}

static int input_handle_event_handler_pre(struct kprobe *p,
					  struct pt_regs *regs)
{
	unsigned int *type = (unsigned int *)&PT_REGS_PARM2(regs);
	unsigned int *code = (unsigned int *)&PT_REGS_PARM3(regs);
	int *value = (int *)&PT_REGS_CCALL_PARM4(regs);
	return ksu_handle_input_handle_event(type, code, value);
}

static DECL_KP(execve_kp, SYS_EXECVE_SYMBOL, sys_execve_handler_pre);
static DECL_KP(vfs_read_kp, SYS_READ_SYMBOL, sys_read_handler_pre);
static DECL_KP(input_event_kp, "input_event", input_handle_event_handler_pre);

static void do_stop_vfs_read_hook(struct work_struct *work)
{
	unregister_kprobe(&vfs_read_kp);
}

static void do_stop_execve_hook(struct work_struct *work)
{
	unregister_kprobe(&execve_kp);
}

static void do_stop_input_hook(struct work_struct *work)
{
	unregister_kprobe(&input_event_kp);
}
#endif // #ifndef CONFIG_KSU_SUSFS

void kp_handle_ksud_stop(enum ksud_stop_code stop_code)
{
	bool ret;
	switch (stop_code) {
	case VFS_READ_HOOK_KP: {
		ret = schedule_work(&stop_vfs_read_work);
		pr_info("unregister vfs_read kprobe: %d!\n", ret);
		break;
	}
	case EXECVE_HOOK_KP: {
		ret = schedule_work(&stop_execve_hook_work);
		pr_info("unregister execve kprobe: %d!\n", ret);
		break;
	}
	case INPUT_EVENT_HOOK_KP: {
		static bool input_hook_stopped = false;
		if (input_hook_stopped) {
			return;
		}
		input_hook_stopped = true;
		ret = schedule_work(&stop_input_hook_work);
		pr_info("unregister input kprobe: %d!\n", ret);
		break;
	}
	default:
		return;
	}
	return;
}

void kp_handle_ksud_init(void)
{
	int ret;

	ret = register_kprobe(&execve_kp);
	pr_info("ksud: execve_kp: %d\n", ret);

	ret = register_kprobe(&vfs_read_kp);
	pr_info("ksud: vfs_read_kp: %d\n", ret);

	ret = register_kprobe(&input_event_kp);
	pr_info("ksud: input_event_kp: %d\n", ret);

	INIT_WORK(&stop_vfs_read_work, do_stop_vfs_read_hook);
	INIT_WORK(&stop_execve_hook_work, do_stop_execve_hook);
	INIT_WORK(&stop_input_hook_work, do_stop_input_hook);
}

void kp_handle_ksud_exit(void)
{
	unregister_kprobe(&execve_kp);
	// this should be done before unregister vfs_read_kp
	// unregister_kprobe(&vfs_read_kp);
	unregister_kprobe(&input_event_kp);
}

// supercalls.c

extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
				 void __user **arg);

static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	int cmd = (int)PT_REGS_PARM3(real_regs);
	void __user **arg = (void __user **)&PT_REGS_SYSCALL_PARM4(real_regs);

	return ksu_handle_sys_reboot(magic1, magic2, cmd, arg);
}

static DECL_KP(reboot_kp, REBOOT_SYMBOL, reboot_handler_pre);

void kp_handle_supercalls_init(void)
{
	int rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("reboot kprobe failed: %d\n", rc);
		return;
	}
	pr_info("reboot kprobe registered successfully\n");
}

void kp_handle_supercalls_exit(void)
{
	unregister_kprobe(&reboot_kp);
}
