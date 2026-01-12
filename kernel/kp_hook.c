#include <linux/kprobes.h>
#include <linux/compat.h>
#include <linux/workqueue.h>

#define DECL_KP(name, sym, pre)                                                \
	struct kprobe name = {                                                 \
		.symbol_name = sym,                                            \
		.pre_handler = pre,                                            \
	}

#define DECL_KRP(name, sym, ent, han)                                                \
	struct kretprobe name = {                                                 \
		.kp.symbol_name = sym,                                            \
		.entry_handler = ent,                                            \
		.handler = han,                                            \
		.data_size = sizeof(void *),                             \
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
	return ksu_handle_execveat_ksud((int *)AT_FDCWD, &filename_p, &argv,
					NULL, NULL);
}

static int sys_read_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	unsigned int fd = PT_REGS_PARM1(real_regs);
	ksu_handle_sys_read(fd);
	return 0;
}

static int sys_fstat_handler_pre(struct kretprobe_instance *p,
					struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	unsigned int fd = PT_REGS_PARM1(real_regs);
	void *statbuf = PT_REGS_PARM2(real_regs);
	*(void **)&p->data = NULL;

	struct file *file = fget(fd);
	if (!file)
		return 1;
	if (is_init_rc(file)) {
		pr_info("stat init.rc");
		fput(file);
		*(void **)&p->data = statbuf;
		return 0;
	}
	fput(file);
	return 1;
}

static int sys_fstat_handler_post(struct kretprobe_instance *p,
					struct pt_regs *regs)
{
	void __user *statbuf = *(void **)&p->data;
	if (statbuf) {
		void __user *st_size_ptr = statbuf + offsetof(struct stat, st_size);
		long size, new_size;
		if (!copy_from_user_nofault(&size, st_size_ptr, sizeof(long))) {
			new_size = size + ksu_rc_len;
			pr_info("adding ksu_rc_len: %ld -> %ld", size, new_size);
			if (!copy_to_user_nofault(st_size_ptr, &new_size, sizeof(long))) {
				pr_info("added ksu_rc_len");
			} else {
				pr_err("add ksu_rc_len failed: statbuf 0x%lx",
					(unsigned long)st_size_ptr);
			}
		} else {
			pr_err("read statbuf 0x%lx failed", (unsigned long)st_size_ptr);
		}
	}

	return 0;
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
static DECL_KP(sys_read_kp, SYS_READ_SYMBOL, sys_read_handler_pre);
static DECL_KRP(sys_fstat_kp, SYS_FSTAT_SYMBOL, sys_fstat_handler_pre, sys_fstat_handler_post);
static DECL_KP(input_event_kp, "input_event", input_handle_event_handler_pre);

static void do_stop_init_rc_hook(struct work_struct *work)
{
	unregister_kprobe(&sys_read_kp);
	unregister_kretprobe(&sys_fstat_kp);
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
	case INIT_RC_HOOK_KP: {
		ret = schedule_work(&stop_init_rc_hook_work);
		pr_info("unregister init_rc_hook kprobe: %d!\n", ret);
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

	ret = register_kprobe(&sys_read_kp);
	pr_info("ksud: sys_read_kp: %d\n", ret);

	ret = register_kretprobe(&sys_fstat_kp);
	pr_info("ksud: sys_fstat_kp: %d\n", ret);

	ret = register_kprobe(&input_event_kp);
	pr_info("ksud: input_event_kp: %d\n", ret);

	INIT_WORK(&stop_init_rc_hook_work, do_stop_init_rc_hook);
	INIT_WORK(&stop_execve_hook_work, do_stop_execve_hook);
	INIT_WORK(&stop_input_hook_work, do_stop_input_hook);
}

void kp_handle_ksud_exit(void)
{
	unregister_kprobe(&execve_kp);
	// this should be done before unregister sys_read_kp
	// unregister_kprobe(&sys_read_kp);
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
	void __user **arg = (void __user **)&PT_REGS_SYSCALL_PARM4(real_regs);

	// cmd is not really used here, so we NULL!
	return ksu_handle_sys_reboot(magic1, magic2, NULL, arg);
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
