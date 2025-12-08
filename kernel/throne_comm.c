#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/task_work.h>
#include <linux/version.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task.h>
#endif
#include <linux/pid.h>
#include <linux/version.h>

#include "klog.h"
#include "throne_comm.h"
#include "ksu.h"

#define PROC_UID_SCANNER "ksu_uid_scanner"
#define UID_SCANNER_STATE_FILE "/data/adb/ksu/.uid_scanner"

static struct proc_dir_entry *proc_entry = NULL;
static struct workqueue_struct *scanner_wq = NULL;
static struct work_struct scan_work;


// Signal userspace to rescan
static bool need_rescan = false;

static void rescan_work_fn(struct work_struct *work)
{
	// Signal userspace through proc interface
	need_rescan = true;
	pr_info("requested userspace uid rescan\n");
}

void ksu_request_userspace_scan(void)
{
	if (scanner_wq) {
		queue_work(scanner_wq, &scan_work);
	}
}

void ksu_handle_userspace_update(void)
{
	// Called when userspace notifies update complete
	need_rescan = false;
	pr_info("userspace uid list updated\n");
}

static void do_save_throne_state(struct callback_head *_cb)
{
	struct file *fp;
	char state_char = ksu_uid_scanner_enabled ? '1' : '0';
	loff_t off = 0;
	const struct cred *saved = override_creds(ksu_cred);

	fp = filp_open(UID_SCANNER_STATE_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(fp)) {
		pr_err("save_throne_state create file failed: %ld\n", PTR_ERR(fp));
		goto revert;
	}

	if (kernel_write(fp, &state_char, sizeof(state_char), &off) != sizeof(state_char)) {
		pr_err("save_throne_state write failed\n");
		goto close_file;
	}

	pr_info("throne state saved: %s\n", ksu_uid_scanner_enabled ? "enabled" : "disabled");

close_file:
	filp_close(fp, 0);
revert:
	revert_creds(saved);
	kfree(_cb);
}

static void do_load_throne_state(struct callback_head *_cb)
{
	struct file *fp;
	char state_char;
	loff_t off = 0;
	ssize_t ret;
	const struct cred *saved = override_creds(ksu_cred);

	fp = filp_open(UID_SCANNER_STATE_FILE, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_info("throne state file not found, using default: disabled\n");
		ksu_uid_scanner_enabled = false;
		goto revert;
	}

	ret = kernel_read(fp, &state_char, sizeof(state_char), &off);
	if (ret != sizeof(state_char)) {
		pr_err("load_throne_state read err: %zd\n", ret);
		ksu_uid_scanner_enabled = false;
		goto close_file;
	}

	ksu_uid_scanner_enabled = (state_char == '1');
	pr_info("throne state loaded: %s\n", ksu_uid_scanner_enabled ? "enabled" : "disabled");

close_file:
	filp_close(fp, 0);
revert:
	revert_creds(saved);
	kfree(_cb);
}

bool ksu_throne_comm_load_state(void)
{
	struct task_struct *tsk;
	struct callback_head *cb;

	tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
	if (!tsk) {
		pr_err("load_throne_state find init task err\n");
		return false;
	}

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb) {
		pr_err("load_throne_state alloc cb err\n");
		goto put_task;
	}
	cb->func = do_load_throne_state;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	task_work_add(tsk, cb, TWA_RESUME);
#else
	task_work_add(tsk, cb, true);
#endif

put_task:
	put_task_struct(tsk);
	return true;
}

void ksu_throne_comm_save_state(void)
{
	struct task_struct *tsk;
	struct callback_head *cb;

	tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
	if (!tsk) {
		pr_err("save_throne_state find init task err\n");
		return;
	}

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb) {
		pr_err("save_throne_state alloc cb err\n");
		goto put_task;
	}
	cb->func = do_save_throne_state;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	task_work_add(tsk, cb, TWA_RESUME);
#else
	task_work_add(tsk, cb, true);
#endif

put_task:
	put_task_struct(tsk);
}

static int uid_scanner_show(struct seq_file *m, void *v)
{
	if (need_rescan) {
		seq_puts(m, "RESCAN\n");
	} else {
		seq_puts(m, "OK\n");
	}
	return 0;
}

static int uid_scanner_open(struct inode *inode, struct file *file)
{
	return single_open(file, uid_scanner_show, NULL);
}

static ssize_t uid_scanner_write(struct file *file, const char __user *buffer, 
								 size_t count, loff_t *pos)
{
	char cmd[16];
	
	if (count >= sizeof(cmd))
		return -EINVAL;
		
	if (copy_from_user(cmd, buffer, count))
		return -EFAULT;
		
	cmd[count] = '\0';
	
	// Remove newline if present
	if (count > 0 && cmd[count-1] == '\n')
		cmd[count-1] = '\0';
	
	if (strcmp(cmd, "UPDATED") == 0) {
		ksu_handle_userspace_update();
		pr_info("received userspace update notification\n");
	}
	
	return count;
}

#ifdef KSU_COMPAT_HAS_PROC_OPS
static const struct proc_ops uid_scanner_proc_ops = {
	.proc_open = uid_scanner_open,
	.proc_read = seq_read,
	.proc_write = uid_scanner_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};
#else
static const struct file_operations uid_scanner_proc_ops = {
	.owner = THIS_MODULE,
	.open = uid_scanner_open,
	.read = seq_read,
	.write = uid_scanner_write,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

int ksu_throne_comm_init(void)
{
	// Create workqueue
	scanner_wq = alloc_workqueue("ksu_scanner", WQ_UNBOUND, 1);
	if (!scanner_wq) {
		pr_err("failed to create scanner workqueue\n");
		return -ENOMEM;
	}
	
	INIT_WORK(&scan_work, rescan_work_fn);
	
	// Create proc entry
	proc_entry = proc_create(PROC_UID_SCANNER, 0600, NULL, &uid_scanner_proc_ops);
	if (!proc_entry) {
		pr_err("failed to create proc entry\n");
		destroy_workqueue(scanner_wq);
		return -ENOMEM;
	}
	
	pr_info("throne communication initialized\n");
	return 0;
}

void ksu_throne_comm_exit(void)
{
	if (proc_entry) {
		proc_remove(proc_entry);
		proc_entry = NULL;
	}
	
	if (scanner_wq) {
		destroy_workqueue(scanner_wq);
		scanner_wq = NULL;
	}
	
	pr_info("throne communication cleaned up\n");
}

void ksu_uid_exit(void)
{
	struct task_struct *tsk;
	struct callback_head *cb;

	tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
	if (!tsk) {
		pr_err("save_throne_state find init task err\n");
		return;
	}

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb) {
		pr_err("save_throne_state alloc cb err\n");
		goto put_task;
	}
	cb->func = do_save_throne_state;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	task_work_add(tsk, cb, TWA_RESUME);
#else
	task_work_add(tsk, cb, true);
#endif

put_task:
	put_task_struct(tsk);
}
