#include <linux/version.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include <linux/pid.h>
#include <linux/resource.h>
#include <linux/rcupdate.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
#include <linux/file.h>
#endif
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"

extern struct task_struct init_task;

// mnt_ns context switch for environment that android_init->nsproxy->mnt_ns != init_task.nsproxy->mnt_ns, such as WSA
struct ksu_ns_fs_saved {
	struct nsproxy *ns;
	struct fs_struct *fs;
};

static void ksu_save_ns_fs(struct ksu_ns_fs_saved *ns_fs_saved)
{
	ns_fs_saved->ns = current->nsproxy;
	ns_fs_saved->fs = current->fs;
}

static void ksu_load_ns_fs(struct ksu_ns_fs_saved *ns_fs_saved)
{
	current->nsproxy = ns_fs_saved->ns;
	current->fs = ns_fs_saved->fs;
}

static bool android_context_saved_checked = false;
static bool android_context_saved_enabled = false;
static struct ksu_ns_fs_saved android_context_saved;

void ksu_android_ns_fs_check()
{
	if (android_context_saved_checked)
		return;
	android_context_saved_checked = true;
	task_lock(current);
	if (current->nsproxy && current->fs &&
		current->nsproxy->mnt_ns != init_task.nsproxy->mnt_ns) {
		android_context_saved_enabled = true;
#ifdef CONFIG_KSU_DEBUG
		pr_info("android context saved enabled due to init mnt_ns(%p) != android mnt_ns(%p)\n",
			current->nsproxy->mnt_ns, init_task.nsproxy->mnt_ns);
#endif
		ksu_save_ns_fs(&android_context_saved);
	} else {
		pr_info("android context saved disabled\n");
	}
	task_unlock(current);
}

struct file *ksu_filp_open_compat(const char *filename, int flags, umode_t mode)
{
	// switch mnt_ns even if current is not wq_worker, to ensure what we open is the correct file in android mnt_ns, rather than user created mnt_ns
	struct ksu_ns_fs_saved saved;
	if (android_context_saved_enabled) {
#ifdef CONFIG_KSU_DEBUG
		pr_info("start switch current nsproxy and fs to android context\n");
#endif
		task_lock(current);
		ksu_save_ns_fs(&saved);
		ksu_load_ns_fs(&android_context_saved);
		task_unlock(current);
	}
	struct file *fp = filp_open(filename, flags, mode);
	if (android_context_saved_enabled) {
		task_lock(current);
		ksu_load_ns_fs(&saved);
		task_unlock(current);
#ifdef CONFIG_KSU_DEBUG
		pr_info("switch current nsproxy and fs back to saved successfully\n");
#endif
	}
	return fp;
}

ssize_t ksu_kernel_read_compat(struct file *p, void *buf, size_t count,
				   loff_t *pos)
{
	return kernel_read(p, buf, count, pos);
}

ssize_t ksu_kernel_write_compat(struct file *p, const void *buf, size_t count,
				loff_t *pos)
{
	return kernel_write(p, buf, count, pos);
}

long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
				   long count)
{
	return strncpy_from_user_nofault(dst, unsafe_addr, count);
}

// Helper function to get task_struct from pid
struct task_struct *ksu_get_target_task(pid_t pid)
{
	struct pid *pid_struct = find_get_pid(pid);
	if (!pid_struct) {
		return NULL;
	}

	// Note: get_pid_task increments the task_struct refcount
	struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task) {
		return NULL;
	}

	return task;
}

// Helper function to get unused fd from target task
int ksu_get_task_unused_fd_flags(struct task_struct *task, unsigned flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
	if (task != current) {
		pr_err("ksu: cross-task fd allocation not supported\n");
		return -EINVAL;
	}
	return get_unused_fd_flags(flags);
#else
	struct files_struct *files = task->files;
	struct fdtable *fdt;
	unsigned int fd, max_fd;
	int error = -EMFILE;

	if (task != current) {
		pr_err("ksu: cross-task fd allocation not supported\n");
		return -EINVAL;
	}
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	max_fd = fdt->max_fds;
	for (fd = 0; fd < max_fd; fd++) {
		if (!test_bit(fd, fdt->open_fds)) {
			__set_open_fd(fd, fdt);
			if (flags & O_CLOEXEC)
				__set_close_on_exec(fd, fdt);
			else
				__clear_close_on_exec(fd, fdt);
			error = fd;
			break;
		}
	}
	spin_unlock(&files->file_lock);
	if (error < 0)
		pr_err("ksu: failed to allocate fd (max=%u)\n", max_fd);
	return error;
#endif
}

// Helper function to install fd to target task
int ksu_install_fd_to_task(struct task_struct *task, int fd, struct file *file)
{
	if (task != current) {
		pr_err("ksu: cross-task fd install not supported\n");
		return -EINVAL;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
	fd_install(fd, file);
#else
	struct files_struct *files = task->files;
	struct fdtable *fdt;

	rcu_read_lock_sched();

	if (unlikely(files->resize_in_progress)) {
		rcu_read_unlock_sched();
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);

		rcu_assign_pointer(fdt->fd[fd], file);

		spin_unlock(&files->file_lock);
		return 0;
	}
	/* coupled with smp_wmb() in expand_fdtable() */
	smp_rmb();
	fdt = rcu_dereference_sched(files->fdt);
	rcu_assign_pointer(fdt->fd[fd], file);
	rcu_read_unlock_sched();
#endif
	return 0;
}
