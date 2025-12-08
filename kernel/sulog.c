#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task.h>
#endif
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

#include "sulog.h"
#include "klog.h"
#include "kernel_compat.h"
#include "ksu.h"
#include "feature.h"

#if __SULOG_GATE

struct dedup_entry dedup_tbl[SULOG_COMM_LEN];
static DEFINE_SPINLOCK(dedup_lock);
static LIST_HEAD(sulog_queue);
static bool sulog_enabled __read_mostly = true;

static int sulog_feature_get(u64 *value)
{
	*value = sulog_enabled ? 1 : 0;
	return 0;
}

static int sulog_feature_set(u64 value)
{
	bool enable = value != 0;
	sulog_enabled = enable;
	pr_info("sulog: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler sulog_handler = {
	.feature_id = KSU_FEATURE_SULOG,
	.name = "sulog",
	.get_handler = sulog_feature_get,
	.set_handler = sulog_feature_set,
};

static void get_timestamp(char *buf, size_t len)
{
	struct timespec64 ts;
	struct tm tm;

	ktime_get_real_ts64(&ts);
	time64_to_tm(ts.tv_sec - sys_tz.tz_minuteswest * 60, 0, &tm);

	snprintf(buf, len, "%04ld-%02d-%02d %02d:%02d:%02d",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void ksu_get_cmdline(char *full_comm, const char *comm, size_t buf_len)
{
	if (!full_comm || buf_len <= 0)
		return;

	if (comm && strlen(comm) > 0) {
		KSU_STRSCPY(full_comm, comm, buf_len);
		return;
	}

	if (in_atomic() || in_interrupt() || irqs_disabled()) {
		KSU_STRSCPY(full_comm, current->comm, buf_len);
		return;
	}

	if (!current->mm) {
		KSU_STRSCPY(full_comm, current->comm, buf_len);
		return;
	}

	int n = get_cmdline(current, full_comm, buf_len);
	if (n <= 0) {
		KSU_STRSCPY(full_comm, current->comm, buf_len);
		return;
	}

	for (int i = 0; i < n && i < buf_len - 1; i++) {
		if (full_comm[i] == '\0')
			full_comm[i] = ' ';
	}
	full_comm[n < buf_len ? n : buf_len - 1] = '\0';
}

static void sanitize_string(char *str, size_t len)
{
	if (!str || len == 0)
		return;
	
	size_t read_pos = 0, write_pos = 0;
	
	while (read_pos < len && str[read_pos] != '\0') {
		char c = str[read_pos];
		
		if (c == '\n' || c == '\r') {
			read_pos++;
			continue;
		}
		
		if (c == ' ' && write_pos > 0 && str[write_pos - 1] == ' ') {
			read_pos++;
			continue;
		}
		
		str[write_pos++] = c;
		read_pos++;
	}
	
	str[write_pos] = '\0';
}

static bool dedup_should_print(uid_t uid, u8 type, const char *content, size_t len)
{
	struct dedup_key key = {
		.crc = dedup_calc_hash(content, len),
		.uid = uid,
		.type = type,
	};
	u64 now = ktime_get_ns();
	u64 delta_ns = DEDUP_SECS * NSEC_PER_SEC;

	u32 idx = key.crc & (SULOG_COMM_LEN - 1);
	spin_lock(&dedup_lock);

	struct dedup_entry *e = &dedup_tbl[idx];
	if (e->key.crc == key.crc &&
		e->key.uid == key.uid &&
		e->key.type == key.type &&
		(now - e->ts_ns) < delta_ns) {
		spin_unlock(&dedup_lock);
		return false;
	}

	e->key = key;
	e->ts_ns = now;
	spin_unlock(&dedup_lock);
	return true;
}

static void sulog_process_queue(void)
{
	struct file *fp;
	struct sulog_entry *entry, *tmp;
	LIST_HEAD(local_queue);
	loff_t pos = 0;
	unsigned long flags;
	const struct cred *old_cred;

	spin_lock_irqsave(&dedup_lock, flags);
	list_splice_init(&sulog_queue, &local_queue);
	spin_unlock_irqrestore(&dedup_lock, flags);

	if (list_empty(&local_queue))
		return;

	old_cred = override_creds(ksu_cred);

	fp = ksu_filp_open_compat(SULOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0640);
	if (IS_ERR(fp)) {
		pr_err("sulog: failed to open log file: %ld\n", PTR_ERR(fp));
		goto revert_creds_out;
	}

	if (fp->f_inode->i_size > SULOG_MAX_SIZE) {
		if (vfs_truncate(&fp->f_path, 0))
			pr_err("sulog: failed to truncate log file\n");
		pos = 0;
	} else {
		pos = fp->f_inode->i_size;
	}

	list_for_each_entry(entry, &local_queue, list)
		ksu_kernel_write_compat(fp, entry->content, strlen(entry->content), &pos);

	vfs_fsync(fp, 0);
	filp_close(fp, 0);

revert_creds_out:
	revert_creds(old_cred);

	list_for_each_entry_safe(entry, tmp, &local_queue, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static void sulog_task_work_handler(struct callback_head *work)
{
	sulog_process_queue();
	kfree(work);
}

static void sulog_schedule_task_work(void)
{
	struct task_struct *tsk;
	struct callback_head *cb;
	int ret;

	tsk = get_pid_task(find_vpid(1), PIDTYPE_PID);
	if (!tsk) {
		pr_err("sulog: failed to find init task\n");
		return;
	}

	cb = kzalloc(sizeof(*cb), GFP_ATOMIC);
	if (!cb) {
		pr_err("sulog: failed to allocate task_work callback\n");
		goto put_task;
	}

	cb->func = sulog_task_work_handler;

	ret = task_work_add(tsk, cb, TWA_RESUME);
	if (ret) {
		pr_err("sulog: failed to queue task work: %d\n", ret);
		kfree(cb);
	}

put_task:
	put_task_struct(tsk);
}

static void sulog_add_entry(char *log_buf, size_t len, uid_t uid, u8 dedup_type)
{
	struct sulog_entry *entry;
	unsigned long flags;

	if (!sulog_enabled || !log_buf || len == 0)
		return;

	if (!dedup_should_print(uid, dedup_type, log_buf, len))
		return;

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return;

	KSU_STRSCPY(entry->content, log_buf, SULOG_ENTRY_MAX_LEN);

	spin_lock_irqsave(&dedup_lock, flags);
	list_add_tail(&entry->list, &sulog_queue);
	spin_unlock_irqrestore(&dedup_lock, flags);

	sulog_schedule_task_work();
}

void ksu_sulog_report_su_grant(uid_t uid, const char *comm, const char *method)
{
	char log_buf[SULOG_ENTRY_MAX_LEN];
	char timestamp[32];
	char full_comm[SULOG_COMM_LEN];

	if (!sulog_enabled)
		return;

	get_timestamp(timestamp, sizeof(timestamp));
	ksu_get_cmdline(full_comm, comm, sizeof(full_comm));
	
	sanitize_string(full_comm, sizeof(full_comm));

	snprintf(log_buf, sizeof(log_buf),
		"[%s] SU_GRANT: UID=%d COMM=%s METHOD=%s PID=%d\n",
		timestamp, uid, full_comm, method ? method : "unknown", current->pid);

	sulog_add_entry(log_buf, strlen(log_buf), uid, DEDUP_SU_GRANT);
}

void ksu_sulog_report_su_attempt(uid_t uid, const char *comm, const char *target_path, bool success)
{
	char log_buf[SULOG_ENTRY_MAX_LEN];
	char timestamp[32];
	char full_comm[SULOG_COMM_LEN];

	if (!sulog_enabled)
		return;

	get_timestamp(timestamp, sizeof(timestamp));
	ksu_get_cmdline(full_comm, comm, sizeof(full_comm));
	
	sanitize_string(full_comm, sizeof(full_comm));

	snprintf(log_buf, sizeof(log_buf),
		"[%s] SU_EXEC: UID=%d COMM=%s TARGET=%s RESULT=%s PID=%d\n",
		timestamp, uid, full_comm, target_path ? target_path : "unknown",
		success ? "SUCCESS" : "DENIED", current->pid);

	sulog_add_entry(log_buf, strlen(log_buf), uid, DEDUP_SU_ATTEMPT);
}

void ksu_sulog_report_permission_check(uid_t uid, const char *comm, bool allowed)
{
	char log_buf[SULOG_ENTRY_MAX_LEN];
	char timestamp[32];
	char full_comm[SULOG_COMM_LEN];

	if (!sulog_enabled)
		return;

	get_timestamp(timestamp, sizeof(timestamp));
	ksu_get_cmdline(full_comm, comm, sizeof(full_comm));
	
	sanitize_string(full_comm, sizeof(full_comm));

	snprintf(log_buf, sizeof(log_buf),
		"[%s] PERM_CHECK: UID=%d COMM=%s RESULT=%s PID=%d\n",
		timestamp, uid, full_comm, allowed ? "ALLOWED" : "DENIED", current->pid);

	sulog_add_entry(log_buf, strlen(log_buf), uid, DEDUP_PERM_CHECK);
}

void ksu_sulog_report_manager_operation(const char *operation, uid_t manager_uid, uid_t target_uid)
{
	char log_buf[SULOG_ENTRY_MAX_LEN];
	char timestamp[32];
	char full_comm[SULOG_COMM_LEN];

	if (!sulog_enabled)
		return;

	get_timestamp(timestamp, sizeof(timestamp));
	ksu_get_cmdline(full_comm, NULL, sizeof(full_comm));
	
	sanitize_string(full_comm, sizeof(full_comm));

	snprintf(log_buf, sizeof(log_buf),
		"[%s] MANAGER_OP: OP=%s MANAGER_UID=%d TARGET_UID=%d COMM=%s PID=%d\n",
		timestamp, operation ? operation : "unknown", manager_uid, target_uid, full_comm, current->pid);

	sulog_add_entry(log_buf, strlen(log_buf), manager_uid, DEDUP_MANAGER_OP);
}

void ksu_sulog_report_syscall(uid_t uid, const char *comm, const char *syscall, const char *args)
{
	char log_buf[SULOG_ENTRY_MAX_LEN];
	char timestamp[32];
	char full_comm[SULOG_COMM_LEN];

	if (!sulog_enabled)
		return;

	get_timestamp(timestamp, sizeof(timestamp));
	ksu_get_cmdline(full_comm, comm, sizeof(full_comm));
	
	sanitize_string(full_comm, sizeof(full_comm));

	snprintf(log_buf, sizeof(log_buf),
		"[%s] SYSCALL: UID=%d COMM=%s SYSCALL=%s ARGS=%s PID=%d\n",
		timestamp, uid, full_comm, syscall ? syscall : "unknown",
		args ? args : "none", current->pid);

	sulog_add_entry(log_buf, strlen(log_buf), uid, DEDUP_SYSCALL);
}

int ksu_sulog_init(void)
{
	if (ksu_register_feature_handler(&sulog_handler)) {
		pr_err("Failed to register sulog feature handler\n");
	}

	pr_info("sulog: initialized successfully\n");
	return 0;
}

void ksu_sulog_exit(void)
{
	struct sulog_entry *entry, *tmp;
	unsigned long flags;

	ksu_unregister_feature_handler(KSU_FEATURE_SULOG);

	sulog_enabled = false;

	sulog_process_queue();

	spin_lock_irqsave(&dedup_lock, flags);
	list_for_each_entry_safe(entry, tmp, &sulog_queue, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	spin_unlock_irqrestore(&dedup_lock, flags);

	pr_info("sulog: cleaned up successfully\n");
}

#endif // __SULOG_GATE