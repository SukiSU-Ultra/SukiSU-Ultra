#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/crc32.h>

#include "klog.h"
#include "kernel_compat.h"
#include "sulog.h"
#include "ksu.h"

#define SULOG_PATH "/data/adb/ksu/log/sulog.log"
#define SULOG_OLD_PATH "/data/adb/ksu/log/sulog.log.old"
#define SULOG_MAX_SIZE (128 * 1024 * 1024) // 128MB
#define SULOG_ENTRY_MAX_LEN 512
#define SULOG_COMM_LEN 256
#define DEDUP_ENTRIES  256
#define DEDUP_SECS     10

struct dedup_key {
    u32     crc;
    uid_t   uid;
    u8      type;
    u8      _pad[1];
};

struct dedup_entry {
    struct dedup_key key;
    u64     ts_ns;
};

static struct dedup_entry dedup_tbl[DEDUP_ENTRIES];
static DEFINE_SPINLOCK(dedup_lock);

enum {
    DEDUP_SU_GRANT = 0,
    DEDUP_SU_ATTEMPT,
    DEDUP_PERM_CHECK,
    DEDUP_MANAGER_OP,
    DEDUP_SYSCALL,
};

static inline u32 dedup_calc_hash(const char *content, size_t len)
{
    return crc32(0, content, len);
}

struct sulog_entry {
	struct list_head list;
	char content[SULOG_ENTRY_MAX_LEN];
};

static LIST_HEAD(sulog_queue);
static DEFINE_MUTEX(sulog_mutex);
static struct workqueue_struct *sulog_workqueue;
static struct work_struct sulog_work;
static bool sulog_enabled = true;

extern struct timezone sys_tz;

static void get_timestamp(char *buf, size_t len)
{
	struct timespec64 ts;
	struct tm tm;

	ktime_get_real_ts64(&ts);

	time64_to_tm(ts.tv_sec - sys_tz.tz_minuteswest * 60, 0, &tm);

	snprintf(buf, len,
		 "%04ld-%02d-%02d %02d:%02d:%02d",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		 tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void get_full_comm(char *comm_buf, size_t buf_len)
{
	struct mm_struct *mm;
	char *cmdline = NULL;
	unsigned long arg_start, arg_end;
	int len;
	
	mm = get_task_mm(current);
	if (mm) {
		arg_start = mm->arg_start;
		arg_end = mm->arg_end;
		
		if (arg_end > arg_start) {
			len = arg_end - arg_start;
			if (len > 0 && len < buf_len) {
				cmdline = kmalloc(len + 1, GFP_ATOMIC);
				if (cmdline) {
					if (ksu_copy_from_user_retry(cmdline, (void __user *)arg_start, len) == 0) {
						cmdline[len] = '\0';
						char *space = strchr(cmdline, ' ');
						if (space) *space = '\0';
						
						char *slash = strrchr(cmdline, '/');
						if (slash && *(slash + 1)) {
							strncpy(comm_buf, slash + 1, buf_len - 1);
						} else {
							strncpy(comm_buf, cmdline, buf_len - 1);
						}
						comm_buf[buf_len - 1] = '\0';
						kfree(cmdline);
						mmput(mm);
						return;
					}
					kfree(cmdline);
				}
			}
		}
		mmput(mm);
	}
	
	strncpy(comm_buf, current->comm, buf_len - 1);
	comm_buf[buf_len - 1] = '\0';
}

static bool dedup_should_print(uid_t uid, u8 type,
                               const char *content, size_t len)
{
    struct dedup_key key = {
        .crc  = dedup_calc_hash(content, len),
        .uid  = uid,
        .type = type,
    };
    u64 now = ktime_get_ns();
    u64 delta_ns = DEDUP_SECS * NSEC_PER_SEC;

    u32 idx = key.crc & (DEDUP_ENTRIES - 1);
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

static void sulog_work_handler(struct work_struct *work)
{
	struct file *fp;
	struct sulog_entry *entry, *tmp;
	LIST_HEAD(local_queue);
	loff_t pos = 0;
	
	mutex_lock(&sulog_mutex);
	list_splice_init(&sulog_queue, &local_queue);
	mutex_unlock(&sulog_mutex);
	
	if (list_empty(&local_queue))
		return;
	
	fp = ksu_filp_open_compat(SULOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0640);
	if (IS_ERR(fp)) {
		pr_err("sulog: failed to open log file: %ld\n", PTR_ERR(fp));
		goto cleanup;
	}
	
	if (fp->f_inode->i_size > SULOG_MAX_SIZE) {
		pr_info("sulog: rotating log file, size: %lld\n", fp->f_inode->i_size);
		filp_close(fp, 0);
		
		struct path old_path;
		if (!kern_path(SULOG_OLD_PATH, 0, &old_path)) {
			ksu_vfs_unlink(old_path.dentry->d_parent->d_inode, old_path.dentry);
			path_put(&old_path);
		}
		
		struct path current_path, parent_path;
		if (!kern_path(SULOG_PATH, 0, &current_path)) {
			parent_path = current_path;
			path_get(&parent_path);
			parent_path.dentry = current_path.dentry->d_parent;
			
			struct dentry *old_dentry = lookup_one_len("sulog.log.old", 
				parent_path.dentry, strlen("sulog.log.old"));
			if (!IS_ERR(old_dentry)) {
				ksu_vfs_rename(parent_path.dentry->d_inode, current_path.dentry,
                          parent_path.dentry->d_inode, old_dentry);
				dput(old_dentry);
			}
			path_put(&current_path);
			path_put(&parent_path);
		}
		
		fp = ksu_filp_open_compat(SULOG_PATH, O_WRONLY | O_CREAT | O_EXCL, 0640);
		if (IS_ERR(fp)) {
			pr_err("sulog: failed to create new log file: %ld\n", PTR_ERR(fp));
			goto cleanup;
		}
		
		const char *rotate_msg = "=== Log file rotated, old log saved as sulog.log.old ===\n";
		ksu_kernel_write_compat(fp, rotate_msg, strlen(rotate_msg), &pos);
	} else {
		pos = fp->f_inode->i_size;
	}
	
	list_for_each_entry(entry, &local_queue, list) {
		ksu_kernel_write_compat(fp, entry->content, strlen(entry->content), &pos);
	}
	
	vfs_fsync(fp, 0);
	filp_close(fp, 0);
	
cleanup:
	list_for_each_entry_safe(entry, tmp, &local_queue, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static void sulog_add_entry(const char *content)
{
	struct sulog_entry *entry;
	
	if (!sulog_enabled || !content)
		return;
	
	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		pr_err("sulog: failed to allocate memory for log entry\n");
		return;
	}
	
	strncpy(entry->content, content, SULOG_ENTRY_MAX_LEN - 1);
	entry->content[SULOG_ENTRY_MAX_LEN - 1] = '\0';
	
	mutex_lock(&sulog_mutex);
	list_add_tail(&entry->list, &sulog_queue);
	mutex_unlock(&sulog_mutex);
	
	if (sulog_workqueue)
		queue_work(sulog_workqueue, &sulog_work);
}

void ksu_sulog_report_su_grant(uid_t uid, const char *comm, const char *method)
{
	char *timestamp, *full_comm, *log_buf;
	
	if (!sulog_enabled)
		return;
	
	timestamp = kmalloc(32, GFP_ATOMIC);
	full_comm = kmalloc(SULOG_COMM_LEN, GFP_ATOMIC);
	log_buf = kmalloc(SULOG_ENTRY_MAX_LEN, GFP_ATOMIC);
	
	if (!timestamp || !full_comm || !log_buf) {
		pr_err("sulog: failed to allocate memory for su_grant log\n");
		goto cleanup_grant;
	}
	
	get_timestamp(timestamp, 32);
	
	if (comm && strlen(comm) > 0) {
		strncpy(full_comm, comm, SULOG_COMM_LEN - 1);
		full_comm[SULOG_COMM_LEN - 1] = '\0';
	} else {
		get_full_comm(full_comm, SULOG_COMM_LEN);
	}
	
	snprintf(log_buf, SULOG_ENTRY_MAX_LEN,
		"[%s] SU_GRANT: UID=%d COMM=%s METHOD=%s PID=%d\n",
		timestamp, uid, full_comm, 
		method ? method : "unknown", current->pid);

	if (!dedup_should_print(uid, DEDUP_SU_GRANT, log_buf, strlen(log_buf)))
        goto cleanup_grant;
	
	sulog_add_entry(log_buf);
	
cleanup_grant:
	if (timestamp) kfree(timestamp);
	if (full_comm) kfree(full_comm);
	if (log_buf) kfree(log_buf);
}

void ksu_sulog_report_su_attempt(uid_t uid, const char *comm, const char *target_path, bool success)
{
	char *timestamp, *full_comm, *log_buf;
	
	if (!sulog_enabled)
		return;
	
	timestamp = kmalloc(32, GFP_ATOMIC);
	full_comm = kmalloc(SULOG_COMM_LEN, GFP_ATOMIC);
	log_buf = kmalloc(SULOG_ENTRY_MAX_LEN, GFP_ATOMIC);
	
	if (!timestamp || !full_comm || !log_buf) {
		pr_err("sulog: failed to allocate memory for su_attempt log\n");
		goto cleanup_attempt;
	}
	
	get_timestamp(timestamp, 32);
	
	if (comm && strlen(comm) > 0) {
		strncpy(full_comm, comm, SULOG_COMM_LEN - 1);
		full_comm[SULOG_COMM_LEN - 1] = '\0';
	} else {
		get_full_comm(full_comm, SULOG_COMM_LEN);
	}
	
	snprintf(log_buf, SULOG_ENTRY_MAX_LEN,
		"[%s] SU_EXEC: UID=%d COMM=%s TARGET=%s RESULT=%s PID=%d\n",
		timestamp, uid, full_comm,
		target_path ? target_path : "unknown",
		success ? "SUCCESS" : "DENIED", current->pid);

	if (!dedup_should_print(uid, DEDUP_SU_ATTEMPT, log_buf, strlen(log_buf)))
        goto cleanup_attempt;
	
	sulog_add_entry(log_buf);
	
cleanup_attempt:
	if (timestamp) kfree(timestamp);
	if (full_comm) kfree(full_comm);
	if (log_buf) kfree(log_buf);
}

void ksu_sulog_report_permission_check(uid_t uid, const char *comm, bool allowed)
{
	char *timestamp, *full_comm, *log_buf;
	
	if (!sulog_enabled)
		return;
	
	timestamp = kmalloc(32, GFP_ATOMIC);
	full_comm = kmalloc(SULOG_COMM_LEN, GFP_ATOMIC);
	log_buf = kmalloc(SULOG_ENTRY_MAX_LEN, GFP_ATOMIC);
	
	if (!timestamp || !full_comm || !log_buf) {
		pr_err("sulog: failed to allocate memory for permission_check log\n");
		goto cleanup_perm;
	}
	
	get_timestamp(timestamp, 32);
	
	if (comm && strlen(comm) > 0) {
		strncpy(full_comm, comm, SULOG_COMM_LEN - 1);
		full_comm[SULOG_COMM_LEN - 1] = '\0';
	} else {
		get_full_comm(full_comm, SULOG_COMM_LEN);
	}
	
	snprintf(log_buf, SULOG_ENTRY_MAX_LEN,
		"[%s] PERM_CHECK: UID=%d COMM=%s RESULT=%s PID=%d\n",
		timestamp, uid, full_comm,
		allowed ? "ALLOWED" : "DENIED", current->pid);

	if (!dedup_should_print(uid, DEDUP_PERM_CHECK, log_buf, strlen(log_buf)))
        goto cleanup_perm;
	
	sulog_add_entry(log_buf);
	
cleanup_perm:
	if (timestamp) kfree(timestamp);
	if (full_comm) kfree(full_comm);
	if (log_buf) kfree(log_buf);
}

void ksu_sulog_report_manager_operation(const char *operation, uid_t manager_uid, uid_t target_uid)
{
	char *timestamp, *full_comm, *log_buf;
	
	if (!sulog_enabled)
		return;
	
	timestamp = kmalloc(32, GFP_ATOMIC);
	full_comm = kmalloc(SULOG_COMM_LEN, GFP_ATOMIC);
	log_buf = kmalloc(SULOG_ENTRY_MAX_LEN, GFP_ATOMIC);
	
	if (!timestamp || !full_comm || !log_buf) {
		pr_err("sulog: failed to allocate memory for manager_operation log\n");
		goto cleanup_mgr;
	}
	
	get_timestamp(timestamp, 32);
	get_full_comm(full_comm, SULOG_COMM_LEN);
	
	snprintf(log_buf, SULOG_ENTRY_MAX_LEN,
		"[%s] MANAGER_OP: OP=%s MANAGER_UID=%d TARGET_UID=%d PID=%d\n",
		timestamp, operation ? operation : "unknown",
		manager_uid, target_uid, current->pid);

	if (!dedup_should_print(manager_uid, DEDUP_MANAGER_OP, log_buf, strlen(log_buf)))
        goto cleanup_mgr;
	
	sulog_add_entry(log_buf);
	
cleanup_mgr:
	if (timestamp) kfree(timestamp);
	if (full_comm) kfree(full_comm);
	if (log_buf) kfree(log_buf);
}

void ksu_sulog_report_syscall(uid_t uid, const char *comm,
			      const char *syscall, const char *args)
{
	char *timestamp, *full_comm, *log_buf;

	if (!sulog_enabled)
		return;

	timestamp = kmalloc(32, GFP_ATOMIC);
	full_comm = kmalloc(SULOG_COMM_LEN, GFP_ATOMIC);
	log_buf   = kmalloc(SULOG_ENTRY_MAX_LEN, GFP_ATOMIC);

	if (!timestamp || !full_comm || !log_buf) {
		pr_err("sulog: failed to allocate memory for syscall log\n");
		goto cleanup_mgr;
	}

	get_timestamp(timestamp, 32);
	get_full_comm(full_comm, SULOG_COMM_LEN);

	snprintf(log_buf, SULOG_ENTRY_MAX_LEN,
		 "[%s] SYSCALL: UID=%d COMM=%s SYSCALL=%s ARGS=%s PID=%d\n",
		 timestamp, uid, full_comm,
		 syscall  ? syscall  : "unknown",
		 args     ? args     : "none",
		 current->pid);

	if (!dedup_should_print(uid, DEDUP_SYSCALL, log_buf, strlen(log_buf)))
        goto cleanup_mgr;

	sulog_add_entry(log_buf);

cleanup_mgr:
	if (timestamp) kfree(timestamp);
	if (full_comm) kfree(full_comm);
	if (log_buf) kfree(log_buf);
}

void ksu_sulog_set_enabled(bool enabled)
{
	sulog_enabled = enabled;
	pr_info("sulog: logging %s\n", enabled ? "enabled" : "disabled");
}

bool ksu_sulog_is_enabled(void)
{
	return sulog_enabled;
}

int ksu_sulog_init(void)
{
	sulog_workqueue = create_singlethread_workqueue("ksu_sulog");
	if (!sulog_workqueue) {
		pr_err("sulog: failed to create workqueue\n");
		return -ENOMEM;
	}
	
	INIT_WORK(&sulog_work, sulog_work_handler);
	
	pr_info("sulog: initialized successfully\n");
	return 0;
}

void ksu_sulog_exit(void)
{
	struct sulog_entry *entry, *tmp;
	
	sulog_enabled = false;
	
	if (sulog_workqueue) {
		flush_workqueue(sulog_workqueue);
		destroy_workqueue(sulog_workqueue);
		sulog_workqueue = NULL;
	}
	
	mutex_lock(&sulog_mutex);
	list_for_each_entry_safe(entry, tmp, &sulog_queue, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	mutex_unlock(&sulog_mutex);
	
	pr_info("sulog: cleaned up successfully\n");
}