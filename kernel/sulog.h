#ifndef __KSU_SULOG_H
#define __KSU_SULOG_H

#include <linux/types.h>
#include <linux/version.h>

#define __SULOG_GATE        1

#if __SULOG_GATE
extern struct timezone sys_tz;

#define SULOG_PATH "/data/adb/ksu/log/sulog.log"
#define SULOG_MAX_SIZE (128 * 1024 * 1024) // 128MB
#define SULOG_ENTRY_MAX_LEN 512
#define SULOG_COMM_LEN 256
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

void ksu_sulog_report_su_grant(uid_t uid, const char *comm, const char *method);
void ksu_sulog_report_su_attempt(uid_t uid, const char *comm, const char *target_path, bool success);
void ksu_sulog_report_permission_check(uid_t uid, const char *comm, bool allowed);
void ksu_sulog_report_manager_operation(const char *operation, uid_t manager_uid, uid_t target_uid);
void ksu_sulog_report_syscall(uid_t uid, const char *comm, const char *syscall, const char *args);

int ksu_sulog_init(void);
void ksu_sulog_exit(void);
#endif // __SULOG_GATE

#endif /* __KSU_SULOG_H */