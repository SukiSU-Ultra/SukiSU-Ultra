#ifndef __KSU_H_UMOUNT_MANAGER
#define __KSU_H_UMOUNT_MANAGER

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>

struct cred;

enum umount_entry_state {
    UMOUNT_STATE_IDLE = 0,
    UMOUNT_STATE_ACTIVE = 1,
    UMOUNT_STATE_BUSY = 2,
};

struct umount_entry {
    struct list_head list;
    char path[256];
    bool check_mnt;
    int flags;
    enum umount_entry_state state;
    bool is_default;
    u32 ref_count;
};

struct umount_manager {
    struct list_head entry_list;
    spinlock_t lock;
    u32 entry_count;
    u32 max_entries;
};

enum umount_manager_op {
    UMOUNT_OP_ADD = 0,
    UMOUNT_OP_REMOVE = 1,
    UMOUNT_OP_LIST = 2,
    UMOUNT_OP_CLEAR_CUSTOM = 3,
};

struct ksu_umount_manager_cmd {
    __u32 operation;
    char path[256];
    __u8 check_mnt;
    __s32 flags;
    __u32 count;
    __aligned_u64 entries_ptr;
};

struct ksu_umount_entry_info {
    char path[256];
    __u8 check_mnt;
    __s32 flags;
    __u8 is_default;
    __u32 state;
    __u32 ref_count;
};

int ksu_umount_manager_init(void);
void ksu_umount_manager_exit(void);
int ksu_umount_manager_add(const char *path, bool check_mnt, int flags, bool is_default);
int ksu_umount_manager_remove(const char *path);
bool ksu_umount_path_is_busy(const char *path);
void ksu_umount_manager_execute_all(const struct cred *cred);
int ksu_umount_manager_get_entries(struct ksu_umount_entry_info __user *entries, u32 *count);
int ksu_umount_manager_clear_custom(void);

#endif // __KSU_H_UMOUNT_MANAGER
