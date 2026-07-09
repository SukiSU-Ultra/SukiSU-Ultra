#ifndef __KSU_H_KERNEL_UMOUNT
#define __KSU_H_KERNEL_UMOUNT

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rwsem.h>

void ksu_kernel_umount_init(void);
void ksu_kernel_umount_exit(void);

// Handler function to be called from setresuid hook
int ksu_handle_umount(uid_t old_uid, uid_t new_uid);

// for the umount list
struct mount_entry {
    char *umountable;
    unsigned int flags;
    struct list_head list;
};
extern struct list_head mount_list;
extern struct rw_semaphore mount_list_lock;

// for umount exclusion list
struct umount_exclusion_entry {
	char *path_prefix;  // Path prefix to skip during umount
	struct list_head list;
};
extern struct list_head umount_exclusion_list;
extern struct rw_semaphore umount_exclusion_lock;

int ksu_umount_exclusion_add(const char *path_prefix);
int ksu_umount_exclusion_remove(const char *path_prefix);
int ksu_umount_exclusion_clear(void);
ssize_t ksu_umount_exclusion_list(char __user *buf, size_t buf_size);

#endif
