#ifndef __KSU_H_KERNEL_UMOUNT
#define __KSU_H_KERNEL_UMOUNT

void ksu_kernel_umount_init(void);
void ksu_kernel_umount_exit(void);

// for the umount list
struct mount_entry {
    char *umountable;
    unsigned int flags;
    struct list_head list;
};
extern struct list_head mount_list;
extern struct rw_semaphore mount_list_lock;

#endif
