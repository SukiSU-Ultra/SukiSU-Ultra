#ifndef __KSU_H_MOUNT_HIDE
#define __KSU_H_MOUNT_HIDE

#include <linux/fs.h>

void ksu_mount_hide_init(void);
void ksu_mount_hide_exit(void);

int ksu_mount_hide_file_open(struct file *file);

#endif // __KSU_H_MOUNT_HIDE
