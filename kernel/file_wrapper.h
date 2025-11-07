#include <linux/file.h>
#include <linux/fs.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
typedef unsigned int __poll_t;
#endif

struct ksu_file_wrapper {
	struct file* orig;
	struct file_operations ops;
};

struct ksu_file_wrapper* mksu_create_file_wrapper(struct file* fp);
void mksu_delete_file_wrapper(struct ksu_file_wrapper* data);
