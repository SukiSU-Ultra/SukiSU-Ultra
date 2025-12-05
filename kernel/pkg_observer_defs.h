// This header should not be used outside of pkg_observer.c!

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
typedef const struct qstr *ksu_fname_t;
#define ksu_fname_len(f) ((f)->len)
#define ksu_fname_arg(f) ((f)->name)
#else
typedef const unsigned char *ksu_fname_t;
#define ksu_fname_len(f) (strlen(f))
#define ksu_fname_arg(f) (f)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
#define KSU_DECL_FSNOTIFY_OPS(name) \
int name(struct fsnotify_mark *mark, u32 mask, \
	struct inode *inode, struct inode *dir, \
	const struct qstr *file_name, u32 cookie)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define KSU_DECL_FSNOTIFY_OPS(name) \
int name(struct fsnotify_group *group, \
	struct inode *inode, u32 mask, const void *data, int data_type, \
	ksu_fname_t file_name, u32 cookie, \
	struct fsnotify_iter_info *iter_info)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#define KSU_DECL_FSNOTIFY_OPS(name) \
int name(struct fsnotify_group *group, \
	struct inode *inode, u32 mask, const void *data, int data_type, \
	ksu_fname_t file_name, u32 cookie, \
	struct fsnotify_iter_info *iter_info)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#define KSU_DECL_FSNOTIFY_OPS(name) \
int name(struct fsnotify_group *group, \
	struct inode *inode, struct fsnotify_mark *inode_mark, \
	struct fsnotify_mark *vfsmount_mark, \
	u32 mask, const void *data, int data_type, \
	ksu_fname_t file_name, u32 cookie, \
	struct fsnotify_iter_info *iter_info)
#else
#define KSU_DECL_FSNOTIFY_OPS(name) \
int name(struct fsnotify_group *group, \
	struct inode *inode, \
	struct fsnotify_mark *inode_mark, \
	struct fsnotify_mark *vfsmount_mark, \
	u32 mask, void *data, int data_type, \
	ksu_fname_t file_name, u32 cookie)
#endif
