#include "ksu_trace.h"

// extern kernelsu functions
extern bool ksu_execveat_hook __read_mostly;
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
			       void *argv, void *envp, int *flags);
extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
					void *argv, void *envp, int *flags);
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
				int *mode, int *flags);
extern bool ksu_vfs_read_hook __read_mostly;
extern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,
			       size_t *count_ptr);
extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
			   int *flags);
extern bool ksu_input_hook __read_mostly;
extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code,
					 int *value);
extern int ksu_handle_devpts(struct inode *);
// end kernelsu functions

// tracepoint callback functions
void ksu_trace_execveat_hook_callback(void *data, int *fd,
				      struct filename **filename_ptr,
				      void *argv, void *envp, int *flags)
{
	if (unlikely(ksu_execveat_hook))
		ksu_handle_execveat(fd, filename_ptr, argv, envp, flags);
	else
		ksu_handle_execveat_sucompat(fd, filename_ptr, NULL, NULL,
					     NULL);
}

void ksu_trace_execveat_sucompat_hook_callback(void *data, int *fd,
					       struct filename **filename_ptr,
					       void *argv, void *envp,
					       int *flags)
{
	if (!ksu_execveat_hook)
		ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
					     flags);
}

void ksu_trace_faccessat_hook_callback(void *data, int *dfd,
				       const char __user **filename_user,
				       int *mode, int *flags)
{
	ksu_handle_faccessat(dfd, filename_user, mode, flags);
}

void ksu_trace_sys_read_hook_callback(void *data, unsigned int fd,
				      char __user **buf_ptr, size_t *count_ptr)
{
	if (unlikely(ksu_vfs_read_hook))
		ksu_handle_sys_read(fd, buf_ptr, count_ptr);
}

void ksu_trace_stat_hook_callback(void *data, int *dfd,
				  const char __user **filename_user, int *flags)
{
	ksu_handle_stat(dfd, filename_user, flags);
}

void ksu_trace_input_hook_callback(void *data, unsigned int *type,
				   unsigned int *code, int *value)
{
	if (unlikely(ksu_input_hook))
		ksu_handle_input_handle_event(type, code, value);
}

void ksu_trace_devpts_hook_callback(void *data, struct inode *inode)
{
	ksu_handle_devpts(inode);
}
// end tracepoint callback functions

// register tracepoint callback functions
void ksu_trace_register(void)
{
	register_trace_ksu_trace_execveat_hook(ksu_trace_execveat_hook_callback,
					       NULL);
	register_trace_ksu_trace_execveat_sucompat_hook(
		ksu_trace_execveat_sucompat_hook_callback, NULL);
	register_trace_ksu_trace_faccessat_hook(
		ksu_trace_faccessat_hook_callback, NULL);
	register_trace_ksu_trace_sys_read_hook(ksu_trace_sys_read_hook_callback,
					       NULL);
	register_trace_ksu_trace_stat_hook(ksu_trace_stat_hook_callback, NULL);
	register_trace_ksu_trace_input_hook(ksu_trace_input_hook_callback,
					    NULL);
	register_trace_ksu_trace_devpts_hook(ksu_trace_devpts_hook_callback,
					     NULL);
}

// unregister tracepoint callback functions
void ksu_trace_unregister(void)
{
	unregister_trace_ksu_trace_execveat_hook(
		ksu_trace_execveat_hook_callback, NULL);
	unregister_trace_ksu_trace_execveat_sucompat_hook(
		ksu_trace_execveat_sucompat_hook_callback, NULL);
	unregister_trace_ksu_trace_faccessat_hook(
		ksu_trace_faccessat_hook_callback, NULL);
	unregister_trace_ksu_trace_sys_read_hook(
		ksu_trace_sys_read_hook_callback, NULL);
	unregister_trace_ksu_trace_stat_hook(ksu_trace_stat_hook_callback,
					     NULL);
	unregister_trace_ksu_trace_input_hook(ksu_trace_input_hook_callback,
					      NULL);
	unregister_trace_ksu_trace_devpts_hook(ksu_trace_devpts_hook_callback,
					       NULL);
}
