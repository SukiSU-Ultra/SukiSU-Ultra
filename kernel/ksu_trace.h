#undef TRACE_SYSTEM
#define TRACE_SYSTEM ksu_trace

#if !defined(_KSU_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KSU_TRACE_H

#include <linux/fs.h>
#include <linux/tracepoint.h>

DECLARE_TRACE(ksu_trace_execveat_hook,
	      TP_PROTO(int *fd, struct filename **filename_ptr, void *argv,
		       void *envp, int *flags),
	      TP_ARGS(fd, filename_ptr, argv, envp, flags));

DECLARE_TRACE(ksu_trace_execveat_sucompat_hook,
	      TP_PROTO(int *fd, struct filename **filename_ptr, void *argv,
		       void *envp, int *flags),
	      TP_ARGS(fd, filename_ptr, argv, envp, flags));

DECLARE_TRACE(ksu_trace_faccessat_hook,
	      TP_PROTO(int *dfd, const char __user **filename_user, int *mode,
		       int *flags),
	      TP_ARGS(dfd, filename_user, mode, flags));

DECLARE_TRACE(ksu_trace_sys_read_hook,
	      TP_PROTO(unsigned int fd, char __user **buf_ptr,
		       size_t *count_ptr),
	      TP_ARGS(fd, buf_ptr, count_ptr));

DECLARE_TRACE(ksu_trace_stat_hook,
	      TP_PROTO(int *dfd, const char __user **filename_user, int *flags),
	      TP_ARGS(dfd, filename_user, flags));

DECLARE_TRACE(ksu_trace_input_hook,
	      TP_PROTO(unsigned int *type, unsigned int *code, int *value),
	      TP_ARGS(type, code, value));

DECLARE_TRACE(ksu_trace_devpts_hook, TP_PROTO(struct inode *inode),
	      TP_ARGS(inode));

#endif /* _KSU_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE ksu_trace

#include <trace/define_trace.h>
