# Tracepoint Hook Integration

## Introduction

Since commit [49b01aad](https://github.com/SukiSU-Ultra/SukiSU-Ultra/commit/49b01aad74bcca6dba5a8a2e053bb54b648eb124), SukiSU has introduced Tracepoint Hook

This Hook theoretically has lower performance overhead compared to Kprobes Hook, but is inferior to Manual Hook / Syscall Hook

> [!NOTE]
> This tutorial references the syscall hook v1.4 version from [backslashxx/KernelSU#5](https://github.com/backslashxx/KernelSU/issues/5), as well as the original KernelSU's [Manual Hook](https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source)

## Guide

### execve Hook (`exec.c`)

Generally need to modify the `do_execve` and `compat_do_execve` methods in `fs/exec.c`

```patch
--- a/fs/exec.c
+++ b/fs/exec.c
@@ -78,6 +78,10 @@
 #include <trace/hooks/sched.h>
 #endif
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+#include <../drivers/kernelsu/ksu_trace.h>
+#endif
+
 EXPORT_TRACEPOINT_SYMBOL_GPL(task_rename);
 
 static int bprm_creds_from_file(struct linux_binprm *bprm);
@@ -2037,6 +2041,9 @@ static int do_execve(struct filename *filename,
 {
 	struct user_arg_ptr argv = { .ptr.native = __argv };
 	struct user_arg_ptr envp = { .ptr.native = __envp };
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+    trace_ksu_trace_execveat_hook((int *)AT_FDCWD, &filename, &argv, &envp, 0);
+#endif
 	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
 }
 
@@ -2064,6 +2071,9 @@ static int compat_do_execve(struct filename *filename,
 		.is_compat = true,
 		.ptr.compat = __envp,
 	};
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+    trace_ksu_trace_execveat_sucompat_hook((int *)AT_FDCWD, &filename, NULL, NULL, NULL); /* 32-bit su */
+#endif
 	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
 }
```

### faccessat Hook (`open.c`)

Generally need to modify the `do_faccessat` method in `/fs/open.c` 

```patch
--- a/fs/open.c
+++ b/fs/open.c
@@ -37,6 +37,10 @@
 #include "internal.h"
 #include <trace/hooks/syscall_check.h>
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+#include <../drivers/kernelsu/ksu_trace.h>
+#endif
+
 int do_truncate(struct user_namespace *mnt_userns, struct dentry *dentry,
 		loff_t length, unsigned int time_attrs, struct file *filp)
 {
@@ -468,6 +472,9 @@ static long do_faccessat(int dfd, const char __user *filename, int mode, int fla
 
 SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
 {
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+	trace_ksu_trace_faccessat_hook(&dfd, &filename, &mode, NULL);
+#endif
 	return do_faccessat(dfd, filename, mode, 0);
 }
```

If there's no `do_faccessat` method, you can find the `faccessat` SYSCALL definition (for kernels earlier than 4.17)

```patch
--- a/fs/open.c
+++ b/fs/open.c
@@ -31,6 +31,9 @@
 #include <linux/ima.h>
 #include <linux/dnotify.h>
 #include <linux/compat.h>
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+#include <../drivers/kernelsu/ksu_trace.h>
+#endif
 
 #include "internal.h"
 
@@ -369,6 +372,9 @@ SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
 	int res;
 	unsigned int lookup_flags = LOOKUP_FOLLOW;
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+	trace_ksu_trace_faccessat_hook(&dfd, &filename, &mode, NULL);
+#endif
 	if (mode & ~S_IRWXO)	/* where's F_OK, X_OK, W_OK, R_OK? */
 		return -EINVAL;
```

### sys_read Hook (`read_write.c`)

Need to modify the `sys_read` method in `fs/read_write.c` (4.19 and above)

```patch
--- a/fs/read_write.c
+++ b/fs/read_write.c
@@ -25,6 +25,10 @@
 #include <linux/uaccess.h>
 #include <asm/unistd.h>
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+#include <../drivers/kernelsu/ksu_trace.h>
+#endif
+
 const struct file_operations generic_ro_fops = {
 	.llseek		= generic_file_llseek,
 	.read_iter	= generic_file_read_iter,
@@ -630,6 +634,9 @@ ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
 
 SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
 {
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+    trace_ksu_trace_sys_read_hook(fd, &buf, &count);
+#endif
 	return ksys_read(fd, buf, count);
 }
```

Or the `read` SYSCALL definition (4.14 and below)

```patch
--- a/fs/read_write.c
+++ b/fs/read_write.c
@@ -25,6 +25,11 @@
 #include <linux/uaccess.h>
 #include <asm/unistd.h>
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+#include <../drivers/kernelsu/ksu_trace.h>
+#endif
+
+
 const struct file_operations generic_ro_fops = {
 	.llseek		= generic_file_llseek,
 	.read_iter	= generic_file_read_iter,
@@ -575,6 +580,9 @@ SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
 
 	if (f.file) {
 		loff_t pos = file_pos_read(f.file);
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+		trace_ksu_trace_sys_read_hook(fd, &buf, &count);
+#endif
 		ret = vfs_read(f.file, buf, count, &pos);
 		if (ret >= 0)
 			file_pos_write(f.file, pos);
```

### fstatat Hook (`stat.c`)

Need to modify the `newfstatat` SYSCALL definition in `stat.c`

If 32-bit support is needed, also need to modify the `statat64` SYSCALL definition

```patch
--- a/fs/stat.c
+++ b/fs/stat.c
@@ -24,6 +24,10 @@
 #include "internal.h"
 #include "mount.h"
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+#include <../drivers/kernelsu/ksu_trace.h>
+#endif
+
 /**
  * generic_fillattr - Fill in the basic attributes from the inode struct
  * @mnt_userns:	user namespace of the mount the inode was found from
@@ -408,6 +412,10 @@ SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
 	struct kstat stat;
 	int error;
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+	trace_ksu_trace_stat_hook(&dfd, &filename, &flag);
+#endif
+
 	error = vfs_fstatat(dfd, filename, &stat, flag);
 	if (error)
 		return error;
@@ -559,6 +567,10 @@ SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,
 	struct kstat stat;
 	int error;
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+	trace_ksu_trace_stat_hook(&dfd, &filename, &flag); /* 32-bit su support */
+#endif
+
 	error = vfs_fstatat(dfd, filename, &stat, flag);
 	if (error)
 		return error;
```

### input Hook (`input.c`, for entering KSU built-in security mode)

Need to modify the `input_event` method in `drivers/input/input.c`, not `input_handle_event`

```patch
--- a/drivers/input/input.c
+++ b/drivers/input/input.c
@@ -26,6 +26,10 @@
 #include "input-compat.h"
 #include "input-poller.h"
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+#include <../../drivers/kernelsu/ksu_trace.h>
+#endif
+
 MODULE_AUTHOR("Vojtech Pavlik <vojtech@suse.cz>");
 MODULE_DESCRIPTION("Input core");
 MODULE_LICENSE("GPL");
@@ -451,6 +455,10 @@ void input_event(struct input_dev *dev,
 {
 	unsigned long flags;
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+    trace_ksu_trace_input_hook(&type, &code, &value);
+#endif
+
 	if (is_event_supported(type, dev->evbit, EV_MAX)) {
 
 		spin_lock_irqsave(&dev->event_lock, flags);
```

### devpts Hook (`pty.c`)

Need to modify the `pts_unix98_lookup` method in `drivers/tty/pty.c`

```patch
--- a/drivers/tty/pty.c
+++ b/drivers/tty/pty.c
@@ -31,6 +31,10 @@
 #include <linux/compat.h>
 #include "tty.h"
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+#include <../../drivers/kernelsu/ksu_trace.h>
+#endif
+
 #undef TTY_DEBUG_HANGUP
 #ifdef TTY_DEBUG_HANGUP
 # define tty_debug_hangup(tty, f, args...)	tty_debug(tty, f, ##args)
@@ -707,6 +711,10 @@ static struct tty_struct *pts_unix98_lookup(struct tty_driver *driver,
 {
 	struct tty_struct *tty;
 
+#if defined(CONFIG_KSU) && defined(CONFIG_KSU_TRACEPOINT_HOOK)
+		trace_ksu_trace_devpts_hook((struct inode *)file->f_path.dentry->d_inode);
+#endif
+
 	mutex_lock(&devpts_mutex);
 	tty = devpts_get_priv(file->f_path.dentry);
 	mutex_unlock(&devpts_mutex);
```
