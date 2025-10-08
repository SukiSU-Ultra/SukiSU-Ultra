# Tracepoint Hook 集成

## 介绍

自 commit [49b01aad](https://github.com/SukiSU-Ultra/SukiSU-Ultra/commit/49b01aad74bcca6dba5a8a2e053bb54b648eb124) 起，SukiSU 引入了 Tracepoint Hook

该 Hook 理论上相比于 Kprobes Hook，性能开销更小，但次于 Manual Hook / Syscall Hook

> [!NOTE]
> 本教程参考了 [backslashxx/KernelSU#5](https://github.com/backslashxx/KernelSU/issues/5) 的 syscall hook v1.4 版本钩子，以及原版 KernelSU 的 [Manual Hook](https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source)

## Guide

### execve 钩子（`exec.c`）

一般需要修改 `fs/exec.c` 的 `do_execve` 和 `compat_do_execve` 方法

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
+    trace_ksu_trace_execveat_hook((int *)AT_FDCWD, &filename, &argv, &envp, 0)); // 32-bit su and 32-on-64 support
+#endif
 	return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
 }
```

### faccessat 钩子 (`open.c`)

一般需要修改 `/fs/open.c` 的 `do_faccessat` 方法 

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

如果没有 `do_faccessat` 方法，可以找 `faccessat` 的 SYSCALL 定义（对于早于 4.17 的内核）

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

###  sys_read 钩子 ( `read_write.c` )

需要修改 `fs/read_write.c` 的 `sys_read` 方法（4.19 及以上）

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

或者是 `read` 的 SYSCALL 定义（4.14 及以下）

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

### fstatat 钩子 ( `stat.c` )

需要修改 `stat.c` 的 `newfstatat` SYSCALL 定义

如果需要 32 位支持，还需要修改 `statat64` SYSCALL 定义

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

### input 钩子 (`input.c` ,用于进入KSU系的内置安全模式)

需要修改 `drivers/input/input.c` 的 `input_event` 方法，而不是 `input_handle_event`

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