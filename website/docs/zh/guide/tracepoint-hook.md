# Tracepoint Hook 集成

## 介绍

自 commit [49b01aad](https://github.com/SukiSU-Ultra/SukiSU-Ultra/commit/49b01aad74bcca6dba5a8a2e053bb54b648eb124) 起，SukiSU 引入了 Tracepoint Hook

**该 Hook 理论上相比于 Kprobes Hook，性能开销更小，但次于 Manual Hook / Syscall Hook**

::: warning
目前 Tracepoint Hook 在 6.x 设备上并不稳定，请勿使用，否则可能出现无法开机或无法获取 `ROOT` 权限等问题。
:::

> [!NOTE]
> 本教程参考了 [backslashxx/KernelSU#5](https://github.com/backslashxx/KernelSU/issues/5) 的 syscall hook v1.4 版本钩子，以及原版 KernelSU 的 [Manual Hook](https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source)

## 在内核中放置 TP 钩子

::: code-group

```diff[exec.c]
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

```diff[open.c]
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

```diff[read_write.c]
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

```diff[stat.c]
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

:::
通常是要改四个地方：

1. compat_do_execve，通常位于 `fs/exec.c`
2. do_faccessat，通常位于 `/fs/open.c`
3. sys_read，通常位于 `fs/read_write.c`
4. newfstatat SYSCALL，通常位于 `fs/stat.c`

如果没有 do_faccessat 方法，可以找 faccessat 的 SYSCALL 定义（对于早于 4.17 的内核）

```diff
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

如果没有 sys_read 方法，并且 4.14 及以下需要修改 read 的 SYSCALL 定义

```diff
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

## 安全模式

要使用 KernelSU 内置的安全模式，你还需要修改 `drivers/input/input.c` 中的 input_handle_event 方法：

```diff
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

## pm 命令执行失败？

你需要修改 `drivers/tty/pty.c`

```diff
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
