# Tracepoint Hook 集成（已废弃）

> [!CAUTION]
> **本教程已过时。** 本页原先介绍的方法需要修改内核源码并启用 `CONFIG_KSU_TRACEPOINT_HOOK`，同时包含 `ksu_trace.h`。**这些在当前的 `main` 与 `builtin` 分支中都已不存在**，照着旧教程修改内核会导致编译失败。

当前的做法：

- `main` 分支在运行时自行注册 kprobes / kretprobes 与 `sys_enter` 系统调用 tracepoint，不需要在内核源码中添加 hook 调用。
- `builtin` 分支使用手动 hook。

详见 [how-to-integrate.md](how-to-integrate.md)。
