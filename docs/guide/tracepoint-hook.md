# Tracepoint Hook (deprecated)

> [!CAUTION]
> **This guide is out of date.** The method described here required patching the kernel source and enabling `CONFIG_KSU_TRACEPOINT_HOOK`, together with the `ksu_trace.h` header. **None of these exist in the current `main` and `builtin` branches**, so following the old guide will fail to compile.

What applies now:

- The `main` branch registers kprobes / kretprobes and the `sys_enter` syscall tracepoint by itself at runtime. No hook calls have to be added to the kernel source.
- The `builtin` branch uses manual hooks.

See [how-to-integrate.md](how-to-integrate.md).
