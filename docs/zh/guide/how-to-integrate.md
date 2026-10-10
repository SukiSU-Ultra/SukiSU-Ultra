# 集成指导

SukiSU-Ultra 可以集成到 GKI 和非 GKI 内核中。前提条件：开源的、可启动的内核。

> [!TIP]
> **只想在 GKI 设备上使用？** 无需自行构建内核，可通过管理器以可加载内核模块 (LKM) 方式安装：见 [LKM 安装](https://sukisu.org/zh/guide/installation#lkm-安装)。

有些 OEM 定制会使大量内核代码游离于上游 Linux 或 ACK 之外。因此非 GKI 内核高度碎片化，缺乏通用的构建方法，我们无法提供非 GKI 内核的启动映像。

## 选择分支

| 分支 | 内核 Hook 方式 | 典型用途 |
|------|----------------|----------|
| `main` | 运行时注册 Kprobes / kretprobes 与 `sys_enter` 系统调用 tracepoint，无需在内核源码中添加 hook 调用 | GKI 内核；可编译为模块 (LKM) 或内置 |
| `builtin` | 不使用 kprobes，由内核源码调用 SukiSU-Ultra 的 hook 入口（手动 hook） | 需要手动修改的内核 |

> [!WARNING]
> `CONFIG_KSU_MANUAL_HOOK` 和 `CONFIG_KSU_TRACEPOINT_HOOK` 在两个分支中都已不存在，旧版 *Tracepoint Hook* 教程使用的 `ksu_trace.h` 也已移除。仍要求启用它们的教程已过时。

## `main` 分支

### 要求

- `CONFIG_KPROBES=y` 和 `CONFIG_EXT4_FS=y`，`CONFIG_KSU` 依赖这两项。
- 当内核提供时，hook 管理器会使用 kretprobes（`CONFIG_KRETPROBES`）和 `sys_enter` 系统调用 tracepoint（`CONFIG_HAVE_SYSCALL_TRACEPOINTS`）。
- `CONFIG_KSU` 是 tristate：选 `y` 为内置，选 `m` 则编译为 `kernelsu` 模块。

### 添加到内核源码

在内核源码根目录运行：

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

脚本会克隆仓库、链接到 `drivers/kernelsu`，并在 `drivers/Makefile` 与 `drivers/Kconfig` 中添加条目。使用 `--cleanup` 可撤销。

### 可选配置

| 选项 | 含义 |
|------|------|
| `CONFIG_KSU_MANUAL_SU`（默认 `y`） | 使用手动 su：通过 `prctl` 授权对应的命令行和应用。 |
| `CONFIG_KPM` | 启用 SukiSU KPM。需要 64 位内核，并会选中 `CONFIG_KALLSYMS` 与 `CONFIG_KALLSYMS_ALL`。可能影响系统稳定性。 |
| `CONFIG_KSU_DISABLE_MANAGER` | 禁用管理器 APK 检测及管理器相关处理。 |
| `CONFIG_KSU_DISABLE_POLICY` | 禁用按应用的配置。提权始终使用默认的完整 root 配置。 |
| `CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER` | 仅 x86_64。动态修补加固后的系统调用分发器以支持 syscall hook，可替代内核源码补丁，适用于 x86_64 的 LKM 模式。 |
| `CONFIG_KSU_DEBUG` | 调试模式。 |

## `builtin` 分支

该分支不注册 kprobes。你需要在内核源码中为它的 hook 入口添加调用（手动 hook），例如 `execveat`、`faccessat`、`stat`、`read`、`reboot`、`setresuid` 和 umount 处理。这些入口声明在该分支的头文件中（`kernel/feature/sucompat.h`、`kernel/feature/kernel_umount.h`、`kernel/runtime/ksud.h` 等），请对照你所构建分支的实际函数签名。

关于手动 hook 放在哪里，上游 KernelSU 的指南可作参考：[手动修改内核源码](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#manually-modify-the-kernel-source)。它是为上游 KernelSU 写的，请勿照搬。

然后将该分支添加到你的源码树：

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s builtin
```

该分支还包含 SUSFS 选项（`CONFIG_KSU_SUSFS` 及其子选项）和需要 64 位内核的 `CONFIG_KPM`。

本文同样发布在网站：[sukisu.org - 集成指导](https://sukisu.org/zh/guide/how-to-integrate)。
