# Integrate

SukiSU-Ultra can be integrated into both GKI and non-GKI kernels. The prerequisite is an open-source, bootable kernel.

> [!TIP]
> **Just want to use it on a GKI device?** You do not need to build a kernel. Install it as a Loadable Kernel Module with the Manager: see [LKM installation](https://sukisu.org/guide/installation#method-1-lkm-via-the-manager-recommended).

Some OEM customizations can result in a large share of the kernel code being out-of-tree, not coming from upstream Linux or the ACK. Because of this, non-GKI kernels are heavily fragmented and there is no general way to build them, so boot images for non-GKI kernels cannot be provided.

## Pick a branch

| Branch | How it hooks the kernel | Typical use |
|--------|-------------------------|-------------|
| `main` | Kprobes / kretprobes and the `sys_enter` syscall tracepoint, registered at runtime. No hook calls have to be added to the kernel source. | GKI kernels, and building as a module (LKM) or built in |
| `builtin` | No kprobes. The kernel source calls SukiSU-Ultra's hook entry points (manual hooks). | Kernels you patch by hand |

> [!WARNING]
> `CONFIG_KSU_MANUAL_HOOK` and `CONFIG_KSU_TRACEPOINT_HOOK` no longer exist in either branch, and the `ksu_trace.h` header used by the old *Tracepoint Hook* guide is gone. Guides that tell you to enable them are out of date.

## The `main` branch

### Requirements

- `CONFIG_KPROBES=y` and `CONFIG_EXT4_FS=y`. `CONFIG_KSU` depends on both.
- The hook manager uses kretprobes (`CONFIG_KRETPROBES`) and the `sys_enter` syscall tracepoint (`CONFIG_HAVE_SYSCALL_TRACEPOINTS`) when your kernel provides them.
- `CONFIG_KSU` is tristate: use `y` to build it in, or `m` to build the `kernelsu` module.

### Add it to your kernel source

Run this in the root of your kernel source tree:

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

The script clones the repository, links it into `drivers/kernelsu` and adds the entries to `drivers/Makefile` and `drivers/Kconfig`. Use `--cleanup` to undo it.

### Optional configs

| Option | Meaning |
|--------|---------|
| `CONFIG_KSU_MANUAL_SU` (default `y`) | Use manual su: authorize the command line and application via `prctl`. |
| `CONFIG_KPM` | Enable SukiSU KPM. Requires a 64-bit kernel and selects `CONFIG_KALLSYMS` and `CONFIG_KALLSYMS_ALL`. May affect system stability. |
| `CONFIG_KSU_DISABLE_MANAGER` | Disable manager APK detection and manager-specific handling. |
| `CONFIG_KSU_DISABLE_POLICY` | Disable per-app profiles. Escalation always uses the default full root profile. |
| `CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER` | x86_64 only. Dynamically patches the hardened syscall dispatcher so syscall hooks work, replacing a kernel source patch. Useful for x86_64 LKM mode. |
| `CONFIG_KSU_DEBUG` | Debug mode. |

## The `builtin` branch

This branch does not register kprobes. You add calls to its hook entry points in your kernel source (manual hooks), for example for `execveat`, `faccessat`, `stat`, `read`, `reboot`, `setresuid` and umount handling. The entry points are declared in the branch's headers (`kernel/feature/sucompat.h`, `kernel/feature/kernel_umount.h`, `kernel/runtime/ksud.h`, among others); check their exact signatures against the branch you build.

For where manual hooks are placed, the upstream KernelSU guide is a useful reference: [Manually modify the kernel source](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#manually-modify-the-kernel-source). It is written for upstream KernelSU, so do not copy it blindly.

Then add the branch to your source tree:

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s builtin
```

This branch also carries the SUSFS options (`CONFIG_KSU_SUSFS` and its sub-options) and `CONFIG_KPM`, which needs a 64-bit kernel.

The same guide is available on the website: [sukisu.org - Integration](https://sukisu.org/guide/how-to-integrate).
