# Integrate

SukiSU can be integrated into both _GKI_ and _non-GKI_ kernels and has been backported to _4.14_.

<!-- It should be 3.4, but backslashxx's syscall manual hook cannot use in SukiSU-->

This customization could result in as much as 50% of kernel code being out-of-tree code and not from upstream Linux kernels or ACKs. Due to this, the custom nature of _non-GKI_ kernels resulted in significant kernel fragmentation, and we lacked a universal method for building them. Therefore, we cannot provide boot images of _non-GKI_ kernels.

Prerequisites: open source bootable kernel.

### Hook method

1. **KPROBES hook:**

   - Default hook method on GKI kernels.
   - Requires `# CONFIG_KSU_MANUAL_HOOK is not set` & `CONFIG_KPROBES=y`
   - Used for Loadable Kernel Module (LKM).

2. **Manual hook:**

   <!-- - backslashxx's syscall manual hook: https://github.com/backslashxx/KernelSU/issues/5 (v1.5 version is not available at the moment, if you want to use it, please use v1.4 version, or standard KernelSU hooks)-->

   - Requires `CONFIG_KSU_MANUAL_HOOK=y`
   - Requires [`guide/how-to-integrate.md`](guide/how-to-integrate.md)
   - Requires [https://github.com/~](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#manually-modify-the-kernel-source)

<!-- This part refer to [rsuntk/KernelSU](https://github.com/rsuntk/KernelSU). -->

If you're able to build a bootable kernel, there are two ways to integrate KernelSU into the kernel source code:

1. Automatically with `kprobe`
2. Manually

## Integrate with kprobe

Applicable:

- _GKI_ kernel

Not applicable:

- _non-GKI_ kernel

KernelSU uses kprobe to do kernel hooks. If kprobe runs well in your kernel, it's recommended to use it this way.

Please refer to this document [https://github.com/~](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#integrate-with-kprobe). Although it is titled “for _non-GKI_,” it only applies to _GKI_.

The execution command for the step that adds KernelSU to your kernel source tree is replaced with:

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

## Manually modify the kernel source

Applicable:

- GKI kernel
- non-GKI kernel

Please refer to this document [https://github.com/~ (Integrate for non-GKI)](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#manually-modify-the-kernel-source) and [https://github.com/~ (Build for GKI)](https://kernelsu.org/zh_CN/guide/how-to-build.html) to integrate manually, although first link is titled “for non-GKI,” it also applies to GKI. It can work on them both.

There is another way to integrate but still work in the process.

<!-- It is backslashxx's syscall manual hook, but it cannot be used now. -->

Run command for the step that adds KernelSU(SukiSU) to your kernel source tree is replaced with:

### GKI kernel

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

### non-GKI kernel

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s nongki
```

### GKI / non-GKI kernel with susfs (experiment)

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-{{branch}}
```

Branch:

- `main` (susfs-main)
- `test` (susfs-test)
- version (for example: susfs-1.5.7, you should check the [branches](https://github.com/SukiSU-Ultra/SukiSU-Ultra/branches))
