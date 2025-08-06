# Installation

You can go to [KernelSU Documentation - Installation](https://kernelsu.org/guide/installation.html) for a reference on how to install it, here are just additional instructions.

## Installation by loading the Loadable Kernel Module(LKM)

See [KernelSU Documentation - LKM Installation](https://kernelsu.org/guide/installation.html#lkm-installation)

Beginning with **Android™** (trademark meaning licensed Google Mobile Services) 12, devices shipping with kernel version 5.10 or higher must ship with the GKI kernel. You may be able to use LKM mode.

## Installation by installing the kernel

See [KernelSU Documentation - GKI mode Installation](https://kernelsu.org/guide/installation.html#gki-mode-installation)

We provide pre-built kernels for you to use:

- [ShirkNeko flavor kernel](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) (add ZRAM compression algorithm patch, susfs, KPM. Works on many devices.)
- [MiRinFork flavored kernel](https://github.com/MiRinFork/GKI_SukiSU_SUSFS) (adds susfs, KPM. Closest kernel to GKI, works on most devices.)

Although some devices can be installed using LKM mode, they cannot be installed on the device by using the GKI kernel; therefore, the kernel needs to be modified manually to compile it. For example:

- OPPO(OnePlus, REALME)
- Meizu

Also, we provide pre-built kernels for your OnePlus device to use:

- [ShirkNeko/Action_OnePlus_MKSU_SUSFS](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS) (add ZRAM compression algorithm patch, susfs, KPM.)

Using the link above, Fork into GitHub Action, fill in the build parameters, compile, and finally flush in the zip with the AnyKernel3 suffix.

> [!Note]
>
> - You only need to fill in the first two parts of the version number, e.g. `5.10`, `6.1`...
> - Make sure you know the processor designation, kernel version, etc. before you use it.
