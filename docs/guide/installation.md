# Installation

The full installation guide is on the website: [sukisu.org - Installation](https://sukisu.org/guide/installation). This page only summarizes the options.

## Installation by loading the Loadable Kernel Module (LKM) (recommended)

Install the Manager and let it patch your boot image with a prebuilt module for your device's KMI. See [LKM installation](https://sukisu.org/guide/installation#method-1-lkm-via-the-manager-recommended) for the steps and the list of prebuilt KMIs.

Beginning with **Android™** (trademark meaning licensed Google Mobile Services) 12, devices shipping with kernel version 5.10 or higher must ship with the GKI kernel. You may be able to use LKM mode.

## Installation by installing the kernel

See [Using pre-built GKI packages](https://sukisu.org/guide/installation#method-2-using-pre-built-gki-packages)

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
