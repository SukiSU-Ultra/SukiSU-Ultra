# SukiSU

**Enlish** | [简体中文](README.md)


Android device root solution based on [KernelSU](https://github.com/KernelSU/KernelSU)

**Experimental! Use at your own risk! **This solution is based on [KernelSU]() and is experimental!

>
> This is an unofficial fork, all rights reserved [@tiann](https://github.com/tiann)
>
> This is a project based on personal use of the second change, personal research and development use only

- Fully adapted for non-GKI devices

## How to add
```
curl -LSs “https://raw.githubusercontent.com/ShirkNeko/KernelSU/main/kernel/setup.sh” | bash -s susfs-dev
```



## How to use integrated susfs

Use the susfs-dev branch directly without any patching


Or use the default branch for patching, with files in [patch](../patch)

## More links
Projects compiled based on Sukisu and susfs
- [GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) 
- [OnePlus](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)

## Hook method
- This method references the hook manual to (https://github.com/rsuntk/KernelSU)

1. **KPROBES hook:**
    - This fork only supports GKI (5.10 - 6.x) kernels, all non-GKI kernels must use manual hooks.
    - For Loadable Kernel Modules (LKM)
    - Default hooking method for GKI kernels
    - Requires `CONFIG_KPROBES=y`. 2.
2. **Hooks manual:**
    - For GKI (5.10 - 6.x) kernels, add `CONFIG_KSU_MANUAL_HOOK=y` to the kernel defconfig and make sure to protect KernelSU hooks by using `#ifdef CONFIG_KSU_MANUAL_HOOK` instead of `#ifdef CONFIG_KSU`.
    - Standard KernelSU hooks: https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source
    - backslashxx syscall hooks: https://github.com/backslashxx/KernelSU/issues/5
    - Some non-GKI devices that manually integrate KPROBES do not require the manual VFS hook `new_hook.patch` patch


## Usage
[GKI]
1. such as millet redmi samsung and other devices (does not include the magic kernel manufacturers such as: meizu, a plus real me oppo)
2. find more links in the GKI build project to find the device kernel version directly download with TWRP or kernel flashing tool to brush into the zip with AnyKernel3 suffix can be
3. General without the suffix of the .zip compressed package is universal, gz suffix for the special TianGui models, lz4 suffix for Google models, general brush without the suffix can be!

[OnePlus]
1. Find the Yiga project in the More link and fill in your own, then build it with cloud compilation, and finally brush in the zip with AnyKernel3 suffix.
Note: You only need to fill in the first two kernel versions, such as 5.10, 5.15, 6.1, 6.6.
- Please search for the processor codename by yourself, usually it is all English without numbers.
- Branching and configuration files, please fill in the kernel open source address.



## Features

1. Kernel-based `su` and root access management.
2. Not based on [OverlayFS](https://en.wikipedia.org/wiki/OverlayFS) module system. 3.
3. [Application Profiles](https://kernelsu.org/guide/app-profile.html): Lock root privileges in a cage. 4.
4. Bringing back non-GKI/GKI 1.0 support
5. More customization



## License

- The file in the “kernel” directory is [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- All other parts except the “kernel” directory are [GPL-3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html).

## Contributions

- [KernelSU](https://github.com/tiann/KernelSU): original project
- [MKSU](https://github.com/5ec1cff/KernelSU): Used project
- [RKSU](https://github.com/rsuntk/KernelsU)：Re-support of non-GKI devices using the kernel of this project
- [susfs](https://gitlab.com/simonpunk/susfs4ksu)：Used susfs file system
- [KernelSU](https://git.zx2c4.com/kernel-assisted-superuser/about/): KernelSU conceptualization
- [Magisk](https://github.com/topjohnwu/Magisk): Powerful root utility
- [genuine](https://github.com/brevent/genuine/): APK v2 Signature Verification
- [Diamorphine](https://github.com/m0nad/Diamorphine): Some rootkit skills.
