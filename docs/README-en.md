# SukiSU Ultra

**English** | [简体中文](README.md) | [日本語](README-ja.md)

Android device root solution based on [KernelSU](https://github.com/tiann/KernelSU)

**Experimental! Use at your own risk!** This solution is based on [KernelSU](https://github.com/tiann/KernelSU) and is experimental!

> This is an unofficial fork. All rights are reserved to [@tiann](https://github.com/tiann)
>
> However, we will be a separately maintained branch of KSU in the future

- Fully adapted for non-GKI devices (susfs-dev and unsusfs-patched dev branches only)

## How to add

Use the susfs-stable or susfs-dev branch (integrated susfs with support for non-GKI devices)
```
curl -LSs "https://raw.githubusercontent.com/ShirkNeko/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-dev
```

Use the main branch
```
curl -LSs "https://raw.githubusercontent.com/ShirkNeko/KernelSU/main/kernel/setup.sh" | bash -s main
```

## How to use integrated susfs

1. Use the susfs-dev branch directly without any patching

## KPM support

- We have removed duplicate KSU functions based on KernelPatch and retained KPM support.
- We will introduce more APatch-compatible functions to ensure the integrity of KPM functionality.

Open source address: https://github.com/ShirkNeko/SukiSU_KernelPatch_patch

KPM template address: https://github.com/udochina/KPM-Build-Anywhere

## More links

Projects compiled based on Sukisu and susfs
- [GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) 
- [OnePlus](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)

## Hook method
- This method references the hook method from (https://github.com/rsuntk/KernelSU)

1. **KPROBES hook:**
    - This method only supports GKI (5.10 - 6.x) kernels, and all non-GKI kernels must use manual hooks.
    - For Loadable Kernel Modules (LKM)
    - Default hooking method for GKI kernels
    - Requires `CONFIG_KPROBES=y`.

2. **Manual hooks:**
    - For GKI (5.10 - 6.x) kernels, add `CONFIG_KSU_MANUAL_HOOK=y` to the kernel defconfig and make sure to protect KernelSU hooks by using `#ifdef CONFIG_KSU_MANUAL_HOOK` instead of `#ifdef CONFIG_KSU`.
    - Standard KernelSU hooks: https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source
    - backslashxx syscall hooks: https://github.com/backslashxx/KernelSU/issues/5
    - Some non-GKI devices that manually integrate KPROBES do not require the manual VFS hook `new_hook.patch` patch

## Usage

### GKI

1. such as Xiaomi, Redmi, Samsung, and other devices (does not include manufacturers that modified the kernel like Meizu, OnePlus, RealMe, and OPPO)
2. Use the prebuilt GKI kernel, the ones with their name ending with AnyKernel3, mentioned in the 'More Links' section, and then flash it with recoveries like TWRP
3. Generally, packages with a plain .zip suffix are universal. However, if your device has a MediaTek processor, you should use the ones with .gz suffix, and packages with .lz4 suffix are dedicated to Google devices.

### OnePlus

1. Use the link mentioned in the 'More Links' section to create a customized build with your device information, and then flash the zip file with the AnyKernel3 suffix.

> [!Note]
> - You only need to fill in the first two parts of kernel versions, such as 5.10, 5.15, 6.1, or 6.6.
> - Please search for the processor codename by yourself, usually it is all English without numbers.
> - You can find the branch and configuration files from the OnePlus open-source kernel repository.

## Features

1. Kernel-based `su` and root access management.
2. Not based on [OverlayFS](https://en.wikipedia.org/wiki/OverlayFS) module system, but based on [Magic Mount](https://github.com/5ec1cff/KernelSU) from 5ec1cff
3. [App Profile](https://kernelsu.org/guide/app-profile.html): Lock root privileges in a cage. 
4. Bringing back non-GKI/GKI 1.0 support
5. More customization
6. Support for KPM kernel modules

## License

- The file in the “kernel” directory is under [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) license.
- All other parts except the “kernel” directory are under [GPL-3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html) license.

## Sponsorship list

- [Ktouls](https://github.com/Ktouls) Thanks so much for bringing me support
- [zaoqi123](https://github.com/zaoqi123) It's not a bad idea to buy me a milk tea
- [wswzgdg](https://github.com/wswzgdg) Many thanks for supporting this project
- [yspbwx2010](https://github.com/yspbwx2010) Many thanks
- [DARKWWEE](https://github.com/DARKWWEE) Thanks for the 100 USDT Lao

If the above list does not have your name, I will update it as soon as possible, and thanks again for your support!

## Contributions

- [KernelSU](https://github.com/tiann/KernelSU): original project
- [MKSU](https://github.com/5ec1cff/KernelSU): Used project
- [RKSU](https://github.com/rsuntk/KernelsU): Reintroduced the support of non-GKI devices using the kernel of this project
- [susfs](https://gitlab.com/simonpunk/susfs4ksu)：Used susfs file system
- [KernelSU](https://git.zx2c4.com/kernel-assisted-superuser/about/): KernelSU conceptualization
- [Magisk](https://github.com/topjohnwu/Magisk): Powerful root utility
- [genuine](https://github.com/brevent/genuine/): APK v2 Signature Verification
- [Diamorphine](https://github.com/m0nad/Diamorphine): Some rootkit utilities.
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch is a key part of the APatch implementation of the kernel module
