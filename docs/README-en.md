# SukiSU Ultra

**English** | [简体中文](README.md) | [日本語](README-ja.md) | [Türkçe](README-tr.md)

Android device root solution based on [KernelSU](https://github.com/tiann/KernelSU)

**Experimental! Use at your own risk!** This solution is based on [KernelSU](https://github.com/tiann/KernelSU) and is experimental!

> This is an unofficial fork. All rights are reserved to [@tiann](https://github.com/tiann)
>
> However, we will be a separately maintained branch of KSU in the future

## How to add

Using main branching (non-GKI device builds are not supported) (requires manual integration of susfs)

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

Using branches that support non-GKI devices (requires manual integration of susfs)

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s nongki
```

## How to use integrated susfs

> [!Note]
>
> - Due to SuSFS version changes and unpredictability issues
> - This susfs-main branch will only merge the latest new version after a full update
> - Please keep an eye on the susfs branch to avoid build failures and incompatibilities caused by the various versions

1. Use susfs-main or other susfs-\* branches directly, no need to integrate susfs again (supports non-GKI device builds)

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-main
```

## Hook method

- This method references the hook [method by rsuntk](https://github.com/rsuntk/KernelSU)

1. **KPROBES hook:**

   - Also used for Loadable Kernel Module (LKM)
   - Default hook method on GKI kernels.
   - Need `CONFIG_KPROBES=y`

2. **Manual hook:**
   - Standard KernelSU hook: https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source

   - backslashxx's syscall manual hook: https://github.com/backslashxx/KernelSU/issues/5 (v1.5 version is not available at the moment, if you want to use it, please use v1.4 version, or standard KernelSU hooks)

   - Default hook method on Non-GKI kernels.
   - Need `CONFIG_KSU_MANUAL_HOOK=y`
  
## KPM Support

- Based on KernelPatch, we have removed duplicates of KSU and kept only KPM support.
- We will introduce more APatch-compatible functions to ensure the integrity of KPM functionality.

Repository address: https://github.com/ShirkNeko/SukiSU_KernelPatch_patch

KPM templates: https://github.com/udochina/KPM-Build-Anywhere

> [!Note]
>
> 1. `CONFIG_KPM=y` needs to be added.
> 2. Non-GKI devices need to add `CONFIG_KALLSYMS=y` and `CONFIG_KALLSYMS_ALL=y` as well.
> 3. Some kernel source code below `4.19` also needs to be backport from `4.19` to the header file `set_memory.h`.

## How to do a system update to retain ROOT

- After OTA, don't reboot first, go to the manager flashing/patching kernel interface, find `GKI/non_GKI install` and select the Anykernel3 kernel zip file that needs to be flashed, select the slot that is opposite to the current running slot of the system for flashing, and then reboot to retain the GKI mode update （This method is not supported for all non-GKI devices, so please try it yourself. It is the safest way to use TWRP for non-GKI devices.）
- Or use LKM mode to install to the unused slot (after OTA).

## Compatibility Status

- KernelSU (versions prior to v1.0.0) officially supports Android GKI 2.0 devices (kernel 5.10+)

- Older kernels (4.4+) are also compatible, but the kernel must be built manually

- KernelSU can support 3.x kernels (3.4-3.18) through additional reverse ports

- Currently supports `arm64-v8a`, `armeabi-v7a (bare)` and some `X86_64`

## More links

**If you need to submit a translation for the manager go to** https://crowdin.com/project/SukiSU-Ultra

Projects compiled based on Sukisu and susfs

- [More patched GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) including ZRAM patches, KPM, susfs...
- [Less patched GKI](https://github.com/MiRinFork/GKI_SukiSU_SUSFS/releases) only susfs
- [OnePlus](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)

## Usage

### Universal GKI

Please **all** refer to https://kernelsu.org/zh_CN/guide/installation.html

> [!Note]
>
> 1. for devices with GKI 2.0 such as Xiaomi, Redmi, Samsung, etc. (excludes kernel-modified manufacturers such as Meizu, OnePlus, Zenith, and oppo)
> 2. Find the GKI build in [more links](#%E6%9B%B4%E5%A4%9A%E9%93%BE%E6%8E%A5). Find the device kernel version. Then download it and use TWRP or kernel flashing tool to flash the zip file with AnyKernel3 suffix. Pixel user need use _Less patched GKI_.
> 3. The .zip archive without suffix is uncompressed, the gz suffix is the compression used by Tenguet models.

### OnePlus

1. Use the link mentioned in the 'More Links' section to create a customized build with your device information, and then flash the zip file with the AnyKernel3 suffix.

> [!Note]
>
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
7. Introducing the Manager for SuSFS Configuration and Advanced Features

## Troubleshooting

1. Uninstalling the KernelSU Manager device is stuck. → Uninstall the application with package name com.sony.playmemories.mobile.

## License

- The file in the “kernel” directory is under [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) license.

- The images of the files `ic_launcher(?!.*alt.*).*` with anime character emoticons are copyrighted by [怡子曰曰](https://space.bilibili.com/10545509), the Brand Intellectual Property in the images is owned by [明风 OuO](https://space.bilibili.com/274939213), and the vectorization is done by @MiRinChan. Before using these files, in addition to complying with [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt), you also need to comply with the authorization of the two authors to use these artistic contents.

- Except for the files or directories mentioned above, all other parts are under [GPL-3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html) license.

## Afdian link
- https://afdian.com/a/shirkneko

## Sponsorship list

- [Ktouls](https://github.com/Ktouls) Thanks so much for bringing me support
- [zaoqi123](https://github.com/zaoqi123) It's not a bad idea to buy me a milk tea
- [wswzgdg](https://github.com/wswzgdg) Many thanks for supporting this project
- [yspbwx2010](https://github.com/yspbwx2010) Many thanks
- [DARKWWEE](https://github.com/DARKWWEE) Thanks for the 100 USDT Lao
- [Saksham Singla](https://github.com/TypeFlu) Website provision as well as maintenance
- [OukaroMF](https://github.com/OukaroMF) Donation of website domain name

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
