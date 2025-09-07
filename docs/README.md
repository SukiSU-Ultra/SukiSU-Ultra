# SukiSU Ultra
<img align='right' src='SukiSU-mini.svg' width='220px' alt="sukisu logo">


**English** | [简体中文](./zh/README.md) | [日本語](./ja/README.md) | [Türkçe](./tr/README.md)

A kernel-based root solution for Android devices, forked from [`tiann/KernelSU`](https://github.com/tiann/KernelSU), and added some interesting changes.

[![Latest release](https://img.shields.io/github/v/release/SukiSU-Ultra/SukiSU-Ultra?label=Release&logo=github)](https://github.com/tiann/KernelSU/releases/latest)
[![Channel](https://img.shields.io/badge/Follow-Telegram-blue.svg?logo=telegram)](https://t.me/Sukiksu)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![GitHub License](https://img.shields.io/github/license/tiann/KernelSU?logo=gnu)](/LICENSE)

## Features

1. Kernel-based `su` and root access management
2. Module system based on [Magic Mount](https://github.com/5ec1cff/KernelSU)
3. [App Profile](https://kernelsu.org/guide/app-profile.html): Lock up the root power in a cage
4. Support non-GKI and GKI 1.0
5. KPM Support
6. Tweaks to the manager theme and the built-in susfs management tool.

## Compatibility Status

- KernelSU (before v1.0.0) officially supports Android GKI 2.0 devices (kernel 5.10+).

- Older kernels (4.4+) are also compatible, but the kernel will have to be built manually.

- With more backports, KernelSU can supports 3.x kernel (3.4-3.18).

- Currently, only `arm64-v8a`, `armeabi-v7a (bare)` and `X86_64`(some) are supported.

## Installation

See [`guide/installation.md`](guide/installation.md)

## Integration

See [`guide/how-to-integrate.md`](guide/how-to-integrate.md)

## Translation

If you need to submit a translation for the manager, please go to [Crowdin](https://crowdin.com/project/SukiSU-Ultra).

## KPM Support

- Based on KernelPatch, we removed features redundant with KSU and retained only KPM support.
- Work in Progress: Expanding APatch compatibility by integrating additional functions to ensure compatibility across different implementations.

**Open-source repository**: [https://github.com/ShirkNeko/SukiSU_KernelPatch_patch](https://github.com/ShirkNeko/SukiSU_KernelPatch_patch)

**KPM template**: [https://github.com/udochina/KPM-Build-Anywhere](https://github.com/udochina/KPM-Build-Anywhere)

> [!Note]
>
> 1. Requires `CONFIG_KPM=y`
> 2. Non-GKI devices requires `CONFIG_KALLSYMS=y` and `CONFIG_KALLSYMS_ALL=y`
> 3. For kernels below `4.19`, backporting from `set_memory.h` from `4.19` is required.

## Troubleshooting

1. Device stuck upon manager app uninstallation?
   Uninstall _com.sony.playmemories.mobile_

## Sponsor

- [ShirkNeko](https://afdian.com/a/shirkneko) (maintainer of SukiSU)
- [weishu](https://github.com/sponsors/tiann) (author of KernelSU)

## ShirkNeko's sponsorship list

- [Ktouls](https://github.com/Ktouls) Thanks so much for bringing me support.
- [zaoqi123](https://github.com/zaoqi123) Thanks for the milk tea.
- [wswzgdg](https://github.com/wswzgdg) Many thanks for supporting this project.
- [yspbwx2010](https://github.com/yspbwx2010) Many thanks.
- [DARKWWEE](https://github.com/DARKWWEE) 100 USDT
- [Saksham Singla](https://github.com/TypeFlu) Provide and maintain the website
- [OukaroMF](https://github.com/OukaroMF) Donation of website domain name

## License

- The file in the “kernel” directory is under [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) license.
- The images of the files `ic_launcher(?!.*alt.*).*` with anime character sticker are copyrighted by [怡子曰曰](https://space.bilibili.com/10545509), the Brand Intellectual Property in the images is owned by [明风 OuO](https://space.bilibili.com/274939213), and the vectorization is done by @MiRinChan. Before using these files, in addition to complying with [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt), you also need to comply with the authorization of the two authors to use these artistic contents.
- Except for the files or directories mentioned above, all other parts are under [GPL-3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html) license.

## Credit

- [KernelSU](https://github.com/tiann/KernelSU): upstream
- [MKSU](https://github.com/5ec1cff/KernelSU): Magic Mount
- [RKSU](https://github.com/rsuntk/KernelsU): support non-GKI
- [susfs](https://gitlab.com/simonpunk/susfs4ksu): An addon root hiding kernel patches and userspace module for KernelSU.
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch is a key part of the APatch implementation of the kernel module

<details>
<summary>KernelSU's credit</summary>

- [Kernel-Assisted Superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/): The KernelSU idea.
- [Magisk](https://github.com/topjohnwu/Magisk): The powerful root tool.
- [genuine](https://github.com/brevent/genuine/): APK v2 signature validation.
- [Diamorphine](https://github.com/m0nad/Diamorphine): Some rootkit skills.
</details>
