# SukiSU Ultra
<img align='right' src='SukiSU-mini.svg' width='220px' alt="sukisu logo">

> Current branch: `main` (active development) · Forked from KernelSU, independently maintained

**English** | [简体中文](./zh/README.md)

A kernel-based root solution for Android devices, forked from [`tiann/KernelSU`](https://github.com/tiann/KernelSU), with some interesting changes added.

[![Latest release](https://img.shields.io/github/v/release/SukiSU-Ultra/SukiSU-Ultra?label=Release&logo=github)](https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/latest)
[![Channel](https://img.shields.io/badge/Follow-Telegram-blue.svg?logo=telegram)](https://t.me/Sukiksu)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![GitHub License](https://img.shields.io/github/license/SukiSU-Ultra/SukiSU-Ultra?logo=gnu)](/LICENSE)

## Features

1. Kernel-based `su` and root access management
2. [App Profile](https://sukisu.org/guide/app-profile): Lock up the root power in a cage
3. Support non-GKI and GKI 1.0
4. KPM Support
5. Built-in susfs management tool for one-click root hiding configuration; customizable manager theme.

## Compatibility Status

- SukiSU Ultra supports Android GKI 2.0 devices (kernel 5.10+).
- Older kernels (4.14+) are also compatible, but the kernel will have to be built manually.
- With more backports, kernels 3.x (3.4–3.18) can be supported.
- Currently, only `arm64-v8a`, `armeabi-v7a (bare)` and `X86_64` (some) are supported.
- **Note**: Since forking from `tiann/KernelSU`, this project has evolved independently. Compatibility is based on actual testing in this repository and no longer equals KernelSU's official support scope.

## Installation

Choose the installation method based on your device:

| Scenario | Method | Notes |
|----------|--------|-------|
| GKI device (kernel 5.10+) | Flash boot image | See [`guide/installation.md`](guide/installation.md) |
| Non-GKI / older kernel (4.14+) | Build kernel manually | See [`guide/how-to-integrate.md`](guide/how-to-integrate.md) |
| Need KPM features | Enable `CONFIG_KPM=y` | See "KPM Support" below |

Detailed steps: [`guide/installation.md`](guide/installation.md)

## Integration

See [`guide/how-to-integrate.md`](guide/how-to-integrate.md)

## KPM Support

Based on [KernelPatch](https://github.com/bmax121/KernelPatch), we removed features redundant with KSU and retained only KPM support.

**Current status**:
- ✅ Basic KPM loading is available (requires `CONFIG_KPM=y`)
- 🚧 APatch compatibility expansion is in progress (some features not yet merged)
- ⚠️ Non-GKI devices additionally require `CONFIG_KALLSYMS=y` and `CONFIG_KALLSYMS_ALL=y`
- ⚠️ Kernels below 4.19 require backporting `set_memory.h` from 4.19

**Open-source repository**: [ShirkNeko/SukiSU_KernelPatch_patch](https://github.com/ShirkNeko/SukiSU_KernelPatch_patch)  
**KPM template**: [udochina/KPM-Build-Anywhere](https://github.com/udochina/KPM-Build-Anywhere)

## Troubleshooting

1. **Device stuck after uninstalling the manager app?**  
   Uninstall `_com.sony.playmemories.mobile_`.

2. **KPM fails to load?**  
   Confirm the kernel has `CONFIG_KPM=y` enabled; Non-GKI devices also need `CONFIG_KALLSYMS=y` and `CONFIG_KALLSYMS_ALL=y`.

3. **Manager cannot detect root?**  
   Confirm the flashed kernel matches the manager version, and check that `su` is in PATH.

4. **Kernel build errors?**  
   Refer to [`guide/how-to-integrate.md`](guide/how-to-integrate.md), and confirm the kernel version meets the minimum requirement (4.14+).

## Translation

If you need to contribute to the translation of the manager, please go to [Weblate](https://hosted.weblate.org/projects/sukisu-ultra/).

<a href="https://hosted.weblate.org/engage/sukisu-ultra/"><img src="https://hosted.weblate.org/widget/sukisu-ultra/multi-auto.svg" alt="Translation status"></a>

## Sponsor

- [ShirkNeko](https://afdian.com/a/shirkneko) (maintainer of SukiSU)
- [weishu](https://github.com/sponsors/tiann) (author of KernelSU)

<details>
<summary>ShirkNeko's sponsorship list</summary>

- [Ktouls](https://github.com/Ktouls) Thanks so much for bringing me support.
- [zaoqi123](https://github.com/zaoqi123) Thanks for the milk tea.
- [wswzgdg](https://github.com/wswzgdg) Many thanks for supporting this project.
- [yspbwx2010](https://github.com/yspbwx2010) Many thanks.
- [DARKWWEE](https://github.com/DARKWWEE) 100 USDT
- [Saksham Singla](https://github.com/TypeFlu) Provide and maintain the website
- [OukaroMF](https://github.com/OukaroMF) Donation of website domain name

</details>

## License

- The files in the `kernel` directory are under [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) license.
- The images of the files `ic_launcher(?!.*alt.*).*` with anime character artwork are licensed under a special arrangement: drawn by [怡子曰曰](https://space.bilibili.com/10545509), the copyright is held by [明风 OuO](https://space.bilibili.com/274939213), and the vectorized icons are provided by this project. See [`LICENSE_icon_English`](./LICENSE_icon_English) and [`LICENSE_icon_SC`](./LICENSE_icon_SC) for details.
- Except for the files or directories mentioned above, all other parts are under [GPL-3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html) license.

## Credit

- [KernelSU](https://github.com/tiann/KernelSU): upstream
- [MKSU](https://github.com/5ec1cff/KernelSU): Magic Mount
- [RKSU](https://github.com/rsuntk/KernelsU): support non-GKI
- [susfs](https://gitlab.com/simonpunk/susfs4ksu): An addon root hiding kernel patches and userspace module for KernelSU.
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch is a key part of the APatch implementation of the kernel module

Contributions welcome via PR; translations via [Weblate](https://hosted.weblate.org/projects/sukisu-ultra/); issues via [GitHub Issues](https://github.com/SukiSU-Ultra/SukiSU-Ultra/issues).

<details>
<summary>KernelSU's credit</summary>

- [Kernel-Assisted Superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/): The KernelSU idea.
- [Magisk](https://github.com/topjohnwu/Magisk): The powerful root tool.
- [genuine](https://github.com/brevent/genuine/): APK v2 signature validation.
- [Diamorphine](https://github.com/m0nad/Diamorphine): Some rootkit skills.
</details>
