# SukiSU Nova
<img align='right' src='SukiSU-mini.svg' width='220px' alt="SukiSU Nova logo">

**English** [简体中文](./README_zh.md) |

A kernel-based root solution for Android, evolved from [`tiann/KernelSU`](https://github.com/tiann/KernelSU) with some interesting changes added.

[![Latest Release](https://img.shields.io/github/v/release/SukiSU-Nova/SukiSU-Nova?label=Release&logo=github)](https://github.com/SukiSU-Nova/SukiSU-Nova/releases/latest)
[![Channel](https://img.shields.io/badge/Follow-Telegram-blue.svg?logo=telegram)](https://t.me/Sukiksu)
[![License: GPL 3.0 or later](https://img.shields.io/badge/License-GPL%203.0%20or%20later-orange.svg?logo=gnu)](https://www.gnu.org/licenses/gpl-3.0.html)
[![GitHub License](https://img.shields.io/github/license/SukiSU-Nova/SukiSU-Nova?logo=gnu)](/LICENSE)

## Features

1. Kernel-based `su` and permission management.
2. [App Profile](https://sukisu.org/guide/app-profile): keep root access in a cage.
3. KPM support.
4. Built-in Zygisk (NyaZygisk) — no separate Zygisk module needed; running status is shown right on the home screen.
5. Theme Store: browse, install and submit themes, with multi-source mirrors, author authorization and review.
6. Kernel Extension Center: CPU/vvar spoofing, AVC log spoofing, version spoofing, SUSFS and mount view hiding — all in one place.
7. Built-in SUSFS management tools with one-tap root hiding configuration.
8. Dual UI: Miuix / Material 3 Expressive; supports Miuix splash screen, module banners and sorting, temporary root grant, and kernel-free preview.

## Compatibility

- SukiSU Nova supports GKI 2.0 devices (kernel version 5.10 and above).
- Older kernels are also compatible (minimum 4.14+), but you need to compile the kernel yourself.
- With additional backports, 3.x kernels (3.4–3.18) can be supported.
- Currently supported architectures: `arm64-v8a`, `armeabi-v7a (bare)`, `X86_64`, `riscv64`.
- **Note**: This project has evolved independently since forking from `tiann/KernelSU`; compatibility is based on testing in this repository and no longer equals the official KernelSU support scope.

## Kernel Compatibility Status

| Scenario | Method | Notes |
|------|------|------|
| GKI devices (kernel 5.10+) | LKM mode recommended | |
| Non-GKI / old kernels (3.0+) | Compile the kernel manually | Please refer to the integration guide on the website |
| KPM features required | Requires `CONFIG_KPM=y` | See "KPM Support" below |


## KPM Support

Developed based on [KernelPatch](https://github.com/bmax121/KernelPatch), with features duplicating KernelSU removed — only KPM support is kept.

**Current status**:
- ✅ Basic KPM loading is available (requires `CONFIG_KPM=y`)
- 🚧 The APatch compatibility layer is still being completed (some features are not yet merged)
- ⚠️ Non-GKI devices additionally require `CONFIG_KALLSYMS=y` and `CONFIG_KALLSYMS_ALL=y`
- ⚠️ Kernels below 4.19 need `set_memory.h` backported from 4.19

**Open-source repository**: [ShirkNeko/SukiSU_KernelPatch_patch](https://github.com/ShirkNeko/SukiSU_KernelPatch_patch)  
**KPM template**: [udochina/KPM-Build-Anywhere](https://github.com/udochina/KPM-Build-Anywhere)

## Troubleshooting

1. **KPM fails to load?**  
   Make sure the kernel has `CONFIG_KPM=y` enabled; Non-GKI devices also need `CONFIG_KALLSYMS=y` and `CONFIG_KALLSYMS_ALL=y`.

2. **The manager doesn't recognize root?**  
   Make sure the flashed kernel matches the manager version, and check whether `su` is in PATH.

3. **Kernel compilation errors?**  
   Refer to [`guide/how-to-integrate.md`](guide/how-to-integrate.md), and make sure the kernel version meets the minimum requirement (4.14+).

## Contributing Translations

To translate SukiSU Nova into your language, or improve existing translations, please use [Weblate](https://hosted.weblate.org/projects/sukisu-ultra/).

<a href="https://hosted.weblate.org/engage/sukisu-ultra/"><img src="https://hosted.weblate.org/widget/sukisu-ultra/multi-auto.svg" alt="Translation status"></a>

## License

- All files under the `kernel` directory are licensed under [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- The `ic_launcher(?!.*alt.*).*` icon files featuring anime character images are licensed in a special form: drawn by 怡子曰曰 (Yizi Yueyue), copyright owned by 明风OuO (Mingfeng OuO). The vectorized icons are provided by this project. See [`LICENSE_icon_English`](./LICENSE_icon_English) and [`LICENSE_icon_SC`](./LICENSE_icon_SC) for details.
- All other parts, except the files and directories mentioned above, are licensed under [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

## Sponsors

- [ShirkNeko](https://afdian.com/a/shirkneko) (lead maintainer of SukiSU)
- [weishu](https://github.com/sponsors/tiann) (author of KernelSU)

<details>
<summary>ShirkNeko's sponsor list</summary>

- [Ktouls](https://github.com/Ktouls) Thank you so much for your support
- [zaoqi123](https://github.com/zaoqi123) Treating me to milk tea is nice too
- [wswzgdg](https://github.com/wswzgdg) Thank you so much for supporting this project
- [yspbwx2010](https://github.com/yspbwx2010) Thank you very much
- [DARKWWEE](https://github.com/DARKWWEE) Thanks bro for the 100 USDT
- [Saksham Singla](https://github.com/TypeFlu) Providing and maintaining the website
- [OukaroMF](https://github.com/OukaroMF) Website domain donation

</details>

## Acknowledgements

- [KernelSU](https://github.com/tiann/KernelSU): upstream
- [/xxksu](https://github.com/backslashxx/KernelSU): reference for kernel compatibility support
- [susfs](https://gitlab.com/simonpunk/susfs4ksu): KernelSU addon with hiding kernel patches and userspace modules
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch is a key part of the kernel module implementation in APatch
- NyaZygisk: built-in Zygisk implementation

PRs are welcome; for translations please go to [Weblate](https://hosted.weblate.org/projects/sukisu-ultra/); for issue reports please open an [Issue](https://github.com/SukiSU-Nova/SukiSU-Nova/issues).

<details>
<summary>KernelSU acknowledgements</summary>

- [kernel-assisted-superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/): inspiration for KernelSU.
- [Magisk](https://github.com/topjohnwu/Magisk): the powerful root toolbox.
- [genuine](https://github.com/brevent/genuine/): apk v2 signature verification.
- [Diamorphine](https://github.com/m0nad/Diamorphine): some rootkit tricks.
</details>
