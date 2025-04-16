# SukiSU

**日本語** | [简体中文](README.md) | [English](README-en.md)

[KernelSU](https://github.com/tiann/KernelSU) をベースとした Android デバイスの root ソリューション

**試験中なビルドです！自己責任で使用してください！**<br>
このソリューションは [KernelSU](https://github.com/tiann/KernelSU) に基づいていますが、試験中なビルドです。

>
> これは非公式なフォークです。すべての権利は [@tiann](https://github.com/tiann) に帰属します。
> ただし、将来的には KSU とは別に管理されるブランチとなる予定です。
>

- GKI 非対応なデバイスに完全に適応 (susfs-dev と unsusfs-patched dev ブランチのみ)

## 追加方法
susfs-stable または susfs-dev ブランチ (GKI 非対応デバイスに対応する統合された susfs) 使用してください。

```
curl -LSs "https://raw.githubusercontent.com/ShirkNeko/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-dev
```

メインブランチを使用する場合
```
curl -LSs "https://raw.githubusercontent.com/ShirkNeko/KernelSU/main/kernel/setup.sh" | bash -s main
```
## 統合された susfs の使い方
1. パッチを当てずに susfs-dev ブランチを直接使用してください。

## KPM に対応
- カーネルパッチに基づいて重複した KSU の機能を削除、KPM の対応を維持させています。
- KPM 機能の整合性を確保するために、APatch の互換機能を更に向上させる予定です。


オープンソースアドレス: https://github.com/ShirkNeko/SukiSU_KernelPatch_patch


KPM テンプレートのアドレス: https://github.com/udochina/KPM-Build-Anywhere

## その他のリンク
SukiSU と susfs をベースにコンパイルされたプロジェクトです。
- [GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) 
- [OnePlus](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)

## フックの方式
- This method references the hook method from (https://github.com/rsuntk/KernelSU)

1. **KPROBES フック:**
    - This method only supports GKI (5.10 - 6.x) kernels, and all non-GKI kernels must use manual hooks.
    - For Loadable Kernel Modules (LKM)
    - Default hooking method for GKI kernels
    - Requires `CONFIG_KPROBES=y`.
2. **手動でフック:**
    - For GKI (5.10 - 6.x) kernels, add `CONFIG_KSU_MANUAL_HOOK=y` to the kernel defconfig and make sure to protect KernelSU hooks by using `#ifdef CONFIG_KSU_MANUAL_HOOK` instead of `#ifdef CONFIG_KSU`.
    - 標準の KernelSU フック: https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source
    - backslashxx syscall フック: https://github.com/backslashxx/KernelSU/issues/5
    - Some non-GKI devices that manually integrate KPROBES do not require the manual VFS hook `new_hook.patch` patch


## Usage
[GKI]
1. such as Xiaomi, Redmi, Samsung, and other devices (does not include manufacturers that modified the kernel like Meizu, OnePlus, RealMe, and OPPO)
2. Use the prebuilt GKI kernel, the ones with their name ending with AnyKernel3, mentioned in the 'More Links' section, and then flash it with recoveries like TWRP
3. Generally, packages with a plain .zip suffix are universal. However, if your device has a MediaTek processor, you should use the ones with .gz suffix, and packages with .lz4 suffix are dedicated to Google devices.

[OnePlus]
1. Use the link mentioned in the 'More Links' section to create a customized build with your device information, and then flash the zip file with the AnyKernel3 suffix.
Note: You only need to fill in the first two parts of kernel versions, such as 5.10, 5.15, 6.1, or 6.6.
- Please search for the processor codename by yourself, usually it is all English without numbers.
- You can find the branch and configuration files from the OnePlus open-source kernel repository.



## 機能

1. Kernel-based `su` and root access management.
2. Not based on [OverlayFS](https://en.wikipedia.org/wiki/OverlayFS) module system, but based on [Magic Mount](https://github.com/5ec1cff/KernelSU) from 5ec1cff
3. [App Profile](https://kernelsu.org/guide/app-profile.html): Lock root privileges in a cage. 
4. Bringing back non-GKI/GKI 1.0 support
5. More customization
6. Support for KPM kernel modules



## ライセンス

- The file in the “kernel” directory is under [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) license.
- All other parts except the “kernel” directory are under [GPL-3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html) license.

## スポンサーシップの一覧
- [Ktouls](https://github.com/Ktouls) Thanks so much for bringing me support
- [zaoqi123](https://github.com/zaoqi123) It's not a bad idea to buy me a milk tea
- [wswzgdg](https://github.com/wswzgdg) Many thanks for supporting this project
- [yspbwx2010](https://github.com/yspbwx2010) Many thanks




If the above list does not have your name, I will update it as soon as possible, and thanks again for your support!

## 貢献者

- [KernelSU](https://github.com/tiann/KernelSU): original project
- [MKSU](https://github.com/5ec1cff/KernelSU): Used project
- [RKSU](https://github.com/rsuntk/KernelsU): Reintroduced the support of non-GKI devices using the kernel of this project
- [susfs](https://gitlab.com/simonpunk/susfs4ksu)：Used susfs file system
- [KernelSU](https://git.zx2c4.com/kernel-assisted-superuser/about/): KernelSU conceptualization
- [Magisk](https://github.com/topjohnwu/Magisk): Powerful root utility
- [genuine](https://github.com/brevent/genuine/): APK v2 Signature Verification
- [Diamorphine](https://github.com/m0nad/Diamorphine): Some rootkit utilities.
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch is a key part of the APatch implementation of the kernel module
