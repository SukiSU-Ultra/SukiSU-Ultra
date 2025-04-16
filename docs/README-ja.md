# SukiSU

**日本語** | [简体中文](README.md) | [English](README-en.md)

[KernelSU](https://github.com/tiann/KernelSU) をベースとした Android デバイスの root ソリューション

**試験中なビルドです！自己責任で使用してください！**<br>
このソリューションは [KernelSU](https://github.com/tiann/KernelSU) に基づいていますが、試験中なビルドです。

>
> これは非公式なフォークです。すべての権利は [@tiann](https://github.com/tiann) に帰属します。
>
>ただし、将来的には KSU とは別に管理されるブランチとなる予定です。

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
- KernelPatch に基づいて重複した KSU の機能を削除、KPM の対応を維持させています。
- KPM 機能の整合性を確保するために、APatch の互換機能を更に向上させる予定です。


オープンソースアドレス: https://github.com/ShirkNeko/SukiSU_KernelPatch_patch


KPM テンプレートのアドレス: https://github.com/udochina/KPM-Build-Anywhere

## その他のリンク
SukiSU と susfs をベースにコンパイルされたプロジェクトです。
- [GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) 
- [OnePlus](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)

## フックの方式
- この方式は (https://github.com/rsuntk/KernelSU) のフック方式を参照してください。

1. **KPROBES フック:**
    - この方式は GKI (5.10 - 6.x) のカーネルのみに対応しています。GKI 以外のカーネルは手動でフックを使用する必要があります。
    - 読み込み可能なカーネルモジュールの場合 (LKM)
    - GKI カーネルのデフォルトとなるフック方式
    - `CONFIG_KPROBES=y` が必要です。
2. **手動でフック:**
    - GKI (5.10 - 6.x) のカーネルの場合、カーネルの defconfig に `CONFIG_KSU_MANUAL_HOOK=y` を追加して `#ifdef CONFIG_KSU` ではなく `#ifdef CONFIG_KSU_MANUAL_HOOK` を使用して KernelSU フックを保護するようにしてください。
    - 標準の KernelSU フック: https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source
    - backslashxx syscall フック: https://github.com/backslashxx/KernelSU/issues/5
    - KPROBES を手動で統合する一部の非 GKI デバイスでは手動の VFS フック `new_hook.patch` パッチは不要です。


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
5. その他のカスタマイズ
6. KPM カーネルモジュールに対応



## ライセンス

- The file in the “kernel” directory is under [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) license.
- All other parts except the “kernel” directory are under [GPL-3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html) license.

## スポンサーシップの一覧
- [Ktouls](https://github.com/Ktouls) 応援をしてくれたことに感謝。
- [zaoqi123](https://github.com/zaoqi123) ミルクティーを買ってあげるのも良い考えですね。
- [wswzgdg](https://github.com/wswzgdg) このプロジェクトを支援していただき、ありがとうございます。
- [yspbwx2010](https://github.com/yspbwx2010) どうもありがとう。




上記の一覧にあなたの名前がない場合は、できるだけ早急に更新しますので再度ご支援をお願いします。

## 貢献者

- [KernelSU](https://github.com/tiann/KernelSU): オリジナルのプロジェクトです。
- [MKSU](https://github.com/5ec1cff/KernelSU): 使用しているプロジェクトです。
- [RKSU](https://github.com/rsuntk/KernelsU): このプロジェクトのカーネルを使用して非 GKI デバイスのサポートを追加しています。
- [susfs](https://gitlab.com/simonpunk/susfs4ksu)：使用している susfs ファイルシステムです。
- [KernelSU](https://git.zx2c4.com/kernel-assisted-superuser/about/): KernelSU について。
- [Magisk](https://github.com/topjohnwu/Magisk): パワフルな root ユーティリティです。
- [genuine](https://github.com/brevent/genuine/): APK v2 署名認証で使用しています。
- [Diamorphine](https://github.com/m0nad/Diamorphine): いくつかの rootkit ユーティリティを使用しています。
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch はカーネルモジュールの APatch 実装での重要な部分となります。
