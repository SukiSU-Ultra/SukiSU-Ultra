# SukiSU Ultra

**日本語** | [简体中文](README.md) | [English](README-en.md)

[KernelSU](https://github.com/tiann/KernelSU) をベースとした Android デバイスの root ソリューション

**試験中なビルドです！自己責任で使用してください！**<br>
このソリューションは [KernelSU](https://github.com/tiann/KernelSU) に基づいていますが、試験中なビルドです。

> これは非公式なフォークです。すべての権利は [@tiann](https://github.com/tiann) に帰属します。
>
> ただし、将来的には KSU とは別に管理されるブランチとなる予定です。

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

## 使い方

### GKI

1. Xiaomi、Redmi、Samsung などのデバイス (Meizu、OnePlus、Realme、OPPO などのカーネルを変更したメーカー以外)
2. `その他のリンク`の項目で言及されているカーネル名が、AnyKernel3 で終わるビルド済みの GKI カーネルを TWRP などのリカバリーでフラッシュします。
3. 一般的な .zip の接頭辞を持つパッケージは汎用的になります。ただし、デバイスに MediaTek 製の SoC が搭載されている場合は、.gz の接頭辞を持つパッケージを使用する必要があります。その他に .lz4 の接頭辞を持つパッケージは Google 製デバイス専用です。

### OnePlus

1. `その他のリンク`の項目に記載されているリンクを開き、デバイス情報を使用してカスタマイズされたカーネルをビルドし、AnyKernel3 の接頭辞を持つ .zip ファイルをフラッシュします。

> [!Note]
> - 5.10、5.15、6.1、6.6 などのカーネルバージョンの最初の 2 文字のみを入力する必要があります。
> - SoC のコードネームは自分で検索してください。通常は、数字がなく英語表記のみです。
> - ブランチと構成ファイルは、OnePlus オープンソースカーネルリポジトリから見つけることができます。

## 機能

1. カーネルベースな `su` および root アクセスの管理。
2. [OverlayFS](https://en.wikipedia.org/wiki/OverlayFS) モジュールシステムではなく、 5ec1cff 氏の [Magic Mount](https://github.com/5ec1cff/KernelSU) に基づいています。
3. [アプリプロファイル](https://kernelsu.org/guide/app-profile.html): root 権限をケージ内にロックします。 
4. 非 GKI / GKI 1.0 の対応を復活
5. その他のカスタマイズ
6. KPM カーネルモジュールに対応

## ライセンス

- “kernel” ディレクトリ内のファイルは [GPL-2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.ja.html) のみライセンス下にあります。
- “kernel” ディレクトリを除くその他すべての部分は [GPL-3.0 またはそれ以降](https://www.gnu.org/licenses/gpl-3.0.html) のライセンス下にあります。

## スポンサーシップの一覧

- [Ktouls](https://github.com/Ktouls) 応援をしてくれたことに感謝。
- [zaoqi123](https://github.com/zaoqi123) ミルクティーを買ってあげるのも良い考えですね。
- [wswzgdg](https://github.com/wswzgdg) このプロジェクトを支援していただき、ありがとうございます。
- [yspbwx2010](https://github.com/yspbwx2010) どうもありがとう。
- [DARKWWEE](https://github.com/DARKWWEE) ラオウ100USDTありがとう！

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
