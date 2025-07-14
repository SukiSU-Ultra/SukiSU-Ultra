# SukiSU Ultra

**日本語** | [简体中文](README.md) | [English](README-en.md) | [Türkçe](README-tr.md)

[KernelSU](https://github.com/tiann/KernelSU) をベースとした Android デバイスの root ソリューション

**試験中なビルドです！自己責任で使用してください！**<br>
このソリューションは [KernelSU](https://github.com/tiann/KernelSU) に基づいていますが、試験中なビルドです。

> これは非公式なフォークです。すべての権利は [@tiann](https://github.com/tiann) に帰属します。
>
> ただし、将来的には KSU とは別に管理されるブランチとなる予定です。

## 追加する方法

メインブランチを使用 (非 GKI のデバイスのビルドは非対応) (susfs を手動で統合が必要)

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

非 GKI のデバイスに対応するブランチを使用 (susfs を手動で統合が必要)

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s nongki
```

## 統合された susfs の使い方

1. susfs-main または他の susfs-\* ブランチを直接で使用、susfs の統合は不要 (非 GKI デバイスのビルドに対応)

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-main
```

## フックの方式

- この方式は (https://github.com/rsuntk/KernelSU) のフック方式を参照してください。

1. **KPROBES でフック:**

   - 読み込み可能なカーネルモジュールの場合 (LKM)
   - GKI カーネルのデフォルトとなるフック方式
   - `CONFIG_KPROBES=y` が必要です

2. **手動でフック:**
   - 標準の KernelSU フック: https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source
   - backslashxx syscall フック: https://github.com/backslashxx/KernelSU/issues/5
   - 非 GKI カーネル用のデフォルトフック方式
   - `CONFIG_KSU_MANUAL_HOOK=y` が必要です

## KPM に対応

- KernelPatch に基づいて重複した KSU の機能を削除、KPM の対応を維持させています。
- KPM 機能の整合性を確保するために、APatch の互換機能を更に向上させる予定です。

オープンソースアドレス: https://github.com/ShirkNeko/SukiSU_KernelPatch_patch

KPM テンプレートのアドレス: https://github.com/udochina/KPM-Build-Anywhere

> [!Note]
>
> 1. `CONFIG_KPM=y` が必要です。
> 2. 非 GKI デバイスには `CONFIG_KALLSYMS=y` と `CONFIG_KALLSYMS_ALL=y` も必要です。
> 3. いくつかのカーネル `4.19` およびそれ以降のソースコードでは、 `4.19` からバックポートされた `set_memory.h` ヘッダーファイルも必要です。

## ROOT を保持した状態でのシステムアップデートの方法

- 始めに OTA 後すぐに再起動せずにマネージャーのカーネルのフラッシュ、パッチのインターフェースを開いて`GKI/非 GKI のインストール`を見つけます。フラッシュする AnyKernel3 の zip ファイルを選択し、フラッシュする実行中のスロットと逆のスロットを選択後に再起動をして GKI モードの更新が保持できます (この方法はすべての非 GKI のデバイスが対応している訳ではないので、自分でお試しください。これは非 GKI のデバイスで TWRP を使用する最も安全な方法です)。
- または LKM モードを使用して未使用のスロットにインストールします (OTA 後)。

## 互換性の状態

- KernelSU (v1.0.0 より前) は Android GKI 2.0 のデバイス (カーネル 5.10 以降) を公式に対応しています。

- 古いカーネル (4.4 以降) も互換性がありますが、カーネルを手動で再ビルドする必要があります。

- KernelSU は追加のリバースポートを通じて 3.x カーネル (3.4-3.18) で対応可能です。

- 現在 `arm64-v8a`, `armeabi-v7a (bare)` および一部の `X86_64` に対応しています。

## その他のリンク

**マネージャーの翻訳を行う場合** https://crowdin.com/project/SukiSU-Ultra

- [その他パッチ済み GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) ZRAM パッチ、KPM、susfs が含まれています...
- [パッチの少ない GKI](https://github.com/MiRinFork/GKI_SukiSU_SUSFS/releases) susfs のみ
- [OnePlus](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)

## 使い方

### Universal GKI

**すべて**参照してください https://kernelsu.org/ja_JP/guide/installation.html

> [!Note]
>
> 1. Xiaomi、Redmi、Samsung などの GKI 2.0 を搭載したデバイス向け (Meizu、OnePlus、Zenith、Oppo などカーネルが変更されているメーカーを除く)
> 2. GKI のビルドは[その他のリンク](#その他のリンク)から入手できます。デバイスのカーネルバージョンを確認してください。ダウンロード後に TWRP またはカーネルフラッシュツールを使用して AnyKernel3 の接頭辞を持つ zip ファイルをフラッシュしてください。Pixel のユーザーは、パッチの少ない GKI を使用する必要があります。
> 3. 接頭辞のない .zip アーカイブは圧縮されていません。.gz の接頭辞は Tenguet モデルで使用される圧縮になります。

### OnePlus

1. `その他のリンク`の項目に記載されているリンクを開き、デバイス情報を使用してカスタマイズされたカーネルをビルドし、AnyKernel3 の接頭辞を持つ .zip ファイルをフラッシュします。

> [!Note]
>
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

## トラブルシューティング

1. KernelSU Manager のアンインストールが停止してしまう → com.sony.playmemories.mobile のアプリをアンインストールしてください。

## ライセンス

- 「kernel」のディレクトリ内のファイルは [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) のライセンスに基づいています。
- アニメキャラクター画像とスタンプを含むこれらのファイルの `ic_launcher(?!.*alt.*).*` は[怡子曰曰](https://space.bilibili.com/10545509)によって著作権保護されており、画像の Brand Intellectual Property は[明风 OuO](https://space.bilibili.com/274939213)によって所有され、ベクター化は @MiRinChan によって行われています。 これらのファイルを使用する前に、[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt)を遵守することに加えて、アートコンテンツを使用するために前の 2 人の作者から許可を得る必要があります。
- 上記のファイルまたはディレクトリを除き、その他のすべての部分は[GPL-3.0 以降](https://www.gnu.org/licenses/gpl-3.0.html)です。

## スポンサーシップの一覧

- [Ktouls](https://github.com/Ktouls) 応援してくれてありがとう
- [zaoqi123](https://github.com/zaoqi123) ミルクティーを買ってあげるのも良い考えですね
- [wswzgdg](https://github.com/wswzgdg) このプロジェクトにご支援いただき、ありがとうございます
- [yspbwx2010](https://github.com/yspbwx2010) ありがとうございます
- [DARKWWEE](https://github.com/DARKWWEE) ラオスから 100 USDT の支援に感謝します
- [Saksham Singla](https://github.com/TypeFlu) ウェブサイトの提供とメンテナンス
- [OukaroMF](https://github.com/OukaroMF) ウェブサイトのドメインと寄付

## 貢献者

- [KernelSU](https://github.com/tiann/KernelSU): オリジナルのプロジェクト
- [MKSU](https://github.com/5ec1cff/KernelSU): 使用しているプロジェクト
- [RKSU](https://github.com/rsuntk/KernelsU): このプロジェクトのカーネルを使用した非 GKI デバイスのサポートの再導入
- [susfs](https://gitlab.com/simonpunk/susfs4ksu): susfs ファイルシステムの使用
- [KernelSU](https://git.zx2c4.com/kernel-assisted-superuser/about/): KernelSU の概念化
- [Magisk](https://github.com/topjohnwu/Magisk): パワフルな root ユーティリティ
- [genuine](https://github.com/brevent/genuine/): APK v2 署名認証
- [Diamorphine](https://github.com/m0nad/Diamorphine): いくつかの root キットユーティリティ
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch はカーネルモジュールの APatch 実装の重要な部分での活用
