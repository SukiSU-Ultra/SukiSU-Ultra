# SukiSU Ultra

**日本語** | [简体中文](README.md) | [English](README-en.md) | [Türkçe](README-tr.md)

[KernelSU](https://github.com/tiann/KernelSU) をベースとした Android デバイスの root ソリューション

**試験中なビルドです！自己責任で使用してください！**<br>
このソリューションは [KernelSU](https://github.com/tiann/KernelSU) に基づいていますが、試験中なビルドです。

> これは非公式なフォークです。すべての権利は [@tiann](https://github.com/tiann) に帰属します。
>
> ただし、将来的には KSU とは別に管理されるブランチとなる予定です。

## 追加方法

メイン分岐の使用（GKI デバイス以外のビルドはサポートされていません。） (手動によるサスフ統合が必要)
```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

GKI以外のデバイスをサポートするブランチを使用する (手動によるサスフ統合が必要)
```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s nongki
```

## 統合された susfs の使い方

1. パッチを当てずに susfs-dev ブランチを直接使用してください (非GKIデバイスビルドをサポート)
```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-dev
```

## KPM に対応

- KernelPatch に基づいて重複した KSU の機能を削除、KPM の対応を維持させています。
- KPM 機能の整合性を確保するために、APatch の互換機能を更に向上させる予定です。

オープンソースアドレス: https://github.com/ShirkNeko/SukiSU_KernelPatch_patch

KPM テンプレートのアドレス: https://github.com/udochina/KPM-Build-Anywhere

> [!Note]
> 1. `CONFIG_KPM=y` が必要である。
> 2.非 GKI デバイスには `CONFIG_KALLSYMS=y` と `CONFIG_KALLSYMS_ALL=y` も必要です。
> 3.いくつかのカーネル `4.19` およびそれ以降のソースコードでは、 `4.19` からバックポートされた `set_memory.h` ヘッダーファイルも必要です。


## ROOT を保持するシステムアップデートの方法
- OTAの後、最初に再起動せず、マネージャのフラッシュ/パッチカーネルインターフェイスに移動し、`GKI/non_GKI 取り付け`を見つけ、フラッシュする必要があるAnykernel3カーネルzipファイルを選択し、フラッシュするためにシステムの現在の実行スロットと反対のスロットを選択し、GKIモードアップデートを保持するために再起動します（この方法は、現時点ではすべてのnon_GKIデバイスでサポートされていませんので、各自でお試しください。 (この方法は、すべての非GKIデバイスでサポートされていませんので、ご自身でお試しください)。
- または、LKMモードを使用して未使用のスロットにインストールします(OTA後)。

## 互換性ステータス
- KernelSU（v1.0.0より前のバージョン）はAndroid GKI 2.0デバイス（カーネル5.10以上）を公式にサポートしています。

- 古いカーネル（4.4+）も互換性がありますが、カーネルは手動でビルドする必要があります。

- KernelSU は追加のリバースポートを通じて 3.x カーネル (3.4-3.18) をサポートしています。

- 現在は `arm64-v8a`、`armeabi-v7a (bare)`、いくつかの `X86_64` をサポートしています。

## その他のリンク

**監督に翻訳を提出する必要がある場合は、https://crowdin.com/project/SukiSU-Ultra。

- [GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) 
- [OnePlus](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)

## フックの方式

- この方式は (https://github.com/rsuntk/KernelSU) のフック方式を参照してください。

1. **KPROBES フック:**
    - 読み込み可能なカーネルモジュールの場合 (LKM)
    - GKI カーネルのデフォルトとなるフック方式
    - `CONFIG_KPROBES=y` が必要です

2. **手動でフック:**
    - 標準の KernelSU フック: https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source
    - backslashxx syscall フック: https://github.com/backslashxx/KernelSU/issues/5
    - 非 GKI カーネル用のデフォルトフッキングメソッド
    - `CONFIG_KSU_MANUAL_HOOK=y` が必要です

## 使い方

### ユニバーサルGKI

https://kernelsu.org/zh_CN/guide/installation.html をご参照ください。

> [!Note]
> 1.Xiaomi、Redmi、Samsung などの GKI 2.0 を搭載したデバイス用 (Meizu、Yiga、Zenith、oppo などのマジックカーネルを搭載したメーカーは除く)。
> 2. [more links](#%E6%9B%B4%E5%A4%9A%E9%93%BE%E6%8E%A5) で GKI ビルドを検索します。 デバイスのカーネルバージョンを検索します。 次に、それをダウンロードし、TWRPまたはカーネルフラッシングツールを使用して、AnyKernel3の接尾辞が付いたzipファイルをフラッシュします。
> 接尾辞なしの.zipアーカイブは非圧縮で、接尾辞gzはTenguetモデルで使用されている圧縮方法です。
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

## トラブルシューティング

1.KernelSU Managerのアンインストールができない。 →パッケージ名com.sony.playmemories.mobile.KernelSU Managerのアプリケーションをアンインストールする。

## ライセンス

- `kernel` ディレクトリ以下のファイルは[GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)です。
- アニメキャラクターの絵文字を含むファイル `ic_launcher(?!.*alt.*).*` の画像は[五十根大虾仁](https://space.bilibili.com/370927)が著作権を所有しており、画像内のブランド知的財産権は[明风OuO](https://space.bilibili.com/274939213)が所有しています。ベクトル化は @MiRinChan が行っています。これらのファイルを使用する前に、[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt)に準拠することに加えて、これらの芸術コンテンツを使用するには、2人の著者の許可にも従う必要があります。
- 上記のファイルまたはディレクトリを除き、その他のすべての部分は[GPL-3.0以降](https://www.gnu.org/licenses/gpl-3.0.html)です。

## スポンサーシップの一覧

- [Ktouls](https://github.com/Ktouls) 応援をしてくれたことに感謝。
- [zaoqi123](https://github.com/zaoqi123) ミルクティーを買ってあげるのも良い考えですね。
- [wswzgdg](https://github.com/wswzgdg) このプロジェクトを支援していただき、ありがとうございます。
- [yspbwx2010](https://github.com/yspbwx2010) どうもありがとう。
- [DARKWWEE](https://github.com/DARKWWEE) ラオウ100USDTありがとう！

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
