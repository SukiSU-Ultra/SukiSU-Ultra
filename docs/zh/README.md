<img align='right' src='zakomonochrome-128.svg' width='100px' alt="logo">

# SukiSU Ultra

[English](../README.md) | **简体中文** | [日本語](../ja/README.md) | [Türkçe](../tr/README.md)

一个 Android 上基于内核的 root 方案，由 [`tiann/KernelSU`](https://github.com/tiann/KernelSU) 分叉而来，添加了一些有趣的变更。

[![最新发行](https://img.shields.io/github/v/release/SukiSU-Ultra/SukiSU-Ultra?label=Release&logo=github)](https://github.com/tiann/KernelSU/releases/latest)
[![频道](https://img.shields.io/badge/Follow-Telegram-blue.svg?logo=telegram)](https://t.me/Sukiksu)
[![协议: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![GitHub 协议](https://img.shields.io/github/license/tiann/KernelSU?logo=gnu)](/LICENSE)

## 特性

1. 基于内核的 `su` 和权限管理。
2. 基于 [Magic Mount](https://github.com/5ec1cff/KernelSU) 的模块系统。
3. [App Profile](https://kernelsu.org/zh_CN/guide/app-profile.html): 把 Root 权限关进笼子里。
4. 支持 non-GKI 与 GKI 1.0。
5. KPM 支持
6. 可调整管理器外观，可自定义 susfs 配置。

## 兼容状态

- KernelSU 官方支持 GKI 2.0 的设备（内核版本 5.10 以上）。

- 旧内核也是兼容的（最低 4.14+），不过需要自己编译内核。

- With more backports, KernelSU can supports 3.x kernel (3.4-3.18).

- 目前支持架构 : `arm64-v8a`、`armeabi-v7a (bare)`、`X86_64`。

## 安装指导

查看 [`guide/installation.md`](guide/installation.md)

## 集成指导

查看 [`guide/how-to-integrate.md`](guide/how-to-integrate.md)

## 参与翻译

要将 SukiSU 翻译成您的语言，或完善现有的翻译，请使用 [Crowdin](https://crowdin.com/project/SukiSU-Ultra).

## KPM 支持

- 基于 KernelPatch 开发，移除了与 KernelSU 重复的功能。
- 正在进行（WIP）：通过集成附加功能来扩展 APatch 兼容性，以确保跨不同实现的兼容性。

**开源仓库**: [https://github.com/ShirkNeko/SukiSU_KernelPatch_patch](https://github.com/ShirkNeko/SukiSU_KernelPatch_patch)

**KPM 模板**: [https://github.com/udochina/KPM-Build-Anywhere](https://github.com/udochina/KPM-Build-Anywhere)

> [!Note]
>
> 1. 需要 `CONFIG_KPM=y`
> 2. Non-GKI 设备需要 `CONFIG_KALLSYMS=y` and `CONFIG_KALLSYMS_ALL=y`
> 3. 对于低于 `4.19` 的内核，需要从 `4.19` 的 `set_memory.h` 进行反向移植。

## Troubleshooting

1. 卸载管理器后系统卡住？
   卸载 _com.sony.playmemories.mobile_

## 许可证

- 目录 `kernel` 下所有文件为 [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)。
- 有动漫人物图片表情包的这些文件 `ic_launcher(?!.*alt.*).*` 的图像版权为[怡子曰曰](https://space.bilibili.com/10545509)所有，图像中的知识产权由[明风 OuO](https://space.bilibili.com/274939213)所有，矢量化由 @MiRinChan 完成，在使用这些文件之前，除了必须遵守 [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt) 以外，还需要遵守向前两者索要使用这些艺术内容的授权。
- 除上述文件及目录的其他部分均为 [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html)。

## 赞助

- [ShirkNeko](https://afdian.com/a/shirkneko) (SukiSU 主要维护者)
- [weishu](https://github.com/sponsors/tiann) (KernelSU 作者)

## ShirkNeko 的赞助列表

- [Ktouls](https://github.com/Ktouls) 非常感谢你给我带来的支持
- [zaoqi123](https://github.com/zaoqi123) 请我喝奶茶也不错
- [wswzgdg](https://github.com/wswzgdg) 非常感谢对此项目的支持
- [yspbwx2010](https://github.com/yspbwx2010) 非常感谢
- [DARKWWEE](https://github.com/DARKWWEE) 感谢老哥的 100 USDT
- [Saksham Singla](https://github.com/TypeFlu) 网站的提供以及维护
- [OukaroMF](https://github.com/OukaroMF) 网站域名捐赠

## 鸣谢

- [KernelSU](https://github.com/tiann/KernelSU): 上游
- [MKSU](https://github.com/5ec1cff/KernelSU): 魔法坐骑支持
- [RKSU](https://github.com/rsuntk/KernelsU): non-GKI 支持
- [susfs](https://gitlab.com/simonpunk/susfs4ksu): 隐藏内核补丁以及用户空间模组的 KernelSU 附件
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch 是内核模块 APatch 实现的关键部分

<details>
<summary>KernelSU 的鸣谢</summary>

- [kernel-assisted-superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/)：KernelSU 的灵感。
- [Magisk](https://github.com/topjohnwu/Magisk)：强大的 root 工具箱。
- [genuine](https://github.com/brevent/genuine/)：apk v2 签名验证。
- [Diamorphine](https://github.com/m0nad/Diamorphine)：一些 rootkit 技巧。
</details>
