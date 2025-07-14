# SukiSU Ultra

**简体中文** | [English](README-en.md) | [日本語](README-ja.md) | [Türkçe](README-tr.md)

基于 [KernelSU](https://github.com/tiann/KernelSU) 的安卓设备 root 解决方案

**实验性! 使用风险自负!**

> 这是非官方分支，[@tiann](https://github.com/tiann) 有权保留所有权利
>
> 但是，我们将会在未来成为一个单独维护的 KSU 分支

## 如何添加

在内核源码的根目录下执行以下命令：

使用 main 分支 (不支持非 GKI 设备构建) (需要手动集成 susfs)

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

使用支持非 GKI 设备的分支 (需要手动集成 susfs)

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s nongki
```

## 如何集成 susfs

1. 直接使用 susfs-main 或者其他 susfs-\* 分支，不需要再集成 susfs (支持非 GKI 设备构建)

> [!Note]
>
> - 因 SuSFS 版本的变化和不可测问题
> - 本 susfs-main 分支只在完整更新后再合并最新新版本
> - 请随时留意 susfs 分支的变化情况以免导致构建失败以及各种版本导致的不兼容问题

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-main
```

## 钩子方法

- 此部分引用自 [rsuntk 的钩子方法](https://github.com/rsuntk/KernelSU)

1. **KPROBES 钩子：**

   - 用于可加载内核模块 (LKM)
   - GKI 2.0 内核的默认钩子方法
   - 需要 `CONFIG_KPROBES=y`

2. **手动钩子：**

   - 标准的 KernelSU 钩子：https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source

   - backslashxx 的 syscall 手动钩子：https://github.com/backslashxx/KernelSU/issues/5 (v1.5 版本暂不可用，如要使用请使用 v1.4 版本，或者标准 KernelSU 钩子)

   - 非 GKI 内核的默认挂钩方法
   - 需要 `CONFIG_KSU_MANUAL_HOOK=y`

## KPM 支持

- 我们基于 KernelPatch 去掉了和 KSU 重复的功能，仅保留了 KPM 支持
- 我们将会引入更多的兼容 APatch 的函数来确保 KPM 功能的完整性

开源地址: https://github.com/ShirkNeko/SukiSU_KernelPatch_patch

KPM 模板地址: https://github.com/udochina/KPM-Build-Anywhere

> [!Note]
>
> 1. 需要 `CONFIG_KPM=y`
> 2. 非 GKI 设备还需要 `CONFIG_KALLSYMS=y` 和 `CONFIG_KALLSYMS_ALL=y`
> 3. 部分内核 `4.19` 以下源码还需要从 `4.19` 向后移植头文件 `set_memory.h`

## 如何进行系统更新保留 ROOT

- OTA 后先不要重启，进入管理器刷写/修补内核界面，找到 `GKI/non_GKI安装` 选择需要刷写的 Anykernel3 内核压缩文件，选择与现在系统运行槽位相反的槽位进行刷写并重启即可保留 GKI 模式更新（暂不支持所有非 GKI 设备使用这种方法，请自行尝试。非 GKI 设备使用 TWRP 刷写是最稳妥的）
- 或者使用 LKM 模式的安装到未使用的槽位（OTA 后）

## 兼容状态

- KernelSU（v1.0.0 之前版本）正式支持 Android GKI 2.0 设备（内核 5.10+）

- 旧内核（4.4+）也兼容，但必须手动构建内核

- 通过更多的反向移植，KernelSU 可以支持 3.x 内核（3.4-3.18）

- 目前支持 `arm64-v8a` ，`armeabi-v7a (bare)` 和部分 `X86_64`

## 更多链接

**如果你需要为管理器提交翻译请前往** https://crowdin.com/project/SukiSU-Ultra

基于 SukiSU 和 susfs 编译的项目

- [增强 GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS)（包括 ZRAM 算法等补丁、KPM、susfs 等）
- [GKI](https://github.com/MiRinFork/GKI_SukiSU_SUSFS/releases)（若增强 GKI boot 失败再尝试这份，这份没有 KPM 等修改，只有 susfs）
- [一加](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)

## 使用方法

### 普适的 GKI

请**全部**参考 https://kernelsu.org/zh_CN/guide/installation.html

> [!Note]
>
> 1. 适用于如小米、红米、三星等的 GKI 2.0 的设备 (不包含魔改内核的厂商如魅族、一加、真我和 oppo)
> 2. 找到[更多链接](#%E6%9B%B4%E5%A4%9A%E9%93%BE%E6%8E%A5)里的 GKI 构建的项目。找到设备内核版本。然后下载下来，用 TWRP 或者内核刷写工具刷入带 AnyKernel3 后缀的压缩包即可。Pixel 请使用不是增强的 GKI。
> 3. 一般不带后缀的 .zip 压缩包是未压缩的，gz 后缀的为天玑机型所使用的压缩方式

### 一加

1.找到更多链接里的一加项目进行自行填写，然后云编译构建，最后刷入带 AnyKernel3 后缀的压缩包即可

> [!Note]
>
> - 内核版本只需要填写前两位即可，如 5.10，5.15，6.1，6.6
> - 处理器代号请自行搜索，一般为全英文不带数字的代号
> - 分支和配置文件请自行到一加内核开源地址进行填写

## 特点

1. 基于内核的 `su` 和 root 访问管理
2. 基于 5ec1cff 的 [Magic Mount](https://github.com/5ec1cff/KernelSU) 的模块系统
3. [App Profile](https://kernelsu.org/guide/app-profile.html)：将 root 权限锁在笼子里
4. 恢复对非 GKI 2.0 内核的支持
5. 更多自定义功能
6. 对 KPM 内核模块的支持
7. 引入 SuSFS 配置的管理器以及进阶功能

## 疑难解答

1. 卸载 KernelSU 管理器设备卡死。→ 卸载包名为 com.sony.playmemories.mobile 的应用。

## 许可证

- `kernel` 目录下的文件是 [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)。
- 有动漫人物图片表情包的这些文件 `ic_launcher(?!.*alt.*).*` 的图像版权为[怡子曰曰](https://space.bilibili.com/10545509)所有，图像中的知识产权由[明风 OuO](https://space.bilibili.com/274939213)所有，矢量化由 @MiRinChan 完成，在使用这些文件之前，除了必须遵守 [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt) 以外，还需要遵守向前两者索要使用这些艺术内容的授权。
- 除了以上所述的文件或目录外，所有其他部分均为 [GPL-3.0 或更高版本](https://www.gnu.org/licenses/gpl-3.0.html)。

## 爱发电链接

- https://afdian.com/a/shirkneko

## 赞助名单

- [Ktouls](https://github.com/Ktouls) 非常感谢你给我带来的支持
- [zaoqi123](https://github.com/zaoqi123) 请我喝奶茶也不错
- [wswzgdg](https://github.com/wswzgdg) 非常感谢对此项目的支持
- [yspbwx2010](https://github.com/yspbwx2010) 非常感谢
- [DARKWWEE](https://github.com/DARKWWEE) 感谢老哥的 100 USDT
- [Saksham Singla](https://github.com/TypeFlu) 网站的提供以及维护
- [OukaroMF](https://github.com/OukaroMF) 网站域名捐赠

## 贡献

- [KernelSU](https://github.com/tiann/KernelSU)：原始项目
- [MKSU](https://github.com/5ec1cff/KernelSU)：使用的项目
- [RKSU](https://github.com/rsuntk/KernelsU)：使用该项目的 kernel 对非 GKI 设备重新进行支持
- [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu)：使用的 susfs 文件系统
- [kernel-assisted-superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/)：KernelSU 的构想
- [Magisk](https://github.com/topjohnwu/Magisk)：强大的 root 工具
- [genuine](https://github.com/brevent/genuine/)：APK v2 签名验证
- [Diamorphine](https://github.com/m0nad/Diamorphine)：一些 rootkit 技能
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch 是 APatch 实现内核模块的关键部分
