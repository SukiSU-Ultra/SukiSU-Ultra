# SukiSU

**简体中文** | [English](README-en.md)

基于 [KernelSU](https://github.com/tiann/KernelSU) 的安卓设备 root 解决方案

**实验性!使用风险自负!**


>
> 这是非官方分叉，保留所有权利 [@tiann](https://github.com/tiann)
>
> 这是个基于个人使用二改的项目，仅限个人研究开发使用


## 如何添加
在内核源码的根目录下执行此命令

```
curl -LSs "https://raw.githubusercontent.com/ShirkNeko/KernelSU/main/kernel/setup.sh" | bash -s susfs-dev
```

## 如何使用集成susfs

直接使用 susfs-dev 分支，不需要打任何补丁


或者对默认分支进行补丁，补丁文件在 [patch](../patch) 目录里


## 钩子方法
- 该方法引用至(https://github.com/rsuntk/KernelSU)的钩子手册

1. **KPROBES钩子:**
    - 此分叉仅支持 GKI（5.10 - 6.x）内核,所有非 GKI 内核都必须使用手动钩子
    - 用于可加载内核模块 (LKM)
    - GKI 内核的默认挂钩方法
    - 需要 `CONFIG_KPROBES=y`
2. **钩子手册:**
    - 对于 GKI（5.10 - 6.x）内核，在内核 defconfig 中添加 `CONFIG_KSU_MANUAL_HOOK=y` 并确保使用 `#ifdef CONFIG_KSU_MANUAL_HOOK` 而不是 `#ifdef CONFIG_KSU` 来保护 KernelSU 挂钩
    - 标准 KernelSU 钩子： https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source
    - backslashxx的系统调用钩子： https://github.com/backslashxx/KernelSU/issues/5
    - 部分手动集成KPROBES的非GKI设备不需要手动VFS钩子 `new_hook.patch` 补丁


## 更多链接
基于 Sukisu 和 susfs 编译的项目
- [GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) 
- [一加](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)


## 使用方法
[GKI]
1.如小米红米三星等设备（不包含魔改内核的厂商如：魅族，一加真我oppo）
2.找到更多链接里的GKI构建的项目找到设备内核版本直接下载用TWRP或者内核刷写工具刷入带AnyKernel3后缀的压缩包即可
3.一般不带后缀的.zip压缩包是通用，gz后缀为天玑机型专用，lz4后缀为谷歌系机型专用，一般刷不带后缀即可

[一加]
1.找到更多链接里的一加项目进行自行填写，然后云编译构建，最后刷入带AnyKernel3后缀的压缩包即可
注意事项：内核版本只需要填写前两位即可如5.10，5.15，6.1，6.6
- 处理器代号请自行搜索，一般为全英文不带数字的代号
- 分支和配置文件请自行到一加内核开源地址进行填写


## 特点

1. 基于内核的 `su` 和 root 访问管理。
2. 非基于 [OverlayFS](https://en.wikipedia.org/wiki/OverlayFS) 的模块系统。
3. [App Profile](https://kernelsu.org/guide/app-profile.html)： 将 root 权限锁在笼子里。
4. 恢复非 GKI/GKI 1.0 支持
5. 更多自定义功能


## 许可证

- " kernel "目录下的文件是[GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)。
- 除 “kernel ”目录外，所有其他部分均为[GPL-3.0 或更高版本](https://www.gnu.org/licenses/gpl-3.0.html)。

## 贡献

- [KernelSU](https://github.com/tiann/KernelSU)： 原始项目
- [MKSU](https://github.com/5ec1cff/KernelSU)：使用的项目
- [RKSU](https://github.com/rsuntk/KernelsU):使用该项目的kernel对非GKI设备进行重新支持
- [susfs](https://gitlab.com/simonpunk/susfs4ksu)：使用的susfs文件系统
- [kernel-assisted-superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/)： KernelSU 的构想
- [Magisk](https://github.com/topjohnwu/Magisk)： 强大的 root 工具
- [genuine](https://github.com/brevent/genuine/)： APK v2 签名验证
- [Diamorphine](https://github.com/m0nad/Diamorphine)： 一些 rootkit 技能
