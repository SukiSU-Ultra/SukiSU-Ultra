# SukiSU Ultra

**简体中文** | [English](README-en.md)

基于 [KernelSU](https://github.com/tiann/KernelSU) 的安卓设备 root 解决方案

**实验性! 使用风险自负!**


>
> 这是非官方分支，保留所有权利 [@tiann](https://github.com/tiann)
> 但是，我们将会在未来成为一个单独维护的KSU分支
>


## 如何添加
在内核源码的根目录下执行以下命令：

使用 susfs-dev 分支（已集成susfs，带非GKI设备的支持）

```
curl -LSs "https://raw.githubusercontent.com/ShirkNeko/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-dev
```


使用 main 分支
```
curl -LSs "https://raw.githubusercontent.com/ShirkNeko/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

## 如何集成 susfs

1. 直接使用 susfs-stable 或者 susfs-dev 分支，不需要再集成 susfs

## 钩子方法
- 此部分引用自 [rsuntk 的钩子方法](https://github.com/rsuntk/KernelSU)

1. **KPROBES 钩子：**
    - 此方法仅支持 GKI 2.0 (5.10 - 6.x) 内核, 所有非 GKI 2.0 内核都必须使用手动钩子
    - 用于可加载内核模块 (LKM)
    - GKI 2.0 内核的默认钩子方法
    - 需要 `CONFIG_KPROBES=y`
2. **手动钩子：**
    - 对于 GKI 2.0 (5.10 - 6.x) 内核，需要在对应设备的 defconfig 文件中添加 `CONFIG_KSU_MANUAL_HOOK=y` 并确保使用 `#ifdef CONFIG_KSU_MANUAL_HOOK` 而不是 `#ifdef CONFIG_KSU` 来保护 KernelSU 钩子
    - 标准的 KernelSU 钩子：https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source
    - backslashxx 的 syscall 手动钩子：https://github.com/backslashxx/KernelSU/issues/5
    - 部分手动集成 KPROBES 的非 GKI 2.0 设备不需要手动 VFS 钩子 `new_hook.patch` 补丁


## KPM支持

- 我们基于KernelPatch去掉了和KSU重复的功能，保留了KPM支持
- 我们将会引入更多的兼容APatch的函数来确保KPM功能的完整性


开源地址: https://github.com/ShirkNeko/SukiSU_KernelPatch_patch


KPM模板地址: https://github.com/udochina/KPM-Build-Anywhere


## 更多链接
基于 SukiSU 和 susfs 编译的项目
- [GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) 
- [一加](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)


## 使用方法

### GKI
1. 适用于如小米红米三星等的 GKI 2.0 的设备 (不包含魔改内核的厂商如魅族、一加、真我和 oppo)
2. 找到更多链接里的 GKI 构建的项目找到设备内核版本直接下载用TWRP或者内核刷写工具刷入带 AnyKernel3 后缀的压缩包即可
3. 一般不带后缀的 .zip 压缩包是通用，gz 后缀的为天玑机型专用，lz4 后缀的为谷歌系机型专用，一般刷不带后缀的即可

### 一加
1.找到更多链接里的一加项目进行自行填写，然后云编译构建，最后刷入带 AnyKernel3 后缀的压缩包即可

注意事项：
- 内核版本只需要填写前两位即可，如 5.10，5.15，6.1，6.6
- 处理器代号请自行搜索，一般为全英文不带数字的代号
- 分支和配置文件请自行到一加内核开源地址进行填写


## 特点

1. 基于内核的 `su` 和 root 访问管理
2. 基于 5ec1cff 的 [Magic Mount](https://github.com/5ec1cff/KernelSU) 的模块系统
3. [App Profile](https://kernelsu.org/guide/app-profile.html)：将 root 权限锁在笼子里
4. 恢复对非 GKI 2.0 内核的支持
5. 更多自定义功能
6. 对KPM内核模块的支持


## 许可证

- `kernel` 目录下的文件是 [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)。
- 除 `kernel` 目录外，所有其他部分均为 [GPL-3.0 或更高版本](https://www.gnu.org/licenses/gpl-3.0.html)。

## 赞助名单
- [Ktouls](https://github.com/Ktouls) 非常感谢你给我带来的支持
- [zaoqi123](https://github.com/zaoqi123) 请我喝奶茶也不错
- [wswzgdg](https://github.com/wswzgdg) 非常感谢对此项目的支持
- [yspbwx2010](https://github.com/yspbwx2010) 非常感谢




如果以上名单没有你的名称，我会及时更新，再次感谢大家的支持

## 贡献

- [KernelSU](https://github.com/tiann/KernelSU)：原始项目
- [MKSU](https://github.com/5ec1cff/KernelSU)：使用的项目
- [RKSU](https://github.com/rsuntk/KernelsU)：使用该项目的 kernel 对非GKI设备重新进行支持
- [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu)：使用的 susfs 文件系统
- [kernel-assisted-superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/)：KernelSU 的构想
- [Magisk](https://github.com/topjohnwu/Magisk)：强大的 root 工具
- [genuine](https://github.com/brevent/genuine/)：APK v2 签名验证
- [Diamorphine](https://github.com/m0nad/Diamorphine)：一些 rootkit 技能
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch是APatch实现内核模块的关键部分