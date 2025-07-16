# Installation

您可以前往 [KernelSU 文档 - 安装](https://kernelsu.org/guide/installation.html) 获取有关如何安装的参考，这里只是额外的说明。

## 通过加载可加载内核模块 (LKM) 进行安装

请参阅 [KernelSU 文档 - LKM 安装](https://kernelsu.org/guide/installation.html#lkm-installation)

从 **Android™**（商标，意为获得 Google 移动服务的许可）12 开始，搭载内核版本 5.10 或更高版本的设备必须搭载 GKI 内核。因此你或许可以使用 LKM 模式。

## 通过安装内核进行安装

请参阅 [KernelSU 文档 - GKI 模式安装](https://kernelsu.org/guide/installation.html#gki-mode-installation)

我们提供预编译的内核供您使用：

- [ShirkNeko 内核](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS)（添加了 ZRAM 压缩算法补丁、susfs 文件和 KPM 文件。适用于很多设备。）
- [MiRinFork 内核](https://github.com/MiRinFork/GKI_SukiSU_SUSFS)（添加了 susfs 文件和 KPM 文件。最接近 GKI 的内核，适用于大多数设备。）

虽然某些设备可以使用 LKM 模式安装，但无法使用 GKI 内核将其安装到设备上；因此，需要手动修改内核进行编译。例如：

- 欧珀（一加、真我）
- 魅族

此外，我们还为您的 OnePlus 设备提供预编译的内核：

- [ShirkNeko/Action_OnePlus_MKSU_SUSFS](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)（添加 ZRAM 压缩算法补丁、susfs 和 KPM。）

使用上面的链接，Fork 到 GitHub Action，填写构建参数，进行编译，最后将 zip 文件以 AnyKernel3 后缀上传到 GitHub Action。

> [!Note]
>
> - 使用时，您只需填写版本号的前两部分，例如 `5.10`、`6.1`...
> - 使用前请确保您了解处理器名称、内核版本等信息。
