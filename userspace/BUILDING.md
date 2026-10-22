# 本机构建 Android Rust 用户空间程序

需要 Python 3.10+、通过 rustup 安装的 Rust，以及 Android NDK。推荐使用与 CI 一致的 NDK r29。

脚本可以从任意工作目录调用，所有 Cargo 操作均在仓库根目录执行。
它只为子进程配置环境变量，不覆盖 `.cargo/config.toml`、APK 原生库或 ksud 嵌入资源。

## 快速开始

在仓库根目录执行：

```powershell
# 默认：arm64 Android / ksud / release
python userspace/build.py

# Windows 也可以使用 BAT，参数完全相同
.\userspace\build.bat --arch arm64

# 第一次使用，允许安装缺少的 Rust target
python userspace/build.py --arch arm64 --install-target

# 开发时快速构建 debug 版
python userspace/build.py --arch arm64 --debug
```

构建产物会保留在 Cargo target 目录，并复制到：

```text
dist/userspace/arm64/release/ksud
dist/userspace/arm64/debug/ksud
```

输出是 **Android ELF 可执行文件**，不是 Windows EXE。构建成功不代表已打包进 APK，也不会自动推送到设备。
仓库 ksud 中嵌入的 ksuinit、内核模块等资源仍来自现有 `userspace/ksud/bin`，本脚本不负责下载或更新它们。

## 选择架构与包

```powershell
python userspace/build.py --arch x86_64 --install-target
python userspace/build.py --arch aarch64-linux-android
python userspace/build.py --package ksuinit --arch arm64
python userspace/build.py --package ksuinit --arch x86_64 --install-target
```

| 参数 | Rust target | 默认 API |
|---|---|---|
| `arm64` / `aarch64` / `arm64-v8a` | `aarch64-linux-android` | 26 |
| `x86_64` | `x86_64-linux-android` | 26 |
| `riscv64` | `riscv64-linux-android` | 35 |

`ksuinit` 按 CI 规则使用静态链接、NDK compiler builtins 和 16 KB 页面对齐。

RISC-V 使用 CI 指定的 nightly 与 build-std：

```powershell
python userspace/build.py --arch riscv64 --install-target
```

默认工具链是 `nightly-2026-09-23`，需要相应 nightly 可下载或已经安装，以及 `rust-src`。
可用 `--toolchain nightly-YYYY-MM-DD` 覆盖；更换版本后的兼容性需要自行验证。
RISC-V 所需 NDK 编译器和 sysroot 也必须存在。

## 指定 NDK

```powershell
python userspace/build.py --ndk "D:\Android\Sdk\ndk\29.0.14206865"
```

未指定时依次检查：

1. `ANDROID_NDK_HOME` / `ANDROID_NDK_ROOT`。
2. `ANDROID_HOME` / `ANDROID_SDK_ROOT` 下的 NDK。
3. `manager/local.properties` 中 `sdk.dir` 下的 NDK。
4. Windows、Linux、macOS 的常见 Android SDK 安装目录。

同一 SDK 中按版本号优先选择最新 NDK。存在多个版本时，建议使用 `--ndk` 固定版本。

## 检查、Clippy 和其他选项

```powershell
# check 不生成可执行文件
python userspace/build.py --action check --debug
python userspace/build.py --action clippy --debug

# 只使用已缓存依赖，不联网安装工具链
python userspace/build.py --debug --offline

# 预览配置；不执行 cargo/rustup 或创建构建产物
python userspace/build.py --arch x86_64 --dry-run

# 指定 API、并行任务和产物目录
python userspace/build.py --api 26 --jobs 8 --output-dir "D:\build-output\arm64"

python userspace/build.py --help
```

所有 Cargo 操作默认带 `--locked`。只有 `--install-target` 会安装 Rust target/工具链；不要与 `--offline` 同时使用。
已有的 `CARGO_TARGET_DIR`、`RUSTFLAGS` 等设置仍可影响构建。没有设置 target 目录时使用仓库 `target`。
`--output-dir` 只控制成功 build 后的复制位置，check/clippy 不复制产物。

## 已验证范围

Windows + NDK r29：arm64 ksud 的 check 和 debug 实际构建、arm64 ksuinit 的静态 debug 构建通过。
x86_64、RISC-V 的配置预览通过，尚未在此环境实际构建；Linux/macOS 主机也需进一步实测。
