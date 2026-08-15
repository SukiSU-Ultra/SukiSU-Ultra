# 用法: .\setup-ndk.ps1 <TRIPLE> <ANDROID_SDK_LEVEL>
# 示例: .\setup-ndk.ps1 aarch64-linux-android 21

param(
   [Parameter(Mandatory=$true)]
   [string]$TRIPLE,

   [Parameter(Mandatory=$true)]
   [int]$ANDROID_SDK_LEVEL
)

# 检查 NDK 环境变量
if (-not $env:ANDROID_NDK_HOME) {
   Write-Error "ANDROID_NDK_HOME 环境变量未设置"
   exit 1
}

$LLVM_PATH = "$env:ANDROID_NDK_HOME\toolchains\llvm\prebuilt\windows-x86_64"
$LLVM_BIN = "$LLVM_PATH\bin"

# 检查路径是否存在
if (-not (Test-Path $LLVM_PATH)) {
   Write-Error "NDK LLVM 路径不存在: $LLVM_PATH"
   Write-Host "请确认 NDK 版本支持 windows-x86_64，或检查 ANDROID_NDK_HOME 是否正确"
   exit 1
}

$NDK_TRIPLE = $TRIPLE
if ($NDK_TRIPLE -eq "armv7-linux-androideabi") {
   $NDK_TRIPLE = "armv7a-linux-androideabi"
}

# Windows 下 clang 可执行文件名
$CLANG_EXE = "${NDK_TRIPLE}${ANDROID_SDK_LEVEL}-clang.cmd"
$CLANGPP_EXE = "${NDK_TRIPLE}${ANDROID_SDK_LEVEL}-clang++.cmd"
$CLANG_PATH = "$LLVM_BIN\$CLANG_EXE"
$CLANGPP_PATH = "$LLVM_BIN\$CLANGPP_EXE"

# 检查 clang 是否存在
if (-not (Test-Path $CLANG_PATH)) {
   Write-Error "未找到编译器: $CLANG_PATH"
   exit 1
}

# 处理 triple 格式
$UTRIPLE = $TRIPLE.Replace("-", "_")
$UUTRIPLE = $UTRIPLE.ToUpper()

# 设置环境变量
$env:CC_$UTRIPLE = $CLANG_PATH
$env:CXX_$UTRIPLE = $CLANGPP_PATH
$env:AR_$UTRIPLE = "$LLVM_BIN\llvm-ar.exe"
$env:CARGO_TARGET_${UUTRIPLE}_LINKER = $CLANG_PATH
$env:BINDGEN_EXTRA_CLANG_ARGS_$UTRIPLE = "--sysroot=$LLVM_PATH\sysroot -I$LLVM_PATH\sysroot\usr\include\$TRIPLE"

# 输出确认信息
Write-Host "NDK 交叉编译环境已配置:"
Write-Host "  TRIPLE:        $TRIPLE"
Write-Host "  NDK_TRIPLE:    $NDK_TRIPLE"
Write-Host "  CC:            $($env:CC_$UTRIPLE)"
Write-Host "  CXX:           $($env:CXX_$UTRIPLE)"
Write-Host "  AR:            $($env:AR_$UTRIPLE)"
Write-Host "  LINKER:        $($env:CARGO_TARGET_${UUTRIPLE}_LINKER)"
Write-Host "  BINDGEN_ARGS:  $($env:BINDGEN_EXTRA_CLANG_ARGS_$UTRIPLE)"