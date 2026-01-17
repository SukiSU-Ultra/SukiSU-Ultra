export DDK_ROOT=/opt/ddk

export KDIR=$DDK_ROOT/kdir/android15-6.6
export CLANG_PATH=$DDK_ROOT/clang/clang-r510928/bin

export PATH=$CLANG_PATH:$PATH
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=arm64
export LLVM=1
export LLVM_IAS=1
