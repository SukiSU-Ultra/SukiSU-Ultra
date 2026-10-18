# NOTE: unity build. single unit.

obj-$(CONFIG_KSU) := ksu.o

CFLAGS_ksu.o += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
CFLAGS_ksu.o += -I$(objtree)/security/selinux

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))

# compliant to last upstream kernel change as of 96770df
CFLAGS_ksu.o += -DKSU_VERSION=32693

KSU_PACKAGE_NAME := me.weishu.kernelsu
KSU_EXPECTED_SIZE := 0x033b
KSU_EXPECTED_HASH := c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6

$(info -- KernelSU Manager package name: $(KSU_PACKAGE_NAME))
$(info -- KernelSU Manager signature size: $(KSU_EXPECTED_SIZE))
$(info -- KernelSU Manager signature hash: $(KSU_EXPECTED_HASH))

CFLAGS_ksu.o += -DKSU_PACKAGE_NAME=\"$(KSU_PACKAGE_NAME)\"
CFLAGS_ksu.o += -DEXPECTED_SIZE=$(KSU_EXPECTED_SIZE)
CFLAGS_ksu.o += -DEXPECTED_HASH=\"$(KSU_EXPECTED_HASH)\"

ifeq ($(shell grep -q "^struct security_operations selinux_ops" $(srctree)/security/selinux/hooks.c; echo $$?),0)
$(info -- KernelSU/compat: exported selinux_ops found!)
CFLAGS_ksu.o += -DKSU_HAS_EXPORTED_SELINUX_OPS
endif

ifeq ($(shell grep -q " current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
CFLAGS_ksu.o += -DKSU_COMPAT_HAS_CURRENT_SID
endif

ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
CFLAGS_ksu.o += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

# UL, look for iterate_dir on ‎fs/readdir.c
ifeq ($(shell grep -q "^int iterate_dir" $(srctree)/fs/readdir.c 2>/dev/null; echo $$?),0)
$(info -- KernelSU/compat: iterate_dir found!)
CFLAGS_ksu.o += -DKSU_HAS_ITERATE_DIR
endif

ifeq ($(shell grep -q "struct type_datum \*\*type_val_to_struct;" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
CFLAGS_ksu.o += -DKSU_TYPE_VAL_TO_STRUCT
endif

# half-assed-backport from 5.1
ifeq ($(shell grep -q "struct type_datum \*\*type_val_to_struct_array;" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
CFLAGS_ksu.o += -DKSU_TYPE_VAL_TO_STRUCT_ARRAY
endif

ifeq ($(shell grep -q "^DEFINE_RWLOCK(policy_rwlock);" $(srctree)/security/selinux/ss/services.c; echo $$?),0)
$(info -- KernelSU/compat: exported policy_rwlock found!)
CFLAGS_ksu.o += -DKSU_COMPAT_HAS_EXPORTED_POLICY_RWLOCK
endif

# branch link hook vfs_statx, this newer version uses struct filename
ifeq ($(shell grep "int vfs_statx" $(srctree)/fs/stat.c 2>/dev/null | grep -q "struct filename" 2>/dev/null; echo $$?),0)
# $(info -- KernelSU/compat: vfs_statx has struct filename argument!)
CFLAGS_ksu.o += -DKSU_HAS_VFS_STATX2
endif

# branch link hook, do_faccessat
ifeq ($(shell grep "long do_faccessat" $(srctree)/fs/open.c 2>/dev/null | grep -q "flags" 2>/dev/null; echo $$?),0)
# $(info -- KernelSU/compat: do_faccessat has flags argument!)
CFLAGS_ksu.o += -DKSU_HAS_FACCESSAT2
endif

# UL, look for read_iter on f_op struct
ifeq ($(shell grep -q "read_iter" $(srctree)/include/linux/fs.h 2>/dev/null; echo $$?),0)
$(info -- KernelSU/compat: f_op->read_iter found!)
CFLAGS_ksu.o += -DKSU_HAS_FOP_READ_ITER
endif

CFLAGS_ksu.o += $(call cc-option, -Wno-declaration-after-statement)
CFLAGS_ksu.o += $(call cc-option, -Wno-implicit-function-declaration)
CFLAGS_ksu.o += $(call cc-option, -Wno-missing-prototypes)
CFLAGS_ksu.o += $(call cc-option, -Wno-strict-prototypes)
CFLAGS_ksu.o += $(call cc-option, -Wno-int-conversion)
CFLAGS_ksu.o += $(call cc-option, -Wno-int-to-pointer-cast)
CFLAGS_ksu.o += $(call cc-option, -Wno-pointer-to-int-cast)
CFLAGS_ksu.o += $(call cc-option, -Wno-unused-variable)
CFLAGS_ksu.o += $(call cc-option, -Wno-unused-function)
CFLAGS_ksu.o += $(call cc-option, -Wno-unused-label)
CFLAGS_ksu.o += $(call cc-option, -Wno-format)
CFLAGS_ksu.o += $(call cc-option, -Wno-macro-redefined)
CFLAGS_ksu.o += $(call cc-option, -Wno-incompatible-pointer-types-discards-qualifiers)
CFLAGS_ksu.o += $(call cc-option, -Wno-discarded-qualifiers)
CFLAGS_ksu.o += $(call cc-option, -Wno-deprecated-octal-literals)

# dont be too strict
CFLAGS_REMOVE_ksu.o += -Werror

# so we can see stack use atleast, as we disable all stack safety here
CFLAGS_ksu.o += $(call cc-option, -Wframe-larger-than=1024)

# to make sure we can use builtins
CFLAGS_REMOVE_ksu.o += -fno-builtin

# Os to O2, we dont care for anything else. O3 vs O2 codegen on hotpath is same.
ifeq ($(CONFIG_CC_OPTIMIZE_FOR_SIZE),y)
CFLAGS_REMOVE_ksu.o += -Oz
CFLAGS_REMOVE_ksu.o += -Os
CFLAGS_ksu.o += -O2
endif

# attempt to enable gnu11 up to gnu2y
# we skip gnu2x here due to its inconsistency
CFLAGS_ksu.o += $(call cc-option, -std=gnu11)
CFLAGS_ksu.o += $(call cc-option, -std=gnu17)
CFLAGS_ksu.o += $(call cc-option, -std=gnu23)
CFLAGS_ksu.o += $(call cc-option, -std=gnu2y)

#ifeq ($(shell $(CC) -v 2>&1 | grep -q 'clang'; echo $$?),0)
# $(info -- KernelSU/CC: clang!)
#endif

# always inline atomics
# clang and gcc CAN try to drop a runtime C11 atomics detector
# https://github.com/llvm/llvm-project/blob/main/llvm/test/CodeGen/AArch64/atomic-ops.ll
# however this is problematic to us as those cannot be linked to the kernel (e.g. __aarch64_cas4_acq, __aarch64_cas4_rel)
# so for LKM they just get plain ARMv8.0 atomics, not LSE / LSE2, even when the device is capable of LSE.
ifeq ($(CONFIG_ARM64),y)
CFLAGS_ksu.o += $(call cc-option, -mno-outline-atomics)
endif

# Optional: for LKM users, I recommend users to build it themselves with optimizations.
# you can get optimized codegen especially around atomics.
# hint: decode your own /proc/cpuinfo and check it here https://github.com/llvm/llvm-project/blob/main/llvm/lib/TargetParser/Host.cpp
# comment it out and put your cpu / arch here
# CFLAGS_ksu.o += -mcpu=cortex-a76 -mtune=cortex-a76

ifneq ($(CONFIG_KSU_DEBUG),y)
# strip, remove tracing / profiling
# comment out if proper backtrace is needed
CFLAGS_ksu.o += -g0 -fno-unwind-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer
CFLAGS_ksu.o += $(call cc-option, -momit-leaf-frame-pointer)

# no profiling
CFLAGS_REMOVE_ksu.o += $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_ksu.o += -pg

# no need for stack init
CFLAGS_REMOVE_ksu.o += -ftrivial-auto-var-init=pattern
CFLAGS_REMOVE_ksu.o += -ftrivial-auto-var-init=zero
CFLAGS_REMOVE_ksu.o += -enable-trivial-auto-var-init-zero-knowing-it-will-be-removed-from-clang

# if cflags can be macro'd, this will be called 'TRUST_ME'
CFLAGS_ksu.o += -fno-stack-protector -fno-stack-check
CFLAGS_REMOVE_ksu.o += -fsanitize=shadow-call-stack
endif # CONFIG_KSU_DEBUG

# Native fallback targets matching the traditional out-of-tree build method
all:
	$(MAKE) -C $(KDIR) M=$(MDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean

# Keep a new line here!! Because someone may append config
