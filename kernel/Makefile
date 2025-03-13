kernelsu-objs := ksu.o
kernelsu-objs += allowlist.o
kernelsu-objs += apk_sign.o
kernelsu-objs += sucompat.o
kernelsu-objs += throne_tracker.o
kernelsu-objs += core_hook.o
kernelsu-objs += ksud.o
kernelsu-objs += embed_ksud.o
kernelsu-objs += kernel_compat.o

kernelsu-objs += selinux/selinux.o
kernelsu-objs += selinux/sepolicy.o
kernelsu-objs += selinux/rules.o
ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

# Do checks before compile
ifneq ($(shell grep -q "int path_umount" $(srctree)/fs/namespace.c; echo $$?),0)
$(error -- Backporting path_umount is mandatory !! Read: https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#how-to-backport-path-umount)
endif

# https://github.com/tiann/KernelSU/pull/2102/files#diff-3a325663233178293ee38b8161f3be511a466af7e0156b9d03d5aed0497564bfR19
NEED_KPROBES := $(strip $(shell \
    if [ "$(VERSION)" -ge "5" -a "$(PATCHLEVEL)" -ge "10" ]; then \
      echo TRUE; \
    else \
      echo FALSE; \
    fi \
  ))


ifeq ($(NEED_KPROBES),TRUE)
$(info -- KernelSU: Kernel version is greater or equal to 5.10!)
# GKI manual hook checks
# https://github.com/Pzqqt/android_kernel_xiaomi_marble/commit/5b8596b5604bcd0e6e12697a01136a0bb9eb0257
ifeq ($(CONFIG_KSU_MANUAL_HOOK),y)
$(info -- KernelSU: Hooks with Manual hook!)
ifeq ($(CONFIG_KSU),m)
$(error CONFIG_KSU_MANUAL_HOOK cannot be enabled when compiling KernelSU as LKM!)
endif
else
ccflags-y += -DKSU_HOOK_WITH_KPROBES
endif
endif

obj-$(CONFIG_KSU) += kernelsu.o

# .git is a text file while the module is imported by 'git submodule add'.
ifeq ($(shell test -e $(srctree)/$(src)/../.git; echo $$?),0)
$(shell cd $(srctree)/$(src); /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin [ -f ../.git/shallow ] && git fetch --unshallow)
KSU_GIT_VERSION := $(shell cd $(srctree)/$(src); /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git rev-list --count HEAD)
# ksu_version: major * 10000 + git version + 600 for historical reasons
$(eval KSU_VERSION=$(shell expr 10000 + $(KSU_GIT_VERSION) + 600))
$(info -- KernelSU version: $(KSU_VERSION))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
else # If there is no .git file, the default version will be passed.
$(warning "KSU_GIT_VERSION not defined! It is better to make KernelSU a git submodule!")
ccflags-y += -DKSU_VERSION=16
endif

# SELinux drivers check
ifeq ($(shell grep -q " current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif
ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

# This feature was introduced in linux 5.0-rc1
ifeq ($(shell grep -q "get_cred_rcu" $(srctree)/include/linux/cred.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_GET_CRED_RCU
else
# https://github.com/gregkh/linux/commit/123e44b9a49a42ff5313ec65256f1540d7c52fa0
ifeq ($(shell grep -q "atomic_long_inc" $(srctree)/include/linux/cred.h; echo $$?),0)
$(info -- KernelSU compat: atomic_long_t detected.)
ccflags-y += -DKSU_COMPAT_ATOMIC_LONG
else
$(info -- KernelSU compat: atomic_t detected.)
endif
endif

# Handle optional backports
ifeq ($(shell grep -q "strncpy_from_user_nofault" $(srctree)/include/linux/uaccess.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_STRNCPY
endif
ifeq ($(shell grep -q "ssize_t kernel_read" $(srctree)/fs/read_write.c; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_KERNEL_READ
endif
ifeq ($(shell grep "ssize_t kernel_write" $(srctree)/fs/read_write.c | grep -q "const void" ; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_KERNEL_WRITE
endif

# Checks Samsung UH drivers
ifeq ($(shell grep -q "CONFIG_KDP_CRED" $(srctree)/kernel/cred.c; echo $$?),0)
ccflags-y += -DSAMSUNG_UH_DRIVER_EXIST
endif

ifndef KSU_EXPECTED_SIZE
KSU_EXPECTED_SIZE := 0x35c
endif

ifndef KSU_EXPECTED_HASH
KSU_EXPECTED_HASH := 947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef
endif

ifdef KSU_MANAGER_PACKAGE
ccflags-y += -DKSU_MANAGER_PACKAGE=\"$(KSU_MANAGER_PACKAGE)\"
$(info -- KernelSU Manager package name: $(KSU_MANAGER_PACKAGE))
endif

$(info -- KernelSU Manager signature size: $(KSU_EXPECTED_SIZE))
$(info -- KernelSU Manager signature hash: $(KSU_EXPECTED_HASH))
$(info -- Supported Unofficial Manager: ShirkNeko (GKI) (Non-GKI))
KERNEL_VERSION := $(VERSION).$(PATCHLEVEL)
$(info -- KERNEL_VERSION: $(KERNEL_VERSION))

# Checks if CONFIG_KSU_HOOK is defined.
ifeq ($(strip $(CONFIG_KSU_VFS)),y)
    $(info -- CONFIG_KSU_VFS is enabled.)
    ccflags-y += -DCONFIG_KSU_VFS
else
    $(info -- CONFIG_KSU_VFS is not enabled.)
endif

ccflags-y += -DEXPECTED_SIZE=$(KSU_EXPECTED_SIZE)
ccflags-y += -DEXPECTED_HASH=\"$(KSU_EXPECTED_HASH)\"

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

# Keep a new line here!! Because someone may append config
