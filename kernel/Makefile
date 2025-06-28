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

obj-$(CONFIG_KSU) += kernelsu.o

obj-$(CONFIG_KPM) += kpm/

REPO_OWNER := SukiSU-Ultra
REPO_NAME := SukiSU-Ultra
REPO_BRANCH := main
KSU_VERSION_API := 3.1.6

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git
CURL_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin curl

KSU_GITHUB_VERSION := $(shell $(CURL_BIN) -s "https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
KSU_GITHUB_VERSION_COMMIT := $(shell $(CURL_BIN) -sI "https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/commits?sha=$(REPO_BRANCH)&per_page=1" | grep -i "link:" | sed -n 's/.*page=\([0-9]*\)>; rel="last".*/\1/p')

LOCAL_GIT_EXISTS := $(shell test -e $(srctree)/$(src)/../.git && echo 1 || echo 0)

define get_ksu_version_full
v$1-$(shell cd $(srctree)/$(src); $(GIT_BIN) rev-parse --short=8 HEAD)@$(shell cd $(srctree)/$(src); $(GIT_BIN) rev-parse --abbrev-ref HEAD)
endef

ifeq ($(KSU_GITHUB_VERSION_COMMIT),)
  ifeq ($(LOCAL_GIT_EXISTS),1)
    $(shell cd $(srctree)/$(src); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
    KSU_LOCAL_VERSION := $(shell cd $(srctree)/$(src); $(GIT_BIN) rev-list --count $(REPO_BRANCH))
    KSU_VERSION := $(shell expr 10000 + $(KSU_LOCAL_VERSION) + 700)
    $(info -- $(REPO_NAME) version (local .git): $(KSU_VERSION))
  else
    KSU_VERSION := 13000
    $(warning -- Could not fetch version online or via local .git! Using fallback version: $(KSU_VERSION))
  endif
else
  KSU_VERSION := $(shell expr 10000 + $(KSU_GITHUB_VERSION_COMMIT) + 700)
  $(info -- $(REPO_NAME) version (GitHub): $(KSU_VERSION))
endif

ifeq ($(KSU_GITHUB_VERSION),)
  ifeq ($(LOCAL_GIT_EXISTS),1)
    $(shell cd $(srctree)/$(src); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
    KSU_VERSION_FULL := $(call get_ksu_version_full,$(KSU_VERSION_API))
    $(info -- $(REPO_NAME) version (local .git): $(KSU_VERSION_FULL))
    $(info -- $(REPO_NAME) Formatted version (local .git): $(KSU_VERSION))
  else
    KSU_VERSION_FULL := v$(KSU_VERSION_API)-$(REPO_NAME)-unknown@unknown
    $(warning -- $(REPO_NAME) version: $(KSU_VERSION_FULL))
  endif
else
  $(shell cd $(srctree)/$(src); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
  KSU_VERSION_FULL := $(call get_ksu_version_full,$(KSU_GITHUB_VERSION))
  $(info -- $(REPO_NAME) version (Github): $(KSU_VERSION_FULL))
endif

ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
ccflags-y += -DKSU_VERSION_FULL=\"$(KSU_VERSION_FULL)\"

# Checks hooks state
ifeq ($(strip $(CONFIG_KSU_MANUAL_HOOK)),y)
$(info -- KernelSU: Manually-patched hook.)
else
$(info -- KernelSU: Kernel-probe hook.)
ccflags-y += -DCONFIG_KSU_KPROBES_HOOK
endif

# SELinux drivers check
ifeq ($(shell grep -q "current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif
ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
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
ifeq ($(shell grep -q "int\s\+path_umount" $(srctree)/fs/namespace.c; echo $$?),0)
ccflags-y += -DKSU_HAS_PATH_UMOUNT
endif

# Checks Samsung UH drivers
ifeq ($(shell grep -q "CONFIG_KDP_CRED" $(srctree)/kernel/cred.c; echo $$?),0)
ccflags-y += -DSAMSUNG_UH_DRIVER_EXIST
endif

# Samsung SELinux Porting
ifeq ($(shell grep -q "SEC_SELINUX_PORTING_COMMON" $(srctree)/security/selinux/avc.c; echo $$?),0)
ccflags-y += -DSAMSUNG_SELINUX_PORTING
endif

ifndef KSU_EXPECTED_SIZE
KSU_EXPECTED_SIZE := 0x375
endif

ifndef KSU_EXPECTED_HASH
KSU_EXPECTED_HASH := f3850041c24d05f8ff4663df00cfc0ae3f572bf91c7888e9f1c442954cf0d5f0
endif

ifdef KSU_MANAGER_PACKAGE
ccflags-y += -DKSU_MANAGER_PACKAGE=\"$(KSU_MANAGER_PACKAGE)\"
$(info -- SukiSU Manager package name: $(KSU_MANAGER_PACKAGE))
endif

$(info -- SukiSU Manager signature size: $(KSU_EXPECTED_SIZE))
$(info -- SukiSU Manager signature hash: $(KSU_EXPECTED_HASH))
$(info -- Supported Unofficial Manager: 5ec1cff (GKI) ShirkNeko udochina (GKI and KPM))
KERNEL_VERSION := $(VERSION).$(PATCHLEVEL)
KERNEL_TYPE := Non-GKI
# Check for GKI 2.0 (5.10+ or 6.x+)
ifneq ($(shell test \( $(VERSION) -ge 5 -a $(PATCHLEVEL) -ge 10 \) -o $(VERSION) -ge 6; echo $$?),0)
# Check for GKI 1.0 (5.4)
ifeq ($(shell test $(VERSION)-$(PATCHLEVEL) = 5-4; echo $$?),0)
KERNEL_TYPE := GKI 1.0
endif
else
KERNEL_TYPE := GKI 2.0
endif
$(info -- KERNEL_VERSION: $(KERNEL_VERSION))
$(info -- KERNEL_TYPE: $(KERNEL_TYPE))

$(info -- KERNEL_VERSION: $(KERNEL_VERSION))
ifeq ($(CONFIG_KPM),y)
$(info -- KPM is enabled)
else
$(info -- KPM is disabled)
endif


ccflags-y += -DEXPECTED_SIZE=$(KSU_EXPECTED_SIZE)
ccflags-y += -DEXPECTED_HASH=\"$(KSU_EXPECTED_HASH)\"

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

# Keep a new line here!! Because someone may append config
