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

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git
CURL_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin curl

KSU_GITHUB_VERSION := $(shell $(CURL_BIN) -sI "https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/commits?sha=$(REPO_BRANCH)&per_page=1" | grep -i "link:" | sed -n 's/.*page=\([0-9]*\)>; rel="last".*/\1/p')

ifeq ($(KSU_GITHUB_VERSION),)
  ifeq ($(shell test -e $(srctree)/$(src)/../.git; echo $$?),0)
    $(shell cd $(srctree)/$(src); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
    KSU_LOCAL_VERSION := $(shell cd $(srctree)/$(src); $(GIT_BIN) rev-list --count $(REPO_BRANCH))
    $(eval KSU_VERSION := $(shell expr 10000 + $(KSU_LOCAL_VERSION) + 700))
    $(info -- SukiSU-Ultra version (local .git): $(KSU_VERSION))
  else
    $(eval KSU_VERSION := 13000)
    $(warning -- Could not fetch version online or via local .git! Using fallback version: $(KSU_VERSION))
  endif
else
  $(eval KSU_VERSION := $(shell expr 10000 + $(KSU_GITHUB_VERSION) + 700))
  $(info -- SukiSU-Ultra version (GitHub): $(KSU_VERSION))
endif

$(info -- SukiSU-Ultra version: $(KSU_VERSION))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION)

ifndef KSU_EXPECTED_SIZE
KSU_EXPECTED_SIZE := 0x35c
endif

ifndef KSU_EXPECTED_HASH
KSU_EXPECTED_HASH := 947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef
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
