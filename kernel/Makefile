obj-$(CONFIG_KSU) := ksu.o

ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

ifeq ($(CONFIG_KSU_SUSFS), y)
## As we are building gki only, no KBUILD_EXTMOD is needed
## Since there is still a build error for 6.12 as $(src) returns absolute path, so here we just hardcode it
ccflags-y += -I$(srctree)/drivers/kernelsu -I$(srctree)/drivers/kernelsu/include
else
ccflags-y += -I$(srctree)/$(src) -I$(srctree)/$(src)/include
endif

MDIR    := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

REPO_OWNER  := SukiSU-Ultra
REPO_NAME   := SukiSU-Ultra
REPO_BRANCH := main

VERSION_BASE    := 40000
VERSION_OFFSET  := 2815

GIT_BIN  := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git
CURL_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin curl

KSU_SRC := $(if $(filter $(srctree),$(src)),$(src),$(srctree)/$(src))
KSU_SRC := $(if $(wildcard $(KSU_SRC)/../.git),$(KSU_SRC),$(MDIR))

git_short_sha    = $(shell cd $(KSU_SRC) && $(GIT_BIN) rev-parse --short=8 HEAD 2>/dev/null)
git_branch       = $(shell cd $(KSU_SRC) && $(GIT_BIN) rev-parse --abbrev-ref HEAD 2>/dev/null)
git_commit_count = $(shell cd $(KSU_SRC) && $(GIT_BIN) rev-list --count $(REPO_BRANCH) 2>/dev/null)
git_latest_tag   = $(shell cd $(KSU_SRC) && $(GIT_BIN) describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')

$(shell cd $(KSU_SRC) 2>/dev/null && [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow 2>/dev/null)

GITHUB_API_BASE  := https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)
KSU_GITHUB_VER   := $(shell $(CURL_BIN) -s "$(GITHUB_API_BASE)/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"v?([^"]+)".*/\1/')
GITHUB_COMMITS   := $(shell $(CURL_BIN) -sI "$(GITHUB_API_BASE)/commits?sha=$(REPO_BRANCH)&per_page=1" 2>/dev/null | grep -i "link:" | sed -n 's/.*page=\([0-9]*\)>; rel="last".*/\1/p')
LOCAL_COUNT     := $(if $(GITHUB_COMMITS),$(GITHUB_COMMITS),$(git_commit_count))
KSU_VERSION     := $(if $(LOCAL_COUNT),$(shell expr $(VERSION_BASE) + $(LOCAL_COUNT) - $(VERSION_OFFSET)),13000)
VERSION_TAG     := $(or $(KSU_GITHUB_VER),$(git_latest_tag),4.1.2)
KSU_VERSION_FULL := $(if $(call git_short_sha),v$(VERSION_TAG)-$(call git_short_sha)@$(call git_branch),v$(VERSION_TAG)-$(REPO_NAME)-unknown@unknown)
$(info -- $(REPO_NAME) version: $(KSU_VERSION) [$(KSU_VERSION_FULL)])

ccflags-y += -DKSU_VERSION=$(KSU_VERSION)
ccflags-y += -DKSU_VERSION_FULL=\"$(KSU_VERSION_FULL)\"

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

ifeq ($(CONFIG_KSU_MANUAL_HOOK), y)
$(info -- $(REPO_NAME): using KSU_MANUAL_HOOK)
else ifeq ($(CONFIG_KSU_SUSFS), y)
$(info -- $(REPO_NAME): using SUSFS_INLINE_HOOK)
else
$(info -- $(REPO_NAME): using Unknown)
endif

ifeq ($(CONFIG_KPM), y)
$(info -- KPM is enabled)
else
$(info -- KPM is disabled)
endif

# Check new vfs_getattr()
ifeq ($(shell grep -A1 "^int vfs_getattr" $(srctree)/fs/stat.c | grep -q "query_flags" ; echo $$?),0)
ccflags-y += -DKSU_HAS_NEW_VFS_GETATTR
endif

ifeq ($(shell grep -q " current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif

ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

ifeq ($(shell grep -q "strncpy_from_user_nofault" $(srctree)/include/linux/uaccess.h; echo $$?),0)
ccflags-y += -DKSU_HAS_STRNCPY_FROM_USER_NOFAULT
endif

ifeq ($(shell grep -q "atomic_t\s\+filter_count" $(srctree)/include/linux/seccomp.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_SECCOMP_FILTER_CNT
endif

# some old kernel backport this, check if put_seccomp_filter still exist
ifneq ($(shell grep -wq "put_seccomp_filter" $(srctree)/kernel/seccomp.c $(srctree)/include/linux/seccomp.h; echo $$?),0)
ifeq ($(shell grep -wq "seccomp_filter_release" $(srctree)/kernel/seccomp.c $(srctree)/include/linux/seccomp.h; echo $$?),0)
ccflags-y += -DKSU_OPTIONAL_SECCOMP_FILTER_RELEASE
endif
endif

ifeq ($(shell grep -q "^DEFINE_RWLOCK(policy_rwlock);" $(srctree)/security/selinux/ss/services.c; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_EXPORTED_POLICY_RWLOCK
endif

ifeq ($(shell grep -q "cpus_ptr;" $(srctree)/include/linux/sched.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_BACKPORTED_CPUS_PTR
endif

ifeq ($(shell grep -q "selinux_inode" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_HAS_SELINUX_INODE
endif

ifeq ($(shell grep -q "selinux_cred" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_HAS_SELINUX_CRED
endif

ifeq ($(shell grep -q "struct type_datum \*\*type_val_to_struct;" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
ccflags-y += -DKSU_TYPE_VAL_TO_STRUCT
endif

# half-assed-backport from 5.1
ifeq ($(shell grep -q "struct type_datum \*\*type_val_to_struct_array;" $(srctree)/security/selinux/ss/policydb.h; echo $$?),0)
ccflags-y += -DKSU_TYPE_VAL_TO_STRUCT_ARRAY
endif

# https://github.com/torvalds/linux/commit/11276d5306b8e5b438a36bbff855fe792d7eaa61
ifeq ($(shell grep -q "DEFINE_STATIC_KEY_TRUE" $(srctree)/include/linux/jump_label.h 2>/dev/null; echo $$?),0)
$(info -- $(REPO_NAME)/compat: modern static_key_interface found)
ccflags-y += -DKSU_HAS_MODERN_STATIC_KEY_INTERFACE
endif

ifdef KSU_MANAGER_PACKAGE
ccflags-y += -DKSU_MANAGER_PACKAGE=\"$(KSU_MANAGER_PACKAGE)\"
$(info -- KernelSU Manager package name: $(KSU_MANAGER_PACKAGE))
endif

## For susfs stuff ##
ifeq ($(shell test -e $(srctree)/fs/susfs.c; echo $$?),0)
$(eval SUSFS_VERSION=$(shell cat $(srctree)/include/linux/susfs.h | grep -E '^#define SUSFS_VERSION' | cut -d' ' -f3 | sed 's/"//g'))
$(info )
$(info -- SUSFS_VERSION: $(SUSFS_VERSION))
else
$(info -- You have not integrated susfs in your kernel yet.)
$(info -- Read: https://gitlab.com/simonpunk/susfs4ksu)
endif

ccflags-y += -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat -Wno-missing-prototypes
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

# Keep a new line here!! Because someone may append config
