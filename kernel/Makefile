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

REPO_OWNER := SukiSU-Ultra
REPO_NAME := SukiSU-Ultra
REPO_BRANCH := main
KSU_VERSION_API := 4.1.2

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git
CURL_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin curl

MDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

KSU_GITHUB_VERSION := $(shell $(CURL_BIN) -s "https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
KSU_GITHUB_VERSION_COMMIT := $(shell $(CURL_BIN) -sI "https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/commits?sha=$(REPO_BRANCH)&per_page=1" | grep -i "link:" | sed -n 's/.*page=\([0-9]*\)>; rel="last".*/\1/p')

ifeq ($(findstring $(srctree),$(src)),$(srctree))
  KSU_SRC := $(src)
else
  KSU_SRC := $(srctree)/$(src)
endif

ifneq ($(shell test -e $(KSU_SRC)/../.git && echo "in-tree"),in-tree)
  KSU_SRC := $(MDIR)
endif

LOCAL_GIT_EXISTS := $(shell test -e $(KSU_SRC)/../.git && echo 1 || echo 0)

define get_ksu_version_full
v$1-$(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --short=8 HEAD)@$(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --abbrev-ref HEAD)
endef

ifeq ($(KSU_GITHUB_VERSION_COMMIT),)
  ifeq ($(LOCAL_GIT_EXISTS),1)
    $(shell cd $(KSU_SRC); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
    KSU_LOCAL_VERSION := $(shell cd $(KSU_SRC); $(GIT_BIN) rev-list --count $(REPO_BRANCH))
    KSU_VERSION := $(shell expr 40000 + $(KSU_LOCAL_VERSION) - 2815)
    $(info -- $(REPO_NAME) version (local .git): $(KSU_VERSION))
  else
    KSU_VERSION := 13000
    $(warning -- Could not fetch version online or via local .git! Using fallback version: $(KSU_VERSION))
  endif
else
  KSU_VERSION := $(shell expr 40000 + $(KSU_GITHUB_VERSION_COMMIT) - 2815)
  $(info -- $(REPO_NAME) version (GitHub): $(KSU_VERSION))
endif

ifeq ($(KSU_GITHUB_VERSION),)
  ifeq ($(LOCAL_GIT_EXISTS),1)
    $(shell cd $(KSU_SRC); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
    KSU_VERSION_FULL := $(call get_ksu_version_full,$(KSU_VERSION_API))
    $(info -- $(REPO_NAME) version (local .git): $(KSU_VERSION_FULL))
    $(info -- $(REPO_NAME) Formatted version (local .git): $(KSU_VERSION))
  else
    KSU_VERSION_FULL := v$(KSU_VERSION_API)-$(REPO_NAME)-unknown@unknown
    $(warning -- $(REPO_NAME) version: $(KSU_VERSION_FULL))
  endif
else
  $(shell cd $(KSU_SRC); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
  KSU_VERSION_FULL := $(call get_ksu_version_full,$(KSU_GITHUB_VERSION))
  $(info -- $(REPO_NAME) version (Github): $(KSU_VERSION_FULL))
endif

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

# Function proc_ops check
ifeq ($(shell grep -q "struct proc_ops " $(srctree)/include/linux/proc_fs.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_PROC_OPS
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
