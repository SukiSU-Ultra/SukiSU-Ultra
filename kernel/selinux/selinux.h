#ifndef __KSU_H_SELINUX
#define __KSU_H_SELINUX

#include <linux/types.h>
#include <linux/version.h>
#include "linux/sched.h"

#ifdef KSU_COMPAT_HAS_SELINUX_STATE
#define KSU_COMPAT_USE_SELINUX_STATE
#endif

void setup_selinux(const char *);

void setenforce(bool);

bool getenforce(void);

bool is_task_ksu_domain(const struct cred* cred);

bool is_ksu_domain(void);

bool is_zygote(const struct cred* cred);

bool is_init(const struct cred* cred);

void apply_kernelsu_rules(void);

u32 ksu_get_ksu_file_sid(void);

int handle_sepolicy(unsigned long arg3, void __user *arg4);

#ifdef CONFIG_KSU_SUSFS
bool susfs_is_sid_equal(void *sec, u32 sid2);
u32 susfs_get_sid_from_name(const char *secctx_name);
u32 susfs_get_current_sid(void);
void susfs_set_zygote_sid(void);
bool susfs_is_current_zygote_domain(void);
void susfs_set_ksu_sid(void);
bool susfs_is_current_ksu_domain(void);
void susfs_set_init_sid(void);
bool susfs_is_current_init_domain(void);
void susfs_set_priv_app_sid(void);
#endif // #ifdef CONFIG_KSU_SUSFS

#endif
