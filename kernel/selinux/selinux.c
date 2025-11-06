#include <linux/version.h>
#include "selinux_defs.h"
#include "../klog.h" // IWYU pragma: keep

#define KERNEL_SU_DOMAIN "u:r:su:s0"

#ifdef CONFIG_KSU_SUSFS
#define KERNEL_INIT_DOMAIN "u:r:init:s0"
#define KERNEL_ZYGOTE_DOMAIN "u:r:zygote:s0"
#define KERNEL_KERNEL_DOMAIN "u:r:kernel:s0"
u32 susfs_ksu_sid = 0;
u32 susfs_init_sid = 0;
u32 susfs_zygote_sid = 0;
u32 susfs_kernel_sid = 0;
#endif

static int transive_to_domain(const char *domain)
{
    struct cred *cred;
    struct task_security_struct *tsec;
    u32 sid;
    int error;

    cred = (struct cred *)__task_cred(current);

    tsec = cred->security;
    if (!tsec) {
        pr_err("tsec == NULL!\n");
        return -1;
    }

    error = security_secctx_to_secid(domain, strlen(domain), &sid);
    if (error) {
        pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n",
            domain, sid, error);
    }

    if (!error) {
        tsec->sid = sid;
        tsec->create_sid = 0;
        tsec->keycreate_sid = 0;
        tsec->sockcreate_sid = 0;
    }

    return error;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 19, 0)
bool __maybe_unused is_ksu_transition(const struct task_security_struct *old_tsec,
            const struct task_security_struct *new_tsec)
{
    static u32 ksu_sid;
    char *secdata;
    u32 seclen;
    bool allowed = false;

    if (!ksu_sid)
        security_secctx_to_secid(KERNEL_SU_DOMAIN, strlen(KERNEL_SU_DOMAIN), &ksu_sid);

    if (security_secid_to_secctx(old_tsec->sid, &secdata, &seclen))
        return false;

    allowed = (!strcmp("u:r:init:s0", secdata) && new_tsec->sid == ksu_sid);
    security_release_secctx(secdata, seclen);
    return allowed;
}
#endif

void setup_selinux(const char *domain)
{
    if (transive_to_domain(domain)) {
        pr_err("transive domain failed.\n");
        return;
    }
}

void setenforce(bool enforce)
{
    __setenforce(enforce);
}

bool getenforce(void)
{
    if (is_selinux_disabled()) {
        return false;
    }

    return __is_selinux_enforcing();
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) &&                         \
    !defined(KSU_COMPAT_HAS_CURRENT_SID)
/*
 * get the subjective security ID of the current task
 */
static inline u32 current_sid(void)
{
    const struct task_security_struct *tsec = current_security();

    return tsec->sid;
}
#endif

bool is_ksu_domain(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
    struct lsm_context ctx;
#else
    char *domain;
    u32 seclen;
#endif
    bool result;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
    int err = security_secid_to_secctx(current_sid(), &ctx);
#else
    int err = security_secid_to_secctx(current_sid(), &domain, &seclen);
#endif

    if (err) {
        return false;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
    result = strncmp(KERNEL_SU_DOMAIN, ctx.context, ctx.len) == 0;
    security_release_secctx(&ctx);
#else
    result = strncmp(KERNEL_SU_DOMAIN, domain, seclen) == 0;
    security_release_secctx(domain, seclen);
#endif
    return result;
}

bool is_zygote(void *sec)
{
    struct task_security_struct *tsec = (struct task_security_struct *)sec;
    if (!tsec) {
        return false;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
    struct lsm_context ctx;
#else
    char *domain;
    u32 seclen;
#endif
    bool result;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
    int err = security_secid_to_secctx(tsec->sid, &ctx);
#else
    int err = security_secid_to_secctx(tsec->sid, &domain, &seclen);
#endif
    if (err) {
        return false;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
    result = strncmp("u:r:zygote:s0", ctx.context, ctx.len) == 0;
    security_release_secctx(&ctx);
#else
    result = strncmp("u:r:zygote:s0", domain, seclen) == 0;
    security_release_secctx(domain, seclen);
#endif
    return result;
}

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
static inline void susfs_set_sid(const char *secctx_name, u32 *out_sid)
{
    int err;
    
    if (!secctx_name || !out_sid) {
        pr_err("secctx_name || out_sid is NULL\n");
        return;
    }

    err = security_secctx_to_secid(secctx_name, strlen(secctx_name),
                       out_sid);
    if (err) {
        pr_err("failed setting sid for '%s', err: %d\n", secctx_name, err);
        return;
    }
    pr_info("sid '%u' is set for secctx_name '%s'\n", *out_sid, secctx_name);
}

bool susfs_is_sid_equal(void *sec, u32 sid2) {
    struct task_security_struct *tsec = (struct task_security_struct *)sec;
    if (!tsec) {
        return false;
    }
    return tsec->sid == sid2;
}

u32 susfs_get_sid_from_name(const char *secctx_name)
{
    u32 out_sid = 0;
    int err;
    
    if (!secctx_name) {
        pr_err("secctx_name is NULL\n");
        return 0;
    }
    err = security_secctx_to_secid(secctx_name, strlen(secctx_name),
                       &out_sid);
    if (err) {
        pr_err("failed getting sid from secctx_name: %s, err: %d\n", secctx_name, err);
        return 0;
    }
    return out_sid;
}

u32 susfs_get_current_sid(void) {
    return current_sid();
}

void susfs_set_zygote_sid(void)
{
    susfs_set_sid(KERNEL_ZYGOTE_DOMAIN, &susfs_zygote_sid);
}

bool susfs_is_current_zygote_domain(void) {
    return unlikely(current_sid() == susfs_zygote_sid);
}

void susfs_set_ksu_sid(void)
{
    susfs_set_sid(KERNEL_SU_DOMAIN, &susfs_ksu_sid);
}

bool susfs_is_current_ksu_domain(void) {
    return unlikely(current_sid() == susfs_ksu_sid);
}

void susfs_set_init_sid(void)
{
    susfs_set_sid(KERNEL_INIT_DOMAIN, &susfs_init_sid);
}

bool susfs_is_current_init_domain(void) {
    return unlikely(current_sid() == susfs_init_sid);
}

void susfs_set_kernel_sid(void)
{
    susfs_set_sid(KERNEL_KERNEL_DOMAIN, &susfs_kernel_sid);
}
#endif

#define DEVPTS_DOMAIN "u:object_r:ksu_file:s0"

u32 ksu_get_devpts_sid(void)
{
    u32 devpts_sid = 0;
    int err = security_secctx_to_secid(DEVPTS_DOMAIN, strlen(DEVPTS_DOMAIN),
                       &devpts_sid);

    if (err)
        pr_info("get devpts sid err %d\n", err);

    return devpts_sid;
}
