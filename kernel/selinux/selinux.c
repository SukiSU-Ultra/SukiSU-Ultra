#include "linux/cred.h"
#include "linux/sched.h"
#include "linux/security.h"
#include "linux/version.h"
#include "selinux_defs.h"
#include "../klog.h" // IWYU pragma: keep
#include "../ksu.h"

static int transive_to_domain(const char *domain, struct cred *cred)
{
	u32 sid;
	int error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	struct task_security_struct *tsec;
#else 
	struct cred_security_struct *tsec;
#endif
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
bool __maybe_unused
is_ksu_transition(const struct task_security_struct *old_tsec,
		  const struct task_security_struct *new_tsec)
{
	static u32 ksu_sid;
	char *secdata;
	u32 seclen;
	bool allowed = false;

	if (!ksu_sid)
		security_secctx_to_secid(KERNEL_SU_DOMAIN,
					 strlen(KERNEL_SU_DOMAIN), &ksu_sid);

	if (security_secid_to_secctx(old_tsec->sid, &secdata, &seclen))
		return false;

	allowed = (!strcmp("u:r:init:s0", secdata) && new_tsec->sid == ksu_sid);
	security_release_secctx(secdata, seclen);
	return allowed;
}
#endif


void setup_selinux(const char *domain)
{
	if (transive_to_domain(domain, (struct cred *)__task_cred(current))) {
		pr_err("transive domain failed.\n");
		return;
	}
}

void setup_ksu_cred()
{
	if (ksu_cred && transive_to_domain(KERNEL_SU_CONTEXT, ksu_cred)) {
		pr_err("setup ksu cred failed.\n");
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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) &&						 \
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
struct lsm_context {
	char *context;
	u32 len;
};

static int __security_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
	return security_secid_to_secctx(secid, &cp->context, &cp->len);
}
static void __security_release_secctx(struct lsm_context *cp)
{
	security_release_secctx(cp->context, cp->len);
}
#else
#define __security_secid_to_secctx security_secid_to_secctx
#define __security_release_secctx security_release_secctx
#endif

bool is_task_ksu_domain(const struct cred *cred)
{
	struct lsm_context ctx;
	bool result;
	if (!cred) {
		return false;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	const struct task_security_struct * tsec = selinux_cred(cred);
#else 
	const struct cred_security_struct *tsec = selinux_cred(cred);
#endif
	if (!tsec) {
		return false;
	}
	int err = __security_secid_to_secctx(tsec->sid, &ctx);
	if (err) {
		return false;
	}
	result = strncmp(KERNEL_SU_CONTEXT, ctx.context, ctx.len) == 0;
	__security_release_secctx(&ctx);
	return result;
}

bool is_ksu_domain(void)
{
	current_sid();
	return is_task_ksu_domain(current_cred());
}

bool is_context(const struct cred *cred, const char *context)
{
	struct lsm_context ctx;
	bool result;
	if (!cred) {
		return false;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	const struct task_security_struct * tsec = selinux_cred(cred);
#else 
	const struct cred_security_struct *tsec = selinux_cred(cred);
#endif
	if (!tsec) {
		return false;
	}
	int err = __security_secid_to_secctx(tsec->sid, &ctx);
	if (err) {
		return false;
	}
	result = strncmp(context, ctx.context, ctx.len) == 0;
	__security_release_secctx(&ctx);
	return result;
}

bool is_zygote(const struct cred *cred)
{
	return is_context(cred, "u:r:zygote:s0");
}

bool is_init(const struct cred *cred)
{
	return is_context(cred, "u:r:init:s0");
}

u32 ksu_get_ksu_file_sid()
{
	u32 ksu_file_sid = 0;
	int err = security_secctx_to_secid(KSU_FILE_CONTEXT, strlen(KSU_FILE_CONTEXT),
					   &ksu_file_sid);
	if (err) {
		pr_info("get ksufile sid err %d\n", err);
	}
	return ksu_file_sid;
}

#ifdef CONFIG_KSU_SUSFS
#define KERNEL_INIT_DOMAIN "u:r:init:s0"
#define KERNEL_ZYGOTE_DOMAIN "u:r:zygote:s0"
#define KERNEL_PRIV_APP_DOMAIN "u:r:priv_app:s0:c512,c768"
u32 susfs_ksu_sid = 0;
u32 susfs_init_sid = 0;
u32 susfs_zygote_sid = 0;
u32 susfs_priv_app_sid = 0;

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
	susfs_set_sid(KERNEL_SU_CONTEXT, &susfs_ksu_sid);
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

void susfs_set_priv_app_sid(void)
{
	susfs_set_sid(KERNEL_PRIV_APP_DOMAIN, &susfs_priv_app_sid);
}
#endif
