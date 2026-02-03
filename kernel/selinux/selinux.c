#include "linux/cred.h"
#include "linux/sched.h"
#include "linux/security.h"
#include "linux/version.h"
#include "selinux_defs.h"
#include "../klog.h" // IWYU pragma: keep
#include "../ksu.h"

/*
 * Cached SID values for frequently checked contexts.
 * These are resolved once at init and used for fast u32 comparison
 * instead of expensive string operations on every check.
 *
 * A value of 0 means "no cached SID is available" for that context.
 * This covers both the initial "not yet cached" state and any case
 * where resolving the SID (e.g. via security_secctx_to_secid) failed.
 * In all such cases we intentionally fall back to the slower
 * string-based comparison path; this degrades performance only and
 * does not cause a functional failure.
 */
static u32 cached_su_sid __read_mostly = 0;
static u32 cached_zygote_sid __read_mostly = 0;
static u32 cached_init_sid __read_mostly = 0;
u32 ksu_file_sid __read_mostly = 0;

static int transive_to_domain(const char *domain, struct cred *cred)
{
	taskcred_sec_t *tsec;
	u32 sid;
	int error;

	tsec = (taskcred_sec_t *)selinux_cred(cred);
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
	int err;
	u32 seclen;
	bool allowed = false;

	if (!ksu_sid) {
		err = security_secctx_to_secid(
			KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &ksu_sid);
		pr_err("failed to get ksu_sid: %d\n", err);
	}

	if (security_secid_to_secctx(old_tsec->sid, &secdata, &seclen))
		return false;

	allowed = (!strcmp("u:r:init:s0", secdata) && new_tsec->sid == ksu_sid);
	security_release_secctx(secdata, seclen);
	return allowed;
}
#endif

void setup_selinux(const char *domain, struct cred *cred)
{
	if (transive_to_domain(domain, cred)) {
		pr_err("transive domain failed.\n");
		return;
	}
}

void setup_ksu_cred(void)
{
	if (ksu_cred && transive_to_domain(KERNEL_SU_CONTEXT, ksu_cred)) {
		pr_err("setup ksu cred failed.\n");
	}
}

void setenforce(bool enforce)
{
	do_setenforce(enforce);
}

bool getenforce(void)
{
	if (is_selinux_disabled()) {
		return false;
	}

	return is_selinux_enforcing();
}

/*
 * Initialize cached SID values for frequently checked SELinux contexts.
 * Called once after SELinux policy is loaded (post-fs-data).
 * This eliminates expensive string comparisons in hot paths.
 */
void cache_sid(void)
{
	int err;

	err = security_secctx_to_secid(
		KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &cached_su_sid);
	if (err) {
		pr_warn("Failed to cache kernel su domain SID: %d\n", err);
		cached_su_sid = 0;
	} else {
		pr_info("Cached su SID: %u\n", cached_su_sid);
	}

	err = security_secctx_to_secid(ZYGOTE_CONTEXT, strlen(ZYGOTE_CONTEXT),
				       &cached_zygote_sid);
	if (err) {
		pr_warn("Failed to cache zygote SID: %d\n", err);
		cached_zygote_sid = 0;
	} else {
		pr_info("Cached zygote SID: %u\n", cached_zygote_sid);
	}

	err = security_secctx_to_secid(INIT_CONTEXT, strlen(INIT_CONTEXT),
				       &cached_init_sid);
	if (err) {
		pr_warn("Failed to cache init SID: %d\n", err);
		cached_init_sid = 0;
	} else {
		pr_info("Cached init SID: %u\n", cached_init_sid);
	}

	err = security_secctx_to_secid(KSU_FILE_CONTEXT,
				       strlen(KSU_FILE_CONTEXT), &ksu_file_sid);
	if (err) {
		pr_warn("Failed to cache ksu_file SID: %d\n", err);
		ksu_file_sid = 0;
	} else {
		pr_info("Cached ksu_file SID: %u\n", ksu_file_sid);
	}
}

/*
 * Fast path: compare task's SID directly against cached value.
 * Falls back to string comparison if cache is not initialized.
 */
static bool is_sid_match(const struct cred *cred, u32 cached_sid,
			 const char *fallback_context)
{
	const taskcred_sec_t *tsec;
	if (!cred) {
		return false;
	}

	tsec = (const taskcred_sec_t *)selinux_cred(cred);
	if (!tsec) {
		return false;
	}

	// Fast path: use cached SID if available
	if (likely(cached_sid != 0)) {
		return tsec->sid == cached_sid;
	}

	// Slow path fallback: string comparison (only before cache is initialized)
	struct lsm_context ctx = { 0 };
	bool result;
	if (__security_secid_to_secctx(tsec->sid, &ctx)) {
		return false;
	}
	result = strncmp(fallback_context, ctx.context, ctx.len) == 0;
	__security_release_secctx(&ctx);
	return result;
}

bool is_task_ksu_domain(const struct cred *cred)
{
	return is_sid_match(cred, cached_su_sid, KERNEL_SU_CONTEXT);
}

bool is_ksu_domain(void)
{
	return is_task_ksu_domain(current_cred());
}

bool is_zygote(const struct cred *cred)
{
	return is_sid_match(cred, cached_zygote_sid, ZYGOTE_CONTEXT);
}

bool is_init(const struct cred *cred)
{
	return is_sid_match(cred, cached_init_sid, INIT_CONTEXT);
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
		pr_err("failed setting sid for '%s', err: %d\n", secctx_name,
		       err);
		return;
	}
	pr_info("sid '%u' is set for secctx_name '%s'\n", *out_sid,
		secctx_name);
}

bool susfs_is_sid_equal(const struct cred *cred, u32 sid2)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	const struct task_security_struct *tsec = selinux_cred(cred);
#else
	const struct cred_security_struct *tsec = selinux_cred(cred);
#endif
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
		pr_err("failed getting sid from secctx_name: %s, err: %d\n",
		       secctx_name, err);
		return 0;
	}
	return out_sid;
}

u32 susfs_get_current_sid(void)
{
	return current_sid();
}

void susfs_set_zygote_sid(void)
{
	susfs_set_sid(KERNEL_ZYGOTE_DOMAIN, &susfs_zygote_sid);
}

bool susfs_is_current_zygote_domain(void)
{
	return unlikely(current_sid() == susfs_zygote_sid);
}

void susfs_set_ksu_sid(void)
{
	susfs_set_sid(KERNEL_SU_CONTEXT, &susfs_ksu_sid);
}

bool susfs_is_current_ksu_domain(void)
{
	return unlikely(current_sid() == susfs_ksu_sid);
}

void susfs_set_init_sid(void)
{
	susfs_set_sid(KERNEL_INIT_DOMAIN, &susfs_init_sid);
}

bool susfs_is_current_init_domain(void)
{
	return unlikely(current_sid() == susfs_init_sid);
}

void susfs_set_priv_app_sid(void)
{
	susfs_set_sid(KERNEL_PRIV_APP_DOMAIN, &susfs_priv_app_sid);
}
#endif // #ifdef CONFIG_KSU_SUSFS
