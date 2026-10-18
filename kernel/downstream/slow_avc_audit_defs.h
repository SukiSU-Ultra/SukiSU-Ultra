// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __KSU_H_SLOW_AVC_AUDIT_HOOK
#define __KSU_H_SLOW_AVC_AUDIT_HOOK

static bool ksu_selinux_hide_enabled;
static u32 cached_su_sid;
static u32 priv_app_sid __read_mostly = 0;

static inline int ksu_selinux_get_sids()
{
	int err = security_secctx_to_secid("u:r:priv_app:s0:c512,c768", strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
	if (!err)
		pr_info("selinux_hide: priv_app_sid: %u\n", priv_app_sid);

	if (!priv_app_sid)
		return -1;

	return 0;
}

static __always_inline void ksu_slow_avc_audit_inline(u32 *tsid)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		return;

	// won't happen. this is unreachable if so
	//if (unlikely(!priv_app_sid))
	//	return;

	if (*tsid != cached_su_sid)
		return;

	pr_info("selinux_hide: slow_avc_audit: replace tsid: %u with priv_app_sid: %u\n", *tsid, priv_app_sid);
	*tsid = priv_app_sid;
}

#if defined(CONFIG_AUDIT) && defined(CONFIG_ARM64) && defined(CONFIG_KALLSYMS)

struct selinux_state;
__maybe_unused void ksu_slow_avc_audit(u32 *tsid) { return; } // dummy

/* 
 * NOTE: both clang __overloadable and a C11 _Generic overloading
 * methods are included here only for demonstration purposes.
 *
 * should be also useful as future reference.
 */
#if defined(__clang__)

#ifndef __overloadable
#define __overloadable __attribute__((overloadable))
#endif

static void *slow_avc_audit_fn __read_mostly = nullptr;

static int __nocfi __overloadable ksu_slow_avc_audit_handler(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a)
{
	int (*orig_fn)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(ssid, tsid, tclass, requested, audited, denied, result, a);
}

static int __nocfi __overloadable ksu_slow_avc_audit_handler(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a)
{
	int (*orig_fn)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(state, ssid, tsid, tclass, requested, audited, denied, result, a);
}

static int __nocfi __overloadable ksu_slow_avc_audit_handler(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags)
{
	int (*orig_fn)(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(state, ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

static int __nocfi __overloadable ksu_slow_avc_audit_handler(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags)
{
	int (*orig_fn)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

// now choose what we have
static typeof(slow_avc_audit) *ksu_slow_avc_audit_hook __read_mostly = nullptr;
static inline void ksu_do_overload_slow_avc_audit(void)
{
	ksu_slow_avc_audit_hook = ksu_slow_avc_audit_handler;
}
#else /* !clang */

static void *slow_avc_audit_fn __read_mostly = nullptr;

static int __nocfi ksu_slow_avc_audit_handler_1(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a)
{
	ksu_slow_avc_audit_inline(&tsid);
	return ((typeof(ksu_slow_avc_audit_handler_1) *)slow_avc_audit_fn)(ssid, tsid, tclass, requested, audited, denied, result, a);
}

static int __nocfi ksu_slow_avc_audit_handler_2(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a)
{
	ksu_slow_avc_audit_inline(&tsid);
	return ((typeof(ksu_slow_avc_audit_handler_2) *)slow_avc_audit_fn)(state, ssid, tsid, tclass, requested, audited, denied, result, a);
}

static int __nocfi ksu_slow_avc_audit_handler_3(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags)
{
	ksu_slow_avc_audit_inline(&tsid);
	return ((typeof(ksu_slow_avc_audit_handler_3) *)slow_avc_audit_fn)(state, ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

static int __nocfi ksu_slow_avc_audit_handler_4(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, int result, struct common_audit_data *a, unsigned int flags)
{
	ksu_slow_avc_audit_inline(&tsid);
	return ((typeof(ksu_slow_avc_audit_handler_4) *)slow_avc_audit_fn)(ssid, tsid, tclass, requested, audited, denied, result, a, flags);
}

#define SLOW_AVC_AUDIT_TYPE_1 u32, u32, u16, u32, u32, u32, int, struct common_audit_data *
#define SLOW_AVC_AUDIT_TYPE_2 struct selinux_state *, u32, u32, u16, u32, u32, u32, int, struct common_audit_data *
#define SLOW_AVC_AUDIT_TYPE_3 struct selinux_state *, u32, u32, u16, u32, u32, u32, int, struct common_audit_data *, unsigned int
#define SLOW_AVC_AUDIT_TYPE_4 u32, u32, u16, u32, u32, u32, int, struct common_audit_data *, unsigned int

#define OVERLOAD_SLOW_AVC_AUDIT(fn) _Generic					\
((fn),										\
	int (*)(SLOW_AVC_AUDIT_TYPE_1): (void *)ksu_slow_avc_audit_handler_1, 	\
	int (*)(SLOW_AVC_AUDIT_TYPE_2): (void *)ksu_slow_avc_audit_handler_2, 	\
	int (*)(SLOW_AVC_AUDIT_TYPE_3): (void *)ksu_slow_avc_audit_handler_3, 	\
	int (*)(SLOW_AVC_AUDIT_TYPE_4): (void *)ksu_slow_avc_audit_handler_4	\
)

// now choose what we have
static typeof(slow_avc_audit) *ksu_slow_avc_audit_hook __read_mostly = nullptr;
static inline void ksu_do_overload_slow_avc_audit(void)
{
	ksu_slow_avc_audit_hook = OVERLOAD_SLOW_AVC_AUDIT(slow_avc_audit);
}
#undef SLOW_AVC_AUDIT_TYPE_4
#undef SLOW_AVC_AUDIT_TYPE_3
#undef SLOW_AVC_AUDIT_TYPE_2
#undef SLOW_AVC_AUDIT_TYPE_1
#undef OVERLOAD_SLOW_AVC_AUDIT

#endif /* !clang */ 

static void ksu_init_slow_avc_audit_hook(void)
{
	int ret = ksu_selinux_get_sids();
	if (ret) {
		pr_info("selinux_hide: sid grab fail?\n");
		goto bail;
	}

	ksu_do_overload_slow_avc_audit();

	*(uintptr_t *)&slow_avc_audit_fn = kallsyms_lookup_retry("slow_avc_audit");
	if (!slow_avc_audit_fn)
		goto bail;

//	ret = arm64_bl_patch_everything((uintptr_t)slow_avc_audit_fn, (uintptr_t)ksu_slow_avc_audit_hook);
//	pr_info("avc_spoof: hook slow_avc_audit ret: %d\n", ret);

//	ret = arm64_bl_patch(kallsyms_lookup_retry("audit_inode_permission"), 64 * sizeof(uint32_t), kallsyms_lookup_retry("slow_avc_audit"), (uintptr_t)ksu_slow_avc_audit_hook);
//	pr_info("avc_spoof: hook on slow_avc_audit on audit_inode_permission ret: %d\n", ret);

	uintptr_t symaddr = kallsyms_lookup_retry("avc_has_extended_perms");
	if (!symaddr)
		goto skip1;
	ret = arm64_bl_patch(symaddr, ksu_get_ksym_size(symaddr, 384 * sizeof(uint32_t)), (uintptr_t)slow_avc_audit_fn, (uintptr_t)ksu_slow_avc_audit_hook);
	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_extended_perms ret: %d\n", ret);
skip1:
	symaddr = kallsyms_lookup_retry("avc_has_perm_flags");
	if (!symaddr)
		goto skip2;
	ret = arm64_bl_patch(symaddr, ksu_get_ksym_size(symaddr, 384 * sizeof(uint32_t)), (uintptr_t)slow_avc_audit_fn, (uintptr_t)ksu_slow_avc_audit_hook);
	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_perm_flags ret: %d\n", ret);
skip2:
	symaddr = kallsyms_lookup_retry("avc_has_perm");
	if (!symaddr)
		goto bail;
	ret = arm64_bl_patch(symaddr, ksu_get_ksym_size(symaddr, 384 * sizeof(uint32_t)), (uintptr_t)slow_avc_audit_fn, (uintptr_t)ksu_slow_avc_audit_hook);
	pr_info("avc_spoof: hook on slow_avc_audit on avc_has_perm ret: %d\n", ret);

bail:;
	extern typeof(dotted_kallsyms_destroy_hash_array) dotted_kallsyms_destroy_hash_array;
	dotted_kallsyms_destroy_hash_array();
}

#elif defined(CONFIG_KPROBES)
static struct kprobe *slow_avc_audit_kp;
static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || defined(KSU_COMPAT_HAS_SELINUX_STATE))
	u32 *tsid = (u32 *)&PT_REGS_PARM3(regs);
#else
	u32 *tsid = (u32 *)&PT_REGS_PARM2(regs);
#endif
	ksu_slow_avc_audit_inline(tsid);

	return 0;
}

static void ksu_init_slow_avc_audit_hook(void) 
{
	int ret = ksu_selinux_get_sids();
	if (ret)
		pr_info("selinux_hide: sid grab fail?\n");

	slow_avc_audit_kp = init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);
}

#else /* ! CONFIG_KPROBES */

void ksu_slow_avc_audit(u32 *tsid)
{
	ksu_slow_avc_audit_inline(tsid);
}

static void ksu_init_slow_avc_audit_hook(void) 
{
	int ret = ksu_selinux_get_sids();
	if (!ret)
		return;

	// doesnt really matter if this fails
	// replacing 0 with soemthing is not a problem
	// this is for the manual hook part so yeah
	pr_info("selinux_hide: sid grab fail?\n");
}
#endif

#endif // __KSU_H_SLOW_AVC_AUDIT_HOOK
