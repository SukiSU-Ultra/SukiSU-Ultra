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
	if (ksu_selinux_hide_enabled && *tsid == cached_su_sid) {
		pr_info("selinux_hide: slow_avc_audit: replace tsid: %u with priv_app_sid: %u\n", *tsid, priv_app_sid);
		*tsid = priv_app_sid;
	}

	/*
	 * The avc_spoof feature has its own SID set and toggle. Honor it on
	 * this path too: when arm64_bl_patch() redirects the avc_has_perm*
	 * callers here, the kprobe avc_spoof installs on slow_avc_audit() is
	 * bypassed (this covers most 3.4 .. 5.4 arm64 builds).
	 */
	ksu_avc_spoof_rewrite_tsid(tsid);
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

/* 3.5 .. 3.16 / vendor trees: no `result` argument yet. */
static int __nocfi __overloadable ksu_slow_avc_audit_handler(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, struct common_audit_data *a, unsigned int flags)
{
	int (*orig_fn)(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, struct common_audit_data *a, unsigned int flags) = slow_avc_audit_fn;
	ksu_slow_avc_audit_inline(&tsid);
	return orig_fn(ssid, tsid, tclass, requested, audited, denied, a, flags);
}

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

/* 3.5 .. 3.16 / vendor trees: no `result` argument yet. */
static int __nocfi ksu_slow_avc_audit_handler_0(u32 ssid, u32 tsid, u16 tclass, u32 requested, u32 audited, u32 denied, struct common_audit_data *a, unsigned int flags)
{
	ksu_slow_avc_audit_inline(&tsid);
	return ((typeof(ksu_slow_avc_audit_handler_0) *)slow_avc_audit_fn)(ssid, tsid, tclass, requested, audited, denied, a, flags);
}

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

#define SLOW_AVC_AUDIT_TYPE_0 u32, u32, u16, u32, u32, u32, struct common_audit_data *, unsigned int
#define SLOW_AVC_AUDIT_TYPE_1 u32, u32, u16, u32, u32, u32, int, struct common_audit_data *
#define SLOW_AVC_AUDIT_TYPE_2 struct selinux_state *, u32, u32, u16, u32, u32, u32, int, struct common_audit_data *
#define SLOW_AVC_AUDIT_TYPE_3 struct selinux_state *, u32, u32, u16, u32, u32, u32, int, struct common_audit_data *, unsigned int
#define SLOW_AVC_AUDIT_TYPE_4 u32, u32, u16, u32, u32, u32, int, struct common_audit_data *, unsigned int

#define OVERLOAD_SLOW_AVC_AUDIT(fn) _Generic					\
((fn),										\
	int (*)(SLOW_AVC_AUDIT_TYPE_0): (void *)ksu_slow_avc_audit_handler_0, 	\
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
#undef SLOW_AVC_AUDIT_TYPE_0
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

#elif defined(CONFIG_ARM) && defined(CONFIG_AUDIT) && defined(CONFIG_KALLSYMS) && \
	!defined(CONFIG_CPU_ENDIAN_BE8) && !defined(CONFIG_CPU_ENDIAN_BE32)

/*
 * ARM32 without kprobes: rewrite every unconditional `bl`/`b
 * slow_avc_audit_ in kernel text with the kernel's own patch_text().
 *
 * The trampoline is deliberately signature-agnostic: on ARM the target SID is
 * the second argument (the third once struct selinux_state was prepended),
 * while slow_avc_audit() also gained a `result` argument after 3.10 and
 * gained/lost the flags argument in different trees. It saves r0-r3 and lr,
 * lets the shared inline hook rewrite the saved tsid slot, then tail-branches
 * to the real slow_avc_audit() with the original register/stack arguments and
 * return address. Patching a `b` keeps it a `b` so a tail-called audit keeps
 * its original return address.
 */
extern char _stext[], _etext[];

/*
 * arch/arm/kernel/patch.c; only declared in the private arch/arm/kernel/patch.h
 * on old trees, and patch.o is only linked when CONFIG_JUMP_LABEL or
 * CONFIG_KPROBES is enabled. Resolve it through kallsyms to avoid a hard link
 * reference; kallsyms stores ARM Thumb function addresses with bit 0 clear,
 * but indirect calls need it set.
 */
typedef void (*ksu_arm32_patch_text_fn)(void *addr, unsigned int insn);
static ksu_arm32_patch_text_fn ksu_arm32_patch_text __read_mostly;

void *ksu_arm32_slow_avc_audit_slot __read_mostly;

__attribute__((used, noinline))
void ksu_slow_avc_audit_arm32_hook(u32 *tsid)
{
	ksu_slow_avc_audit_inline(tsid);
}

/* Keep the manual-hook API available on this branch too. */
void ksu_slow_avc_audit(u32 *tsid)
{
	ksu_slow_avc_audit_inline(tsid);
}

/*
 * slow_avc_audit(ssid, tsid, ...) until 4.16; 4.17+ prepends
 * struct selinux_state, so tsid moves to the third argument (saved r2).
 * Keep this in sync with the kprobe argument selection in avc_spoof.c.
 *
 * Layout after push {r0-r3, lr} + sub sp, sp, #4:
 *   sp+0 padding, sp+4 r0, sp+8 r1, sp+12 r2, sp+16 r3, sp+20 lr
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || defined(KSU_COMPAT_HAS_SELINUX_STATE))
#define KSU_ARM32_TSID_SAVED_OFFSET "12"
#else
#define KSU_ARM32_TSID_SAVED_OFFSET "8"
#endif

__attribute__((naked, used, noinline))
static void ksu_arm32_slow_avc_audit_trampoline(void)
{
	asm volatile(
		"push	{r0-r3, lr}\n"
		"sub	sp, sp, #4\n"
		"add	r0, sp, #" KSU_ARM32_TSID_SAVED_OFFSET "\n"
		"bl	ksu_slow_avc_audit_arm32_hook\n"
		"add	sp, sp, #4\n"
		"pop	{r0-r3, lr}\n"
		"ldr	r12, 1f\n"
		"ldr	r12, [r12]\n"
		"bx	r12\n"
		".align	2\n"
		"1:	.word	ksu_arm32_slow_avc_audit_slot\n");
}

#undef KSU_ARM32_TSID_SAVED_OFFSET

static int ksu_arm32_patch_slow_avc_audit_calls(uintptr_t target)
{
	uintptr_t start = (uintptr_t)_stext;
	uintptr_t end = (uintptr_t)_etext;
	uintptr_t hook = (uintptr_t)&ksu_arm32_slow_avc_audit_trampoline;
	uintptr_t patch_fn = kallsyms_lookup_retry("patch_text");
	uintptr_t patch_call = patch_fn;
	u8 *buf;
	uintptr_t page;
	int found = 0;
	int patched = 0;

#ifdef CONFIG_THUMB2_KERNEL
	patch_call |= 1UL;
#endif

	if (!start || !end || end <= start || !target || !patch_fn) {
		pr_info("avc_spoof: arm32 hook unavailable (start 0x%lx end 0x%lx target 0x%lx patch_text 0x%lx)\n",
			start, end, target, patch_fn);
		return 0;
	}

	*(void **)&ksu_arm32_patch_text = (void *)patch_call;

	buf = kmalloc(PAGE_SIZE + 8, GFP_KERNEL);
	if (!buf)
		return 0;

	/* Kallsyms returns the raw code address, without the Thumb bit. */
	target &= ~1UL;
#ifdef CONFIG_THUMB2_KERNEL
	ksu_arm32_slow_avc_audit_slot = (void *)(target | 1UL);
#else
	ksu_arm32_slow_avc_audit_slot = (void *)target;
#endif

	for (page = start & PAGE_MASK; page < end; page += PAGE_SIZE) {
		size_t len = end - page;
		size_t off;

		if (len > PAGE_SIZE + 8)
			len = PAGE_SIZE + 8;

		if (copy_from_kernel_nofault(buf, (void *)page, len)) {
			len = end - page;
			if (len > PAGE_SIZE)
				len = PAGE_SIZE;
			if (copy_from_kernel_nofault(buf, (void *)page, len))
				continue;
		}

		cond_resched();

#ifdef CONFIG_THUMB2_KERNEL
		for (off = 0; off + 4 <= len; off += 2) {
			uintptr_t site = page + off;
			u16 hw1, hw2, n1, n2;
			u32 base, s, j1, j2, i1, i2, imm10, imm11, imm25;
			s32 delta;
			long rel;
			int is_bl;

			if (site < start)
				continue;

			hw1 = *(u16 *)(buf + off);
			hw2 = *(u16 *)(buf + off + 2);
			if ((hw1 & 0xf800) != 0xf000)
				continue;

			base = hw2 & 0xd000;
			if (base != 0xd000 && base != 0x9000)
				continue;

			s = (hw1 >> 10) & 1;
			imm10 = hw1 & 0x03ff;
			j1 = (hw2 >> 13) & 1;
			j2 = (hw2 >> 11) & 1;
			i1 = (j1 ^ s) ^ 1;
			i2 = (j2 ^ s) ^ 1;
			imm25 = (s << 24) | (i1 << 23) | (i2 << 22) |
				(imm10 << 12) | ((hw2 & 0x07ff) << 1);
			delta = (s32)(imm25 << 7) >> 7;

			/*
			 * T32 B/BL base is Align(PC, 4), PC being the
			 * instruction address + 4. For a 32-bit instruction at
			 * addr & 2 this is the second halfword's address.
			 */
			if ((uintptr_t)((((long)site + 4) & ~3L) + delta) != target)
				continue;

			found++;

			rel = (long)(hook & ~1UL) - (long)(((uintptr_t)site + 4) & ~3UL);
			if ((rel & 1) || rel < -(1L << 24) || rel > (1L << 24) - 2)
				continue;

			is_bl = (base == 0xd000);
			s = (rel >> 24) & 1;
			i1 = (rel >> 23) & 1;
			i2 = (rel >> 22) & 1;
			j1 = ((i1 ^ 1) ^ s) & 1;
			j2 = ((i2 ^ 1) ^ s) & 1;
			imm10 = (rel >> 12) & 0x03ff;
			imm11 = (rel >> 1) & 0x07ff;
			n1 = 0xf000 | (s << 10) | imm10;
			n2 = (is_bl ? 0xd000 : 0x9000) |
				(j1 << 13) | (j2 << 11) | imm11;

			ksu_arm32_patch_text((void *)site, ((u32)n1 << 16) | n2);
			patched++;
		}
#else
		for (off = 0; off + 4 <= len; off += 4) {
			uintptr_t site = page + off;
			u32 insn, op, newinsn;
			s32 delta;
			long rel;
			int is_bl;

			if (site < start)
				continue;

			insn = *(u32 *)(buf + off);
			op = insn & 0xff000000;
			if (op != 0xea000000 && op != 0xeb000000)
				continue;

			delta = (s32)(insn << 8) >> 6;
			if ((uintptr_t)((long)site + 8 + delta) != target)
				continue;

			found++;

			rel = (long)hook - (long)(site + 8);
			if ((rel & 3) || rel < -(1L << 25) || rel > (1L << 25) - 4)
				continue;

			is_bl = (op == 0xeb000000);
			newinsn = (is_bl ? 0xeb000000 : 0xea000000) |
				((u32)(rel >> 2) & 0x00ffffff);

			ksu_arm32_patch_text((void *)site, newinsn);
			patched++;
		}
#endif
	}

	kfree(buf);

	pr_info("avc_spoof: arm32 hook: found %d site(s), patched %d\n",
		found, patched);

	return patched;
}

static void ksu_init_slow_avc_audit_hook(void)
{
	uintptr_t target;
	int ret = ksu_selinux_get_sids();

	if (ret)
		pr_info("selinux_hide: sid grab fail?\n");

	target = kallsyms_lookup_retry("slow_avc_audit");
	if (!target) {
		pr_info("avc_spoof: slow_avc_audit not found, arm32 hook skipped\n");
		return;
	}

	ksu_arm32_patch_slow_avc_audit_calls(target);
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
