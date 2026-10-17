// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported from KernelPatch to SukiSU-Ultra: 2025 Liankong.
 *
 * Compatibility symbols exported by the in-kernel KP runtime to KPMs.
 *
 * Layout mirrors the upstream KernelPatch `kpm/symbols.c`:
 *   - One `sukisu_kpm_symbols[]` table lists every KPM-ABI symbol.
 *   - The loader looks up names through `sukisu_kpm_symbol_lookup`,
 *     which walks the table. There is no EXPORT_SYMBOL in this file
 *     for the KPM-ABI names; the KPM loader's `simplify_symbols`
 *     path is the only legitimate entry point.
 *
 * Differences from upstream KernelPatch:
 *   - `hook_wrap / hook_unwrap_remove / unhook` (the KPM-facing hook
 *     API) are routed through SukiSU's `ksu_register_syscall_hook`
 *     layer instead of an inline syscall-table patch. The upstream
 *     LKM's `fphook.c` is not compiled in this build, so the
 *     `hook_syscalln / hook_compat_syscalln` slots are stubs.
 *   - `is_su_allow_uid / get_ap_mod_exclude` are wired to SukiSU's
 *     policy / manager identity layer rather than KP's
 *     supercall/kstorage layer.
 *   - `kp_sys_call_table` and `kp_kpm_hotpatch_nosync` are not
 *     available; their slots return 0 / -ENOSYS respectively.
 *   - `kp_kpm_pgtable_entry` is implemented locally — KP ships it
 *     verbatim because it is pure header arithmetic.
 *   - `kp_kpm_safe_kallsyms_on_each_symbol` (the BTI / CFI shield
 *     around `kallsyms_on_each_symbol`) is omitted; on SukiSU-Ultra
 *     `kallsyms_on_each_symbol` is safe to call directly.
 */

#include "kp_symbols.h"

#include <linux/cred.h>
#include <linux/gfp.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/uidgid.h>

/* GKI module builds route variable-argument helpers through either
 * <linux/stdarg.h> (5.15+) or the toolchain <stdarg.h> (5.10). Use
 * __has_include so the choice does not depend on LINUX_VERSION_CODE
 * being reachable. */
#if __has_include(<linux/stdarg.h>)
#  include <linux/stdarg.h>
#else
#  include <stdarg.h>
#endif

#include <asm/thread_info.h>

#include <hook.h> /* KP inline-hook framework (kernel/include/hook.h) */

#include "../hook/syscall_hook.h"
#include "../hook/syscall_hook_manager.h"

#include "policy/allowlist.h"
#include "manager/manager_identity.h"

#ifndef CONFIG_ARM64
/* Forward declaration for the non-arm64 stub used by the symbol
 * table below; the real definition sits at the bottom of this
 * file (after the table). The stub returns -ENOSYS because the
 * inline-hook engine (kp_hook.c) is arm64-only. */
static long sukisu_kpm_hook_unsupported(void);
#endif

/* ── Statically-known layout constants (arm64 GKI 5.10/5.15/6.1) ──── */

static u32 sukisu_kpm_kver = LINUX_VERSION_CODE;
static u32 sukisu_kpm_kpver = KP_VERSION;
static int sukisu_kpm_thread_size = THREAD_SIZE;
/* Every supported GKI tree has CONFIG_THREAD_INFO_IN_TASK=y, so
 * thread_info is embedded inside task_struct. */
static int sukisu_kpm_thread_info_in_task = 1;
/* arm64 GKI: SP_EL0 holds the current thread_info pointer. */
static int sukisu_kpm_sp_el0_is_current = 1;
static int sukisu_kpm_sp_el0_is_thread_info = 1;
static int sukisu_kpm_task_in_thread_info_offset = -1;
static int sukisu_kpm_stack_in_task_offset = offsetof(struct task_struct, stack);
static int sukisu_kpm_stack_end_offset = THREAD_SIZE;
static int sukisu_kpm_task_ext_size;
/* Some SukiSU-Ultra KPMs look up `cred_offset` as a standalone scalar
 * (rather than dereferencing the `task_struct_offset` struct). The
 * value is the same as `task_struct_offset.cred_offset`; we publish
 * both names so old and new KPMs can resolve either way. */
static long sukisu_kpm_cred_offset;
/* KP ABI stack-layout facts (arm64 GKI: task->stack + THREAD_SIZE is
 * the end of stack, pt_regs sits just below it). */
static int sukisu_kpm_has_syscall_wrapper;

struct sukisu_kpm_task_struct_offset {
	s16 pid_offset, tgid_offset, thread_pid_offset, ptracer_cred_offset;
	s16 real_cred_offset, cred_offset, comm_offset, fs_offset, files_offset;
	s16 loginuid_offset, sessionid_offset, seccomp_offset, security_offset;
	s16 stack_offset, tasks_offset, mm_offset, active_mm_offset;
};

static struct sukisu_kpm_task_struct_offset sukisu_kpm_task_struct_offset = {
	.pid_offset          = offsetof(struct task_struct, pid),
	.tgid_offset         = offsetof(struct task_struct, tgid),
	.thread_pid_offset   = offsetof(struct task_struct, thread_pid),
	.ptracer_cred_offset = offsetof(struct task_struct, ptracer_cred),
	.real_cred_offset    = offsetof(struct task_struct, real_cred),
	.cred_offset         = offsetof(struct task_struct, cred),
	.comm_offset         = offsetof(struct task_struct, comm),
	.fs_offset           = offsetof(struct task_struct, fs),
	.files_offset        = offsetof(struct task_struct, files),
	.loginuid_offset     = -1,
	.sessionid_offset    = -1,
	.seccomp_offset      = offsetof(struct task_struct, seccomp),
	.security_offset     = -1,
	.stack_offset        = offsetof(struct task_struct, stack),
	.tasks_offset        = offsetof(struct task_struct, tasks),
	.mm_offset           = offsetof(struct task_struct, mm),
	.active_mm_offset    = offsetof(struct task_struct, active_mm),
};

struct sukisu_kpm_mm_struct_offset {
	s16 mmap_base_offset;
	s16 task_size_offset;
	s16 pgd_offset;
	s16 map_count_offset;
	s16 total_vm_offset;
	s16 locked_vm_offset;
	s16 pinned_vm_offset;
	s16 data_vm_offset;
	s16 exec_vm_offset;
	s16 stack_vm_offset;
	s16 start_code_offset, end_code_offset, start_data_offset, end_data_offset;
	s16 start_brk_offset, brk_offset, start_stack_offset;
	s16 arg_start_offset, arg_end_offset, env_start_offset, env_end_offset;
};
static struct sukisu_kpm_mm_struct_offset sukisu_kpm_mm_struct_offset;

/* ── Page-table walker (pure header arithmetic) ──────────────────── */

static u64 *sukisu_kpm_pgtable_entry(u64 pgd_addr, u64 va)
{
	pgd_t *pgd = (pgd_t *)pgd_addr + pgd_index(va);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
	if (pud_sect(*pud))
		return (u64 *)pud;
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
	if (pmd_sect(*pmd))
		return (u64 *)pmd;
	pte = pte_offset_kernel(pmd, va);
	return pte ? (u64 *)pte : NULL;
}

/* ── printk / kallsyms trampolines (function pointer variables) ──── *
 * KPM headers declare these as `extern <type> (*name)(...)` pointer
 * variables; KPM code does `name(...)` which the header re-declares
 * as `(*name)(...)`, so the call site is indirect through the slot.
 * Publishing the address of the slot keeps the call chain kCFI-clean.
 */

__attribute__((no_sanitize("cfi")))
static int sukisu_kpm_printk(const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	int rc;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	/* Route through the kernel's own printk("%pV") so we do not
	 * call the statement-expression macro `printk` (which is the
	 * very thing the KPM ABI is trying to look up). */
	rc = printk("%pV", &vaf);
	va_end(args);
	return rc;
}

static int (*sukisu_kpm_printk_fn)(const char *fmt, ...);

static unsigned long (*sukisu_kpm_kallsyms_lookup_name_fn)(const char *name);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
/* 6.4+ dropped the `struct module *` parameter from
 * kallsyms_on_each_symbol's callback; match the running kernel so
 * the resolved pointer's kCFI type hash lines up with whatever KPM
 * modules pass in. */
static int (*sukisu_kpm_kallsyms_on_each_symbol_fn)(
	int (*fn)(void *, const char *, unsigned long), void *data);
#else
static int (*sukisu_kpm_kallsyms_on_each_symbol_fn)(
	int (*fn)(void *, const char *, struct module *, unsigned long), void *data);
#endif

/* ── copy_to_user / strncpy_from_user shims ──────────────────────── */

static int sukisu_kpm_copy_to_user(void __user *to, const void *from, int len)
{
	return copy_to_user(to, from, len) ? 0 : len;
}

static long sukisu_kpm_strncpy_from_user(char *dst, const char __user *src, long count)
{
	long rc = strncpy_from_user(dst, src, count);

	if (rc >= count) {
		dst[count - 1] = '\0';
		return count;
	}
	return rc > 0 ? rc + 1 : rc;
}

static uid_t sukisu_kpm_current_uid(void)
{
	return from_kuid(current_user_ns(), current_uid());
}

/* ── kf_* helpers ─ the slots are filled from the running kernel ── *
 * `kf_##name` slot types match `typeof(name)` so the KPM-side header
 * `extern <type> (*kf_name)(...)` declaration lines up. */

#define SUKISU_KPM_KFUNC_INIT(name) \
	kf_##name = (typeof(kf_##name))kallsyms_lookup_name(#name)
#define SUKISU_KPM_KFUNC_ENTRY(name) \
	{ "kf_" #name, (unsigned long)&kf_##name }

static int (*kf_sprintf)(char *buf, const char *fmt, ...);
static int (*kf_snprintf)(char *buf, size_t size, const char *fmt, ...);
static int (*kf_vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);
static char *(*kf_strcpy)(char *dest, const char *src);
static char *(*kf_strncpy)(char *dest, const char *src, size_t count);
static char *(*kf_strncat)(char *dest, const char *src, size_t count);
static int (*kf_strcmp)(const char *cs, const char *ct);
static int (*kf_strncmp)(const char *cs, const char *ct, size_t count);
static size_t (*kf_strlen)(const char *s);
static size_t (*kf_strnlen)(const char *s, size_t count);
static char *(*kf_strchr)(const char *s, int c);
static char *(*kf_strrchr)(const char *s, int c);
static char *(*kf_strstr)(const char *s1, const char *s2);
static void *(*kf_memset)(void *s, int c, size_t count);
static void *(*kf_memcpy)(void *dest, const void *src, size_t count);
static void *(*kf_memmove)(void *dest, const void *src, size_t count);
static int (*kf_memcmp)(const void *cs, const void *ct, size_t count);
static char *(*kf_kstrdup)(const char *s, gfp_t gfp);
static void *(*kf_kmemdup)(const void *src, size_t len, gfp_t gfp);
static char *(*kf_kasprintf)(gfp_t gfp, const char *fmt, ...);
static void *(*kf_memchr)(const void *s, int c, size_t n);
static char *(*kf_strcat)(char *dest, const char *src);

/* ── Inline syscall-table hook (KP-style `hook_syscalln`) ───────── *
 * KP's LKM patches sys_call_table entries directly through fphook.
 * SukiSU's runtime does not expose the syscall table for live
 * patching, so these symbols are stubs that return -ENOSYS. KPM
 * authors that need an in-place syscall hook should use
 * `hook_wrap` (which is the SukiSU equivalent). */

/* ── Inline syscall-table hook (KP-style `hook_syscalln`) ───────── *
 * KP's LKM patches sys_call_table entries directly through fphook.
 * SukiSU's runtime does not expose the syscall table for live
 * patching, so these symbols are stubs that return -ENOSYS. KPM
 * authors that need an in-place syscall hook should use
 * `hook_wrap` (which is the SukiSU equivalent). */

static int sukisu_kpm_has_config_compat;

static uintptr_t sukisu_kpm_syscalln_name_addr(int nr, int is_compat)
{
	(void)nr; (void)is_compat;
	return 0;
}

static uintptr_t sukisu_kpm_syscalln_addr(int nr, int is_compat)
{
	return sukisu_kpm_syscalln_name_addr(nr, is_compat);
}

static int sukisu_kpm_hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
	(void)nr; (void)narg; (void)before; (void)after; (void)udata;
	return -ENOSYS; /* see comment above */
}

static void sukisu_kpm_unhook_syscalln(int nr, void *before, void *after)
{
	(void)nr; (void)before; (void)after;
}

static int sukisu_kpm_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
	(void)nr; (void)narg; (void)before; (void)after; (void)udata;
	return -ENOSYS; /* no compat table on arm64 GKI */
}

static void sukisu_kpm_unhook_compat_syscalln(int nr, void *before, void *after)
{
	(void)nr; (void)before; (void)after;
}

/* ── task_pt_regs (arm64 GKI: pt_regs is just below stack top) ── */

static struct pt_regs *sukisu_kpm_task_pt_reg(struct task_struct *task)
{
	unsigned long stack = (unsigned long)task_stack_page(task);
	return (struct pt_regs *)(THREAD_SIZE + stack - sizeof(struct pt_regs));
}

/* ── SU allowlist / exclude (SukiSU-specific wiring) ──────────── */

static int sukisu_kpm_is_su_allow_uid(uid_t uid)
{
	return __ksu_is_allow_uid_for_current(uid) ? 1 : 0;
}

static int sukisu_kpm_get_ap_mod_exclude(uid_t uid)
{
	/* SukiSU-Ultra does not implement a per-package exclude list. */
	(void)uid;
	return 0;
}

static int sukisu_kpm_set_ap_mod_exclude(uid_t uid, int exclude)
{
	(void)uid; (void)exclude;
	return -ENOSYS;
}

/* ── hotpatch_nosync ─────────────────────────────────────────── *
 * KP ships a stop_machine-free text-patch helper. SukiSU does not
 * expose an equivalent on the supported GKI trees, so the slot is
 * a stub that returns -ENOSYS. KPMs that need text patching should
 * use `hook_wrap`. */

static int sukisu_kpm_hotpatch_nosync(void *addr, uint32_t value)
{
	(void)addr; (void)value;
	return -ENOSYS;
}

/* ── Centralized symbol table (KPM-ABI lookup) ──────────────── *
 * The KPM loader calls `sukisu_kpm_symbol_lookup(name)`. If the
 * table has an entry we hand back its address (the address of the
 * storage cell, the function, or the function-pointer-variable
 * slot, depending on which kind of symbol it is). Otherwise the
 * loader falls back to kallsyms. */

struct sukisu_kpm_symbol {
	const char *name;
	unsigned long addr;
};

static const struct sukisu_kpm_symbol sukisu_kpm_symbols[] = {
	{ "compat_copy_to_user",         (unsigned long)sukisu_kpm_copy_to_user },
	{ "compat_strncpy_from_user",    (unsigned long)sukisu_kpm_strncpy_from_user },
	{ "current_uid",                 (unsigned long)sukisu_kpm_current_uid },
	{ "kver",                        (unsigned long)&sukisu_kpm_kver },
	{ "kpver",                       (unsigned long)&sukisu_kpm_kpver },
	{ "thread_size",                 (unsigned long)&sukisu_kpm_thread_size },
	{ "thread_info_in_task",         (unsigned long)&sukisu_kpm_thread_info_in_task },
	{ "sp_el0_is_current",           (unsigned long)&sukisu_kpm_sp_el0_is_current },
	{ "sp_el0_is_thread_info",       (unsigned long)&sukisu_kpm_sp_el0_is_thread_info },
	{ "task_in_thread_info_offset", (unsigned long)&sukisu_kpm_task_in_thread_info_offset },
	{ "stack_in_task_offset",        (unsigned long)&sukisu_kpm_stack_in_task_offset },
	{ "stack_end_offset",            (unsigned long)&sukisu_kpm_stack_end_offset },
	{ "task_ext_size",               (unsigned long)&sukisu_kpm_task_ext_size },
	{ "task_struct_offset",          (unsigned long)&sukisu_kpm_task_struct_offset },
	{ "cred_offset",                 (unsigned long)&sukisu_kpm_cred_offset },
	{ "pgtable_entry",               (unsigned long)sukisu_kpm_pgtable_entry },
	{ "printk",                      (unsigned long)&sukisu_kpm_printk_fn },
	{ "kallsyms_lookup_name",        (unsigned long)&sukisu_kpm_kallsyms_lookup_name_fn },
	{ "kallsyms_on_each_symbol",     (unsigned long)&sukisu_kpm_kallsyms_on_each_symbol_fn },
	SUKISU_KPM_KFUNC_ENTRY(sprintf),
	SUKISU_KPM_KFUNC_ENTRY(snprintf),
	SUKISU_KPM_KFUNC_ENTRY(vsnprintf),
	SUKISU_KPM_KFUNC_ENTRY(strcpy),
	SUKISU_KPM_KFUNC_ENTRY(strncpy),
	SUKISU_KPM_KFUNC_ENTRY(strncat),
	SUKISU_KPM_KFUNC_ENTRY(strcmp),
	SUKISU_KPM_KFUNC_ENTRY(strncmp),
	SUKISU_KPM_KFUNC_ENTRY(strlen),
	SUKISU_KPM_KFUNC_ENTRY(strnlen),
	SUKISU_KPM_KFUNC_ENTRY(strchr),
	SUKISU_KPM_KFUNC_ENTRY(strrchr),
	SUKISU_KPM_KFUNC_ENTRY(strstr),
	SUKISU_KPM_KFUNC_ENTRY(memset),
	SUKISU_KPM_KFUNC_ENTRY(memcpy),
	SUKISU_KPM_KFUNC_ENTRY(memmove),
	SUKISU_KPM_KFUNC_ENTRY(memcmp),
	SUKISU_KPM_KFUNC_ENTRY(kstrdup),
	SUKISU_KPM_KFUNC_ENTRY(kmemdup),
	SUKISU_KPM_KFUNC_ENTRY(kasprintf),
	SUKISU_KPM_KFUNC_ENTRY(memchr),
	SUKISU_KPM_KFUNC_ENTRY(strcat),
	{ "mm_struct_offset",            (unsigned long)&sukisu_kpm_mm_struct_offset },
	{ "has_config_compat",           (unsigned long)&sukisu_kpm_has_config_compat },
	{ "has_syscall_wrapper",         (unsigned long)&sukisu_kpm_has_syscall_wrapper },
	{ "hook_syscalln",               (unsigned long)sukisu_kpm_hook_syscalln },
	{ "unhook_syscalln",             (unsigned long)sukisu_kpm_unhook_syscalln },
	{ "hook_compat_syscalln",        (unsigned long)sukisu_kpm_hook_compat_syscalln },
	{ "unhook_compat_syscalln",      (unsigned long)sukisu_kpm_unhook_compat_syscalln },
	{ "syscalln_addr",               (unsigned long)sukisu_kpm_syscalln_addr },
	{ "syscalln_name_addr",          (unsigned long)sukisu_kpm_syscalln_name_addr },
	{ "_task_pt_reg",                (unsigned long)sukisu_kpm_task_pt_reg },
	{ "is_su_allow_uid",             (unsigned long)sukisu_kpm_is_su_allow_uid },
	{ "get_ap_mod_exclude",          (unsigned long)sukisu_kpm_get_ap_mod_exclude },
	{ "set_ap_mod_exclude",          (unsigned long)sukisu_kpm_set_ap_mod_exclude },
	{ "hotpatch_nosync",             (unsigned long)sukisu_kpm_hotpatch_nosync },
	{ "hook_wrap",                   (unsigned long)hook_wrap },
	{ "hook_unwrap_remove",          (unsigned long)hook_unwrap_remove },
#ifdef CONFIG_ARM64
	/* The KP inline-hook engine (kp_hook.c) is arm64-only. On
	 * other architectures these entries resolve to stubs (below). */
	{ "hook_chain_add",              (unsigned long)hook_chain_add },
	{ "hook_chain_remove",           (unsigned long)hook_chain_remove },
	{ "hook_prepare",                (unsigned long)hook_prepare },
	{ "hook_install",                (unsigned long)hook_install },
	{ "hook_uninstall",              (unsigned long)hook_uninstall },
	{ "hook",                        (unsigned long)hook },
#else
	{ "hook_chain_add",              (unsigned long)sukisu_kpm_hook_unsupported },
	{ "hook_chain_remove",           (unsigned long)sukisu_kpm_hook_unsupported },
	{ "hook_prepare",                (unsigned long)sukisu_kpm_hook_unsupported },
	{ "hook_install",                (unsigned long)sukisu_kpm_hook_unsupported },
	{ "hook_uninstall",              (unsigned long)sukisu_kpm_hook_unsupported },
	{ "hook",                        (unsigned long)sukisu_kpm_hook_unsupported },
#endif
	{ "unhook",                      (unsigned long)unhook },
};

/* On x86_64 (no kp_hook.o) the symbols hook_wrap / hook_unwrap_remove /
 * unhook are not provided anywhere else, so the table entries above
 * would not link. Alias them to the -ENOSYS stub. */
#ifndef CONFIG_ARM64
static long hook_unwrap_remove(void *func, void *before, void *after, int remove);
static long hook_wrap(void *func, long argno, void *before, void *after, void *udata);
static long unhook(void *func);

static long hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
	(void)func; (void)before; (void)after; (void)remove;
	return -ENOSYS;
}

static long hook_wrap(void *func, long argno, void *before, void *after, void *udata)
{
	(void)func; (void)argno; (void)before; (void)after; (void)udata;
	return -ENOSYS;
}

static long unhook(void *func)
{
	(void)func;
	return -ENOSYS;
}
#endif

unsigned long sukisu_kpm_symbol_lookup(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sukisu_kpm_symbols); i++) {
		if (!strcmp(name, sukisu_kpm_symbols[i].name))
			return sukisu_kpm_symbols[i].addr;
	}
	return 0;
}

/* ── Init ─────────────────────────────────────────────────── *
 * Resolve the kernel-version-dependent slots and call out into the
 * SukiSU policy layer for the offset/allowlist data. */

int kp_compat_init(void)
{
	/* Function pointer variables: point at the local trampolines
	 * (or at the kernel's own kallsyms_lookup_name). */
	sukisu_kpm_printk_fn = sukisu_kpm_printk;
	sukisu_kpm_kallsyms_lookup_name_fn = (void *)kallsyms_lookup_name;
	sukisu_kpm_kallsyms_on_each_symbol_fn =
		(void *)kallsyms_lookup_name("kallsyms_on_each_symbol");

	/* kf_* helpers: resolve to the running kernel's
	 * implementations. */
	SUKISU_KPM_KFUNC_INIT(sprintf);
	SUKISU_KPM_KFUNC_INIT(snprintf);
	SUKISU_KPM_KFUNC_INIT(vsnprintf);
	SUKISU_KPM_KFUNC_INIT(strcpy);
	SUKISU_KPM_KFUNC_INIT(strncpy);
	SUKISU_KPM_KFUNC_INIT(strncat);
	SUKISU_KPM_KFUNC_INIT(strcmp);
	SUKISU_KPM_KFUNC_INIT(strncmp);
	SUKISU_KPM_KFUNC_INIT(strlen);
	SUKISU_KPM_KFUNC_INIT(strnlen);
	SUKISU_KPM_KFUNC_INIT(strchr);
	SUKISU_KPM_KFUNC_INIT(strrchr);
	SUKISU_KPM_KFUNC_INIT(strstr);
	SUKISU_KPM_KFUNC_INIT(memset);
	SUKISU_KPM_KFUNC_INIT(memcpy);
	SUKISU_KPM_KFUNC_INIT(memmove);
	SUKISU_KPM_KFUNC_INIT(memcmp);
	SUKISU_KPM_KFUNC_INIT(kstrdup);
	SUKISU_KPM_KFUNC_INIT(kmemdup);
	SUKISU_KPM_KFUNC_INIT(kasprintf);
	SUKISU_KPM_KFUNC_INIT(memchr);
	SUKISU_KPM_KFUNC_INIT(strcat);

	/* mm_struct offsets. */
	sukisu_kpm_mm_struct_offset.mmap_base_offset  = offsetof(struct mm_struct, mmap_base);
	sukisu_kpm_mm_struct_offset.task_size_offset  = offsetof(struct mm_struct, task_size);
	sukisu_kpm_mm_struct_offset.pgd_offset        = offsetof(struct mm_struct, pgd);
	sukisu_kpm_mm_struct_offset.map_count_offset  = offsetof(struct mm_struct, map_count);
	sukisu_kpm_mm_struct_offset.total_vm_offset   = offsetof(struct mm_struct, total_vm);
	sukisu_kpm_mm_struct_offset.locked_vm_offset  = offsetof(struct mm_struct, locked_vm);
	sukisu_kpm_mm_struct_offset.pinned_vm_offset  = offsetof(struct mm_struct, pinned_vm);
	sukisu_kpm_mm_struct_offset.data_vm_offset    = offsetof(struct mm_struct, data_vm);
	sukisu_kpm_mm_struct_offset.exec_vm_offset    = offsetof(struct mm_struct, exec_vm);
	sukisu_kpm_mm_struct_offset.stack_vm_offset   = offsetof(struct mm_struct, stack_vm);
	sukisu_kpm_mm_struct_offset.start_code_offset = offsetof(struct mm_struct, start_code);
	sukisu_kpm_mm_struct_offset.end_code_offset   = offsetof(struct mm_struct, end_code);
	sukisu_kpm_mm_struct_offset.start_data_offset = offsetof(struct mm_struct, start_data);
	sukisu_kpm_mm_struct_offset.end_data_offset   = offsetof(struct mm_struct, end_data);
	sukisu_kpm_mm_struct_offset.start_brk_offset  = offsetof(struct mm_struct, start_brk);
	sukisu_kpm_mm_struct_offset.brk_offset        = offsetof(struct mm_struct, brk);
	sukisu_kpm_mm_struct_offset.start_stack_offset = offsetof(struct mm_struct, start_stack);
	sukisu_kpm_mm_struct_offset.arg_start_offset  = offsetof(struct mm_struct, arg_start);
	sukisu_kpm_mm_struct_offset.arg_end_offset    = offsetof(struct mm_struct, arg_end);
	sukisu_kpm_mm_struct_offset.env_start_offset  = offsetof(struct mm_struct, env_start);
	sukisu_kpm_mm_struct_offset.env_end_offset    = offsetof(struct mm_struct, env_end);

	sukisu_kpm_has_config_compat = 0;

	/* arm64 GKI: syscalls go through __arm64_sys_* wrappers, so
	 * the KPM must parse syscall args with the wrapper ABI
	 * (narg + 1). */
	sukisu_kpm_has_syscall_wrapper = 0;
	if (kallsyms_lookup_name("__arm64_sys_openat"))
		sukisu_kpm_has_syscall_wrapper = 1;

	/* Populate the standalone cred_offset scalar from the offset
	 * struct so KPMs that look it up by name resolve correctly. */
	sukisu_kpm_cred_offset = sukisu_kpm_task_struct_offset.cred_offset;

	pr_info("sukisu_kp_compat: stack facts: stack_in_task=%d stack_end=%d has_syscall_wrapper=%d\n",
		sukisu_kpm_stack_in_task_offset, sukisu_kpm_stack_end_offset,
		sukisu_kpm_has_syscall_wrapper);
	pr_info("sukisu_kp_compat: KPM compatibility layer initialized "
		"(%zu symbols, printk=%px kallsyms_lookup_name=%px kf_strncat=%px kf_strcmp=%px)\n",
		ARRAY_SIZE(sukisu_kpm_symbols),
		sukisu_kpm_printk_fn, sukisu_kpm_kallsyms_lookup_name_fn,
		kf_strncat, kf_strcmp);
	return 0;
}

#ifndef CONFIG_ARM64
/* On non-arm64 builds the inline-hook engine (kp_hook.c) is not
 * compiled. Provide a single -ENOSYS stub so the symbol table
 * still publishes the KP-ABI names without a link error. The
 * function is variadic and matches the loosest KP hook_*
 * signature; KPM-side headers declare the actual prototype the
 * KPM author is calling, and the stub is reached only through
 * the sukisu_kpm_symbols[] table (never invoked through a
 * declared function pointer). */
static long sukisu_kpm_hook_unsupported(void)
{
	return -ENOSYS;
}
#endif
