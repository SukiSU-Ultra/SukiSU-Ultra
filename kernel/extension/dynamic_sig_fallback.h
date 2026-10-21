// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_DYNAMIC_SIG_FALLBACK
#define __KSU_H_DYNAMIC_SIG_FALLBACK

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/list.h>
#ifdef KSU_COMPAT_USE_STATIC_KEY
#include <linux/static_key.h>
#endif

typedef bool (*ksu_sig_fallback_fn)(struct list_head *uid_data);

#ifdef KSU_COMPAT_USE_STATIC_KEY
DECLARE_STATIC_KEY_FALSE(ksu_sig_fallback_key);
#define KSU_SIG_FALLBACK_ENABLE() static_branch_enable(&ksu_sig_fallback_key)
#define KSU_SIG_FALLBACK_DISABLE() static_branch_disable(&ksu_sig_fallback_key)
#else
extern bool ksu_sig_fallback_enabled;
#define KSU_SIG_FALLBACK_ENABLE() WRITE_ONCE(ksu_sig_fallback_enabled, true)
#define KSU_SIG_FALLBACK_DISABLE() WRITE_ONCE(ksu_sig_fallback_enabled, false)
#endif

extern ksu_sig_fallback_fn ksu_sig_fallback_current;

/*
 * Gate the call site on the feature switch.
 *
 * With static keys this compiles to a jump-label test: once the branch is
 * enabled the call site is an unconditional jump, while disabled it is a
 * single NOP. Without them (very old kernels) we fall back to a
 * __read_mostly bool read.
 *
 * The implementation pointer is re-read with READ_ONCE() and NULL-checked
 * in both cases, so a racing unregister can never turn into a NULL call.
 */
static inline bool ksu_sig_fallback_run(struct list_head *uid_data)
{
    ksu_sig_fallback_fn fn;

#ifdef KSU_COMPAT_USE_STATIC_KEY
    if (!static_branch_unlikely(&ksu_sig_fallback_key))
        return false;
#else
    if (unlikely(!READ_ONCE(ksu_sig_fallback_enabled)))
        return false;
#endif

    fn = READ_ONCE(ksu_sig_fallback_current);
    if (!fn)
        return false;

    return fn(uid_data);
}

int ksu_sig_fallback_register(ksu_sig_fallback_fn fn);
void ksu_sig_fallback_unregister(void);
bool ksu_sig_fallback_registered(void);

void __init ksu_sig_fallback_init(void);
void __exit ksu_sig_fallback_exit(void);

#endif /* __KSU_H_DYNAMIC_SIG_FALLBACK */