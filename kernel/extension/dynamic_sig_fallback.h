// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_DYNAMIC_SIG_FALLBACK
#define __KSU_H_DYNAMIC_SIG_FALLBACK

#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/static_key.h>

#include "manager/throne_tracker.h"

typedef bool (*ksu_sig_fallback_fn)(struct list_head *uid_data);

DECLARE_STATIC_KEY_FALSE(ksu_sig_fallback_key);

extern ksu_sig_fallback_fn ksu_sig_fallback_current;

static inline bool ksu_sig_fallback_run(struct list_head *uid_data)
{
    ksu_sig_fallback_fn fn;

    if (!static_branch_unlikely(&ksu_sig_fallback_key))
        return false;

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
