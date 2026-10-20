// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_DYNAMIC_SIG_FALLBACK
#define __KSU_H_DYNAMIC_SIG_FALLBACK

#include <linux/list.h>
#include <linux/static_call.h>

typedef bool (*ksu_sig_fallback_fn)(struct list_head *uid_data);
DECLARE_STATIC_CALL(ksu_sig_fallback, bool(struct list_head *));
bool ksu_sig_fallback_stub(struct list_head *uid_data);

static inline bool ksu_sig_fallback_run(struct list_head *uid_data)
{
    return static_call(ksu_sig_fallback)(uid_data);
}

int ksu_sig_fallback_register(ksu_sig_fallback_fn fn);
void ksu_sig_fallback_unregister(void);
bool ksu_sig_fallback_registered(void);

void __init ksu_sig_fallback_init(void);
void __exit ksu_sig_fallback_exit(void);

#endif /* __KSU_H_DYNAMIC_SIG_FALLBACK */