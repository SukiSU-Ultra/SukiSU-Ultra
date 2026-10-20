// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_DYNAMIC_SIG_FALLBACK
#define __KSU_H_DYNAMIC_SIG_FALLBACK

#include <linux/list.h>
#include <linux/static_call.h>

#include "manager/throne_tracker.h"

typedef bool (*ksu_sig_fallback_fn)(struct list_head *uid_data);
DECLARE_STATIC_CALL(ksu_sig_fallback, bool(struct list_head *));

static inline bool ksu_sig_fallback_run(struct list_head *uid_data)
{
    return static_call(ksu_sig_fallback)(uid_data);
}

void __init ksu_sig_fallback_init(void);
void __exit ksu_sig_fallback_exit(void);

#endif /* __KSU_H_DYNAMIC_SIG_FALLBACK */