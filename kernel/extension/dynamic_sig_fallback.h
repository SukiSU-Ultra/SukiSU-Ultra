// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_DYNAMIC_SIG_FALLBACK
#define __KSU_H_DYNAMIC_SIG_FALLBACK

#include <linux/list.h>

bool track_throne_sig_fallback_hook(struct list_head *uid_data);

#endif