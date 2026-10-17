/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_CACHE_H_
#define _KP_CACHE_H_
/* KP's freestanding cache.h declares arm64 cache primitives in raw asm.
 * The kernel module build uses the real <asm/cacheflush.h>. */
#include <asm/cacheflush.h>
#endif