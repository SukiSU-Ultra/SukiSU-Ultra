/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_COMPILER_H_
#define _KP_COMPILER_H_
/* The freestanding compiler.h provides attribute sugar and standalone type
 * keywords (likely/unlikely/barrier/__user/__force). The kernel already
 * provides all of these via <linux/compiler.h> + <linux/compiler_types.h>. */
#include <linux/compiler.h>
#include <linux/compiler_types.h>
#endif