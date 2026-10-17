/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_IO_H_
#define _KP_IO_H_
#include <linux/types.h>
/* kernel-side: reads/writes just deref volatile memory; no endian swap. */
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#endif