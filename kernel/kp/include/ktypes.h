/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Compatibility shim that redirects KP's freestanding headers to the real
 * kernel headers when the KP framework is compiled inside the SukiSU-Ultra
 * kernel module. The KP sources retain their original <ktypes.h>/<compiler.h>
 * /<pgtable.h>/... includes; we satisfy those names here so the LKM build
 * can pull in KP/KPM code without rewriting it.
 */
#ifndef _KP_KTYPES_H_
#define _KP_KTYPES_H_
#include <linux/types.h>
#include <linux/compiler.h>
#endif