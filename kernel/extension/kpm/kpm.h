/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_EXTENSION_KPM
#define __KSU_H_EXTENSION_KPM

/*
 * KPM (Kernel Patch Module) extension.
 *
 * Sticky state (u64 bit 0): whether CONFIG_KPM and the runtime KP bridge are available.
 * io op: forwards struct ksu_kpm_cmd to do_kpm().
 *
 * The actual KPM control surface (load / unload / list / info / control /
 * num / version) lives in extension/kpm/kpm.c. This header exposes only
 * the entry point that the extension glue (extension/kpm.c) needs.
 */

/* Dispatch a kpm control op from userspace. */
int do_kpm(void __user *arg);

#endif /* __KSU_H_EXTENSION_KPM */
