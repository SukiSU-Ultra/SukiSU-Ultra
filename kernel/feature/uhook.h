/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_UHOOK
#define __KSU_H_UHOOK

/* Entry point for the KSU_IOCTL_UHOOK supercall (see uapi/supercall.h). */
struct ksu_uhook_cmd;
int ksu_uhook(struct ksu_uhook_cmd *cmd);

/* Resolve kernel symbols and initialise the hook table. Safe to call once. */
void ksu_uhook_init(void);
void ksu_uhook_exit(void);

#endif
