/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_MOUNT_PROPAGATION
#define __KSU_H_MOUNT_PROPAGATION

int ksu_mount_propagation_init(void);
void ksu_mount_propagation_exit(void);
void ksu_set_zygote_started(void);

#endif /* __KSU_H_MOUNT_PROPAGATION */
