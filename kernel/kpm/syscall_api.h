#ifndef __SUKISU_KPM_SYSCALL_API_H
#define __SUKISU_KPM_SYSCALL_API_H

#include <asm/ptrace.h>
#include <linux/types.h>

/* KPM syscall bridge. Returning non-zero from before suppresses the original
 * syscall and uses the return value as the syscall result. */
typedef long (*kpm_syscall_before_t)(int nr, const struct pt_regs *regs, void *data);
typedef void (*kpm_syscall_after_t)(int nr, const struct pt_regs *regs, long result, void *data);

#define KPM_SYSCALL_CONTINUE LONG_MIN

int kpm_hook_syscall(int nr, kpm_syscall_before_t before,
                     kpm_syscall_after_t after, void *data);
int kpm_unhook_syscall(int nr, kpm_syscall_before_t before,
                       kpm_syscall_after_t after);

#endif
