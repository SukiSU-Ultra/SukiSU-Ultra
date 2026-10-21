// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#pragma once
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <elf.h>
#include <stdint.h>
#include <dirent.h>

// macro overrides is much more portable than typedef redefinitions
#define __aligned_u64	uint64_t
#define __u64		uint64_t
#define __s64		int64_t
#define __u32		uint32_t
#define __s32		int32_t
#define __u16		uint16_t
#define __s16		int16_t
#define __u8		uint8_t
#define __s8		int8_t

#include "../../include/uapi/app_profile.h"
#include "../../include/uapi/supercall.h"

/**
 * while we can actually just let libc map these for us
 * we can reduce binary size by 4kB by actually manually mapping
 * libc functions to respective syscalls, and workaround some kinks
 *
 * TODO: maybe test on arm32
 */
#define small_rt_use_errno
#include "small_rt.h"
#define syscall __syscall

#define sys_reboot(a, b, c, d)	syscall(SYS_reboot, a, b, c, d)
#define sys_ioctl(a, b, c)	syscall(SYS_ioctl, a, b, c)
#define getdents64(a, b, c)	syscall(SYS_getdents64, a, b, c)
#define open(path, flags, ...)	syscall(SYS_openat, AT_FDCWD, path, flags, ##__VA_ARGS__)
#define close(fd)		syscall(SYS_close, fd)
#define read(fd, buf, count)	syscall(SYS_read, fd, buf, count)
#define write(fd, buf, count)	syscall(SYS_write, fd, buf, count)
#define fsync(fd)		syscall(SYS_fsync, fd)
#define chdir(path)		syscall(SYS_chdir, path)

static long __sys_exit(int code)
{
	syscall(SYS_exit, code);
	__builtin_unreachable();
	return 42;
}
#define _exit __sys_exit

#if defined(__arm__) // map to fstatat64
#define SYS_newfstatat SYS_fstatat64
#endif
#define fstat(fd, st)		syscall(SYS_newfstatat, fd, "", st, AT_EMPTY_PATH)
#define lstat(path, st)		syscall(SYS_newfstatat, AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW)

#define fork()			syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0)
#define waitpid(a, b, c)	syscall(SYS_wait4, a, b, c, 0)
#define setpgid(pid, pgid)	syscall(SYS_setpgid, pid, pgid)
#define execve(fn, arg, env)	syscall(SYS_execve, fn, arg, env)

#define pipe2(pipefd, flags)	syscall(SYS_pipe2, pipefd, flags)
#define kill(pid, sig)		syscall(SYS_kill, pid, sig)

#define nanosleep(req, rem)	syscall(SYS_nanosleep, req, rem)

/**
 * map clock_gettime specifically, we do NOT want a vdso call.
 * also, map to old gettime for armeabi as it will -ENOSYS on k3.x.
 * it can truncate on Y2038 but not a big deal.
 */
#if defined(__arm__)
struct old_timespec32 { int32_t tv_sec; int32_t	tv_nsec; };
static int __sys_clock_gettime_shim(int clk, struct timespec *ts)
{
	struct old_timespec32 ts32;
#define SYS_clock_gettime32 263
	int ret = syscall(SYS_clock_gettime32, clk, &ts32);
	ts->tv_sec = ts32.tv_sec;
	ts->tv_nsec = ts32.tv_nsec;
	return ret;
}
#define clock_gettime(clk, ts)	__sys_clock_gettime_shim(clk, ts)
#else
#define clock_gettime(clk, ts)	syscall(SYS_clock_gettime, clk, ts)
#endif

// https://elixir.bootlin.com/linux/v4.14.1/source/fs/file.c#L876
// https://elixir.bootlin.com/musl/v1.2.6/source/src/unistd/dup2.c#L6
static int sys_dup2(int old, int new)
{
	if (old == new) { // basically just check if valid
		long r = syscall(SYS_fcntl, old, F_GETFD);
		return (r >= 0) ? old : r;
	}
	return syscall(SYS_dup3, old, new, 0);
}
#define dup2 sys_dup2

// https://elixir.bootlin.com/musl/v1.2.6/source/src/select/poll.c#L6
// both armeabi and aarch64 has ppoll, we use ppoll.
static int __sys_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
	typedef long ppoll_ts_t[2];
	return syscall(SYS_ppoll, fds, nfds, timeout_ms >= 0 ?
		((ppoll_ts_t){ timeout_ms / 1000, (timeout_ms % 1000) * 1000000L }) : NULL,
		NULL, _NSIG / 8);
}
#define poll __sys_poll

#if defined(__arm__) // https://elixir.bootlin.com/linux/v3.0.101/source/arch/arm/kernel/entry-common.S#L580
#define SYS_mmap2 192
#define mmap(addr, len, prot, flags, fd, off) ({ (void *)syscall(SYS_mmap2, addr, len, prot, flags, fd, (off) >> 12); })
#else
#define mmap(addr, len, prot, flags, fd, off) ({ (void *)syscall(SYS_mmap, addr, len, prot, flags, fd, off); })
#endif

#define munmap(addr, len) syscall(SYS_munmap, addr, len)

#define __NR_init_module	SYS_init_module
#define __NR_finit_module	SYS_finit_module
#define __NR_execveat		SYS_execveat

struct __linux_dirent64 {
	uint64_t	d_ino;
	int64_t		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[0];
};
#define linux_dirent64 __linux_dirent64

/* buildinfo */

#define __runner_stringify2(x) #x
#define __runner_stringify(x) __runner_stringify2(x)

#define __runner_STDC __runner_stringify(__STDC_VERSION__)

#define __runner_ARCH "unknown"
#if defined(__aarch64__)
#define __runner_ARCH "aarch64"
#elif defined(__arm__)
#define __runner_ARCH "arm"
#endif

#define __runner_CLANG "Clang " __runner_stringify(__clang_major__) "." __runner_stringify(__clang_minor__) "." __runner_stringify(__clang_patchlevel__)
#define __runner_COMPILER __runner_CLANG " on zig " ZIG_VERSION

#define __runner_BUILD_INFO "KernelSU preinit ELF running on " __runner_ARCH "! / buildinfo: " __runner_COMPILER " stdc: " __runner_STDC

