#ifndef __KSU_H_KSU_KBROBES_HOOK_MANAGER
#define __KSU_H_KSU_KBROBES_HOOK_MANAGER

#include <linux/init.h>
#include <linux/version.h>
#include <linux/binfmts.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include "selinux/selinux.h"
#include "objsec.h"

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC    0x1cd1
#endif

extern bool ksu_is_compat __read_mostly;

extern int __ksu_handle_devpts(struct inode *inode); // sucompat.c

void ksu_kprobe_hook_init(void);
void ksu_kprobe_hook_exit(void);

#endif