#ifndef __KSU_H_KLOG
#define __KSU_H_KLOG

#include <linux/printk.h>

extern void write_sulog(uint8_t sym);
extern int send_sulog_dump(void __user *uptr);
extern void sulog_init_heap();

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "KernelSU: " fmt
#endif

#endif
