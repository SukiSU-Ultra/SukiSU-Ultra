/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LOG_H_
#define _KP_LOG_H_
/* Mirror KP's log prefixes but route through the kernel's printk so the
 * output shows up in dmesg alongside the rest of SukiSU. */
#include <linux/printk.h>

#define logkv(fmt, ...) pr_debug("[+] KP V " fmt, ##__VA_ARGS__)
#define logkfv(fmt, ...) pr_debug("[+] KP V %s: " fmt, __func__, ##__VA_ARGS__)
#define logkd(fmt, ...) pr_debug("[+] KP D " fmt, ##__VA_ARGS__)
#define logkfd(fmt, ...) pr_debug("[+] KP D %s: " fmt, __func__, ##__VA_ARGS__)
#define logki(fmt, ...) pr_info("[+] KP I " fmt, ##__VA_ARGS__)
#define logkfi(fmt, ...) pr_info("[+] KP I %s: " fmt, __func__, ##__VA_ARGS__)
#define logkw(fmt, ...) pr_warn("[-] KP W " fmt, ##__VA_ARGS__)
#define logkfw(fmt, ...) pr_warn("[-] KP W %s: " fmt, __func__, ##__VA_ARGS__)
#define logke(fmt, ...) pr_err("[-] KP E " fmt, ##__VA_ARGS__)
#define logkfe(fmt, ...) pr_err("[-] KP E %s: " fmt, __func__, ##__VA_ARGS__)

static inline void log_boot(const char *fmt, ...) { (void)fmt; }
static inline const char *get_boot_log(void) { return ""; }
#endif