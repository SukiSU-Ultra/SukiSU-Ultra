// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Compatibility symbol table exposed to KPMs. The KP project exposes a
 * small list of stable symbols (printk, memcpy, kallsyms_lookup_name, hook
 * helpers, etc.) and a per-module table of forwarders built into a
 * per-KPM trampoline. The LKM build instead resolves these symbols once
 * at module load time and pins the function pointer in kp_compat_*.
 * Anything else KPM asks for is delegated to kallsyms.
 */
#include <linux/cache.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <ktypes.h>
#include <log.h>

int kp_compat_printk(const char *fmt, ...);
void *kp_compat_memcpy(void *dst, const void *src, size_t n);
void *kp_compat_memmove(void *dst, const void *src, size_t n);
void *kp_compat_memset(void *dst, int c, size_t n);
int kp_compat_strcmp(const char *a, const char *b);
char *kp_compat_strcpy(char *dst, const char *src);
size_t kp_compat_strlen(const char *s);
int kp_compat_strncmp(const char *a, const char *b, size_t n);
int kp_compat_sprintf(char *buf, const char *fmt, ...);
int kp_compat_snprintf(char *buf, size_t size, const char *fmt, ...);
void kp_compat_panic(const char *fmt, ...);

int kp_compat_printk(const char *fmt, ...)
{
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = vprintk(fmt, ap);
    va_end(ap);
    return r;
}

void *kp_compat_memcpy(void *dst, const void *src, size_t n) { return memcpy(dst, src, n); }
void *kp_compat_memmove(void *dst, const void *src, size_t n) { return memmove(dst, src, n); }
void *kp_compat_memset(void *dst, int c, size_t n) { return memset(dst, c, n); }
int kp_compat_strcmp(const char *a, const char *b) { return strcmp(a, b); }
char *kp_compat_strcpy(char *dst, const char *src) { return strcpy(dst, src); }
size_t kp_compat_strlen(const char *s) { return strlen(s); }
int kp_compat_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
int kp_compat_sprintf(char *buf, const char *fmt, ...) { va_list ap; int r; va_start(ap, fmt); r = vsprintf(buf, fmt, ap); va_end(ap); return r; }
int kp_compat_snprintf(char *buf, size_t size, const char *fmt, ...) { va_list ap; int r; va_start(ap, fmt); r = vsnprintf(buf, size, fmt, ap); va_end(ap); return r; }
void kp_compat_panic(const char *fmt, ...)
{
    va_list ap;
    char buf[256];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    panic("%s", buf);
}

unsigned long kp_kallsyms_lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}
EXPORT_SYMBOL(kp_kallsyms_lookup_name);

int kp_kallsyms_on_each_symbol_wrapper(struct kpm_module *mod, int (*fn)(struct kpm_module *, const char *, unsigned long))
{
    struct kp_kallsyms_cb {
        int (*user_fn)(struct kpm_module *, const char *, unsigned long);
        struct kpm_module *mod;
    } ctx = { .user_fn = fn, .mod = mod };

    int bridge(void *data, const char *name, unsigned long addr)
    {
        struct kp_kallsyms_cb *c = data;
        return c->user_fn(c->mod, name, addr);
    }

    return kallsyms_on_each_symbol(bridge, &ctx);
}
EXPORT_SYMBOL(kp_kallsyms_on_each_symbol_wrapper);

EXPORT_SYMBOL(kp_compat_printk);
EXPORT_SYMBOL(kp_compat_memcpy);
EXPORT_SYMBOL(kp_compat_memmove);
EXPORT_SYMBOL(kp_compat_memset);
EXPORT_SYMBOL(kp_compat_strcmp);
EXPORT_SYMBOL(kp_compat_strcpy);
EXPORT_SYMBOL(kp_compat_strlen);
EXPORT_SYMBOL(kp_compat_strncmp);
EXPORT_SYMBOL(kp_compat_sprintf);
EXPORT_SYMBOL(kp_compat_snprintf);
EXPORT_SYMBOL(kp_compat_panic);