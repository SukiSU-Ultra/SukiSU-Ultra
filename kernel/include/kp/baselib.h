/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_BASELIB_H_
#define _KP_BASELIB_H_
/* KP's baselib.h is the standalone libc (lib_memcpy/lib_strcmp/...). Inside
 * the kernel module build we just rely on the standard kernel/lib/string.c. */
#include <linux/string.h>
#include <linux/slab.h>
static inline void *lib_memcpy(void *dst, const void *src, size_t n) { return memcpy(dst, src, n); }
static inline void *lib_memmove(void *dst, const void *src, size_t n) { return memmove(dst, src, n); }
static inline void *lib_memset(void *dst, int c, size_t n) { return memset(dst, c, n); }
static inline int lib_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
static inline void *lib_memchr(const void *s, int c, size_t n) { return memchr(s, c, n); }
static inline char *lib_strcpy(char *d, const char *s) { return strcpy(d, s); }
static inline int lib_strcmp(const char *a, const char *b) { return strcmp(a, b); }
static inline int lib_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
static inline size_t lib_strlen(const char *s) { return strlen(s); }
static inline size_t lib_strnlen(const char *s, size_t n) { return strnlen(s, n); }
static inline char *lib_strchr(const char *s, int c) { return strchr(s, c); }
static inline char *lib_strrchr(const char *s, int c) { return strrchr(s, c); }
static inline char *lib_strstr(const char *h, const char *n) { return strstr(h, n); }
static inline char *lib_strcat(char *d, const char *s) { return strcat(d, s); }
static inline char *lib_strncat(char *d, const char *s, size_t n) { return strncat(d, s, n); }
static inline char *lib_strncpy(char *d, const char *s, size_t n) { return strncpy(d, s, n); }
static inline int lib_strcasecmp(const char *a, const char *b) { return strcasecmp(a, b); }
static inline int lib_strncasecmp(const char *a, const char *b, size_t n) { return strncasecmp(a, b, n); }
static inline size_t lib_strlcpy(char *d, const char *s, size_t n) { return strlcpy(d, s, n); }
#endif