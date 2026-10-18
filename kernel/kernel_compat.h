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

#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 18, 0)
#include "external/linux_overflow.h"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 9, 0)
#include "external/linux_hashtable.h"
#endif

#ifndef READ_ONCE
#define READ_ONCE(x) (*(const volatile typeof(x) __may_alias *)&(x))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, y) (*(volatile typeof(x) __may_alias *)&(x) = (typeof(x) __may_alias)(y))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0) && !defined(smp_store_release)
#define smp_store_release(p, v) do { smp_mb(); WRITE_ONCE(*p, v); } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
static noinline void ksu_do_nothing(void *unused) { };
__weak void kick_all_cpus_sync(void)
{
	smp_mb();
	smp_call_function(ksu_do_nothing, NULL, 1);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#define memzero_explicit(ptr, count) memset_explicit(ptr, 0, count)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static void *ksu_kvmalloc(size_t bytes, gfp_t flags)
{
	void *p = kmalloc(bytes, flags);
	if (p)
		return p;

	if (flags & __GFP_ZERO)
		return vzalloc(bytes);

	return vmalloc(bytes);
}
#define kvmalloc ksu_kvmalloc

static void ksu_kvfree(const void *buf)
{
	if (is_vmalloc_addr(buf))
		vfree(buf);
	else
		kfree(buf);
}
#define kvfree ksu_kvfree
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
static void *ksu_kvcalloc(size_t n, size_t size, gfp_t flags)
{
	size_t bytes;
	if (check_mul_overflow(n, size, &bytes))
		return nullptr;

	return kvmalloc(bytes, flags | __GFP_ZERO);
}
#define kvcalloc ksu_kvcalloc
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) // probe_kernel_read
__weak long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
	// https://elixir.bootlin.com/linux/v5.2.21/source/mm/maccess.c#L27
	long ret;
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst, (__force const void __user *)src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) // probe_user_read
__weak long copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
	// https://elixir.bootlin.com/linux/v5.8/source/mm/maccess.c#L205
	long ret = -EFAULT;
	mm_segment_t old_fs = get_fs();

	set_fs(USER_DS);

	/**
	 * normally theres an access_ok check here
	 * but for what we use it, it will always be true. 
	 * we skip it.
	 */
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst, src, size);
	pagefault_enable();

	set_fs(old_fs);

	if (ret)
		return -EFAULT;
	return 0;
}
#endif

/**
 * copy_from_user_retry(): try nofault copy first, then fall back to faulting copy
 * return: 0 on success
 */
static __always_inline long copy_from_user_retry(void *to, const void __user *from, unsigned long count)
{
	long ret = copy_from_user_nofault(to, from, count);
	if (likely(!ret))
		return ret;

	// we faulted! fallback to slow path
	return copy_from_user(to, from, count);
}

/**
 * memmove_user(): memmove user memory through a temp buffer
 * return: 0 on success
 */
static __always_inline long memmove_user(void __user *dst, const void __user *src, size_t count)
{
	char *buf __offstack_flags(count, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (!!copy_from_user_retry(buf, src, count))
		return -EFAULT;

	if (!!copy_to_user(dst, buf, count))
		return -EFAULT;

	return 0;
}

#ifdef TIF_SECCOMP
#define ksu_is_seccomp_enabled() test_thread_flag(TIF_SECCOMP)
#else
#define ksu_is_seccomp_enabled() (!!current->seccomp.mode)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
static noinline ssize_t ksu_kernel_read_compat(struct file *file, void *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs = get_fs();
	set_fs(get_ds());
	ssize_t result = vfs_read(file, (void __user *)buf, count, pos);
	set_fs(old_fs);
	return result;
}
#define kernel_read ksu_kernel_read_compat

static noinline ssize_t ksu_kernel_write_compat(struct file *file, const void *buf, size_t count, loff_t *pos)
{
	mm_segment_t old_fs = get_fs();
	set_fs(get_ds());
	ssize_t res = vfs_write(file, (__force const char __user *)buf, count, pos);
	set_fs(old_fs);
	return res;
}
#define kernel_write ksu_kernel_write_compat
#endif // < 4.14

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#define d_inode(dentry) ((dentry)->d_inode)
#endif

// for supercalls.c fd install tw
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0) && !defined(TWA_RESUME)
#define TWA_RESUME 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
static __nocfi struct file *ksu_dentry_open(const struct path *path, int flags, const struct cred *cred)
{
	// new type: struct file * dentry_open(const struct path *, int, const struct cred *);
	extern typeof(dentry_open) dentry_open;
	if (!__builtin_types_compatible_p(typeof(dentry_open), typeof(ksu_dentry_open)))
		goto old_fn;

	typeof(ksu_dentry_open) *fn_new = (void *)&dentry_open;
	return fn_new(path, flags, cred);

old_fn:; // old type: struct file * dentry_open(struct dentry *, struct vfsmount *, int, const struct cred *);
	struct file *(*fn_old)(struct dentry *, struct vfsmount *, int, const struct cred *) = (void *)&dentry_open;
	/**
	 * old dentry_open consumes a reference regardless of failure or success (dput/mntput)
	 * we have take one before calling it, else it releases caller's reference. see nameidata_to_filp
	 */
	path_get((struct path *)path); // unqual
	return fn_old((*path).dentry, (*path).mnt, flags, cred);
}
#define dentry_open ksu_dentry_open
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
__weak int path_mount(const char *dev_name, struct path *path, const char *type_page, unsigned long flags, void *data_page)
{
	char *buf __offstack_flags(PATH_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	char *realpath = d_path(path, buf, PATH_MAX);
	if (IS_ERR(realpath) || realpath == buf)
		return -ENOENT;

	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	long ret = do_mount(dev_name, (const char __user *)realpath, type_page, flags, data_page);
	set_fs(old_fs);
	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0) && !defined(replace_fops)
#define replace_fops(f, fops) do {		\
	struct file *__file = (f);		\
	fops_put(__file->f_op);			\
	BUG_ON(!(__file->f_op = (fops))); 	\
} while(0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0) && defined(CONFIG_JUMP_LABEL)
#define KSU_CAN_USE_JUMP_LABEL

// https://elixir.bootlin.com/linux/v3.10.108/source/include/linux/jump_label.h#L211
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
static inline void ksu_static_key_enable(struct static_key *key)
{
	int count = atomic_read(&key->enabled);
	if (!count)
		static_key_slow_inc(key);
}

static inline void ksu_static_key_disable(struct static_key *key)
{
	int count = atomic_read(&key->enabled);
	if (count)
		static_key_slow_dec(key);
}

static inline int ksu_static_key_count(struct static_key *key)
{
	return atomic_read(&key->enabled);
}

struct ksu_static_key_true_false { struct static_key key; };

#ifdef CC_HAVE_ASM_GOTO
#define KSU_STATIC_KEY_TRUE_INIT	{ .key = { .enabled = ATOMIC_INIT(1), .entries = (void *)1 } }
#define KSU_STATIC_KEY_FALSE_INIT	{ .key = { .enabled = ATOMIC_INIT(0), .entries = (void *)0 } }
#else
#define KSU_STATIC_KEY_TRUE_INIT	{ .key = { .enabled = ATOMIC_INIT(1) } }
#define KSU_STATIC_KEY_FALSE_INIT	{ .key = { .enabled = ATOMIC_INIT(0) } }
#endif

#define DEFINE_STATIC_KEY_TRUE(name)	struct ksu_static_key_true_false name = KSU_STATIC_KEY_TRUE_INIT
#define DEFINE_STATIC_KEY_FALSE(name)	struct ksu_static_key_true_false name = KSU_STATIC_KEY_FALSE_INIT

#define static_key_enable(x)		ksu_static_key_enable(x)
#define static_key_disable(x)		ksu_static_key_disable(x)

#define static_branch_enable(x)		ksu_static_key_enable(&(x)->key)
#define static_branch_disable(x)	ksu_static_key_disable(&(x)->key)

#define static_branch_inc(x)		ksu_static_key_enable(&(x)->key)
#define static_branch_dec(x)		ksu_static_key_disable(&(x)->key)

#define static_branch_unlikely(x)	static_key_false(&(x)->key)
#define static_branch_likely(x)		static_key_true(&(x)->key)

// NOTE: on 4.4+ this is overloaded, but no big deal, that struct's first member is the key
#define static_key_enabled(x)		({ ksu_static_key_count((struct static_key *)x) > 0; })

#endif // < 4.3
#endif // >= 3.4 && CONFIG_JUMP_LABEL

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

#ifndef untagged_addr
#ifdef CONFIG_ARM64
static __always_inline __s64 ksu_sign_extend64(__u64 value, int index)
{
	__u8 shift = 63 - index;
	return (__s64)(value << shift) >> shift;
}
#define untagged_addr(addr) ksu_sign_extend64((__u64)addr, 55)
#else
#define untagged_addr(addr) (addr)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0) || !defined(CONFIG_EXT4_FS)
__weak void ext4_unregister_sysfs(struct super_block *sb)
{
	pr_info("%s: feature not implemented!\n", __func__);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0) && !defined(strscpy)
/**
 * hand-rolled strscpy from builtins.
 *
 * not 1:1, no aligned/per-word optimization.
 * discardable since 4.16: https://github.com/torvalds/linux/commit/08a77676f9c5
 */
static ssize_t ksu_strscpy(char *dest, const char *src, size_t count)
{
	if (!count)
		return -E2BIG;

	// look for the first null terminator w/in count
	// alternatively, strnlen?
	const char *end = __builtin_memchr(src, '\0', count);
	if (!end)
		goto no_null_term;

	size_t copy_len = end - src + 1; // +1 to copy \0
	__builtin_memcpy(dest, src, copy_len);
	return copy_len;

no_null_term:
	__builtin_memcpy(dest, src, count - 1);
	dest[count - 1] = '\0';
	return -E2BIG;
}
#define strscpy ksu_strscpy
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0) && !defined(strscpy_pad)
// https://elixir.bootlin.com/linux/v5.2-rc1/source/lib/string.c#L259
static ssize_t ksu_strscpy_pad(char *dest, const char *src, size_t count)
{
	ssize_t written = strscpy(dest, src, count);
	if (written < 0 || written == count - 1)
		return written;
	memset(dest + written + 1, 0, count - written - 1);
	return written;
}
#define strscpy_pad ksu_strscpy_pad
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
// https://elixir.bootlin.com/linux/v3.16/source/lib/string.c#L305
static char *ksu_strchrnul(const char *s, int c)
{
	while (*s && *s != (char)c)
		s++;
	return (char *)s;
}
#define strchrnul ksu_strchrnul
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#define d_is_reg(dentry) S_ISREG((dentry)->d_inode->i_mode)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0) && !defined(KSU_HAS_ITERATE_DIR)
struct dir_context { const filldir_t actor; loff_t pos; };
// #define iterate_dir(file, ctx) vfs_readdir(file, (ctx)->actor, ctx)
static int ksu_iterate_dir(struct file *file, struct dir_context *ctx)
{
	extern int vfs_readdir(struct file *file, filldir_t filler, void *buf);

	// torvalds/linux bb6f619b3a49f940d7478112500da312d70866eb
	ctx->pos = file->f_pos;
	int ret = vfs_readdir(file, ctx->actor, ctx);
	file->f_pos = ctx->pos;
	return ret;
}
#define iterate_dir ksu_iterate_dir
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
__weak char *bin2hex(char *dst, const void *src, size_t count)
{
	const unsigned char *_src = src;
	while (count--) {
		sprintf(dst, "%02x", *_src++);
		dst = dst + 2;
	}
	return dst;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
#define file_inode(file) ((file)->f_path.dentry->d_inode)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0) && !defined(CONFIG_LSM)
#define selinux_inode(inode) ((inode)->i_security)
#define selinux_cred(cred) ((cred)->security)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 15, 0)
__weak void groups_sort(struct group_info *group_info) { } // no-op
#endif

#ifndef U16_MAX
#define	U16_MAX	((u16)(~0U))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 12, 0) && !defined(EPOLLIN)
#define EPOLLIN		0x00000001
#define EPOLLPRI	0x00000002
#define EPOLLOUT	0x00000004
#define EPOLLERR	0x00000008
#define EPOLLHUP	0x00000010
#define EPOLLRDNORM	0x00000040
#define EPOLLRDBAND	0x00000080
#define EPOLLWRNORM	0x00000100
#define EPOLLWRBAND	0x00000200
#define EPOLLMSG	0x00000400
#define EPOLLRDHUP	0x00002000
#endif // < 4.12 && !EPOLLIN

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 15, 0)
#define task_ppid_nr(__unused) ({ (pid_t)sys_getppid(); })
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 17, 0)
static inline u64 ksu_ktime_get_ns(void) { return ktime_to_ns(ktime_get()); }
#define ktime_get_ns ksu_ktime_get_ns
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 4, 0)
// this is okay for current use
// #define vm_mmap(__unused, addr, len, prot, flag, offset) sys_mmap_pgoff(addr, len, prot, flag, 0, offset >> PAGE_SHIFT)
__weak unsigned long vm_mmap(struct file *file, unsigned long addr, unsigned long len,
			unsigned long prot, unsigned long flags, unsigned long offset)
{
	// The caller must hold down_write(&current->mm->mmap_sem).
	down_write(&current->mm->mmap_sem);
	unsigned long ret = do_mmap_pgoff(file, addr, len, prot, flags, offset >> PAGE_SHIFT);
	up_write(&current->mm->mmap_sem);
	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (4, 12, 0) && !defined(ALIGN_DOWN)
#define ALIGN_DOWN(x, a) __ALIGN_KERNEL((x) - ((a) - 1), (a))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 9, 0)
static inline int __must_check ksu_kref_get_unless_zero(struct kref *kref)
{ 
	return atomic_add_unless(&kref->refcount, 1, 0); 
}
#define kref_get_unless_zero ksu_kref_get_unless_zero
#endif // < 3.9

/**
 *  kver agnostic workaround for < 3.14's CONFIG_UIDGID_STRICT_TYPE_CHECKS=n
 *
 *  - force dereferences an unsigned int (uid_t)
 *  - redefines current_uid / current_euid macros
 *
 * ref
 *  - https://elixir.bootlin.com/linux/v3.13/source/include/linux/uidgid.h
 *  - https://elixir.bootlin.com/linux/v3.13/source/include/linux/cred.h#L331
 */
#define ksu_get_uid_t(x) *(unsigned int *)&(x)

#if LINUX_VERSION_CODE < KERNEL_VERSION (3, 14, 0)
#undef current_uid
#undef current_euid
typedef struct { uid_t val; } ksu_kuid_t;
static inline ksu_kuid_t current_uid() { return *(ksu_kuid_t *)(&current_cred()->uid); }
static inline ksu_kuid_t current_euid() { return *(ksu_kuid_t *)(&current_cred()->euid); }
#endif // < 3.14

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
static __nocfi struct user_struct *ksu_alloc_uid(uid_t uid)
{
	// old: struct user_struct *alloc_uid(struct user_namespace *ns, uid_t uid)
	// new: struct user_struct *alloc_uid(kuid_t uid)
	extern typeof(alloc_uid) alloc_uid;
	if (!__builtin_types_compatible_p(typeof(alloc_uid), struct user_struct *(struct user_namespace *, uid_t)))
		goto new_fn;

	return ((struct user_struct *(*)(struct user_namespace *, uid_t))&alloc_uid)(current_user_ns(), uid);

new_fn:;
	/**
	 * HACK: some kernels does NOT have kuid_t typedef, it wont compile.
	 * either way uid_t == kuid_t == ksu_kuid_t, so use a dummy struct
	 * doesn't rly matter, just explicitness, an excuse to use ksu_kuid_t
	 */
	struct user_struct *(*fn_new)(ksu_kuid_t uid) = (void *)&alloc_uid;
	ksu_kuid_t kuid = { .val = uid };
	return fn_new(kuid);
}
#define alloc_uid(kuid) ksu_alloc_uid(ksu_get_uid_t(kuid))
#endif

#if defined(CONFIG_KEYS) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)

#define KEY_SPEC_SESSION_KEYRING	-3	/* - key ID for session-specific keyring */
#ifdef KEY_DEFER_PERM_CHECK // torvalds/linux 8c0637e950d68933a67f7438f779d79b049b5e5c
extern key_ref_t lookup_user_key(key_serial_t id, unsigned long lflags, enum key_need_perm need_perm);
#define KSU_KEY_ALLPERM KEY_DEFER_PERM_CHECK
#else
extern key_ref_t lookup_user_key(key_serial_t id, unsigned long lflags, key_perm_t perm);
#define KSU_KEY_ALLPERM 0
#endif

static void ksu_grab_init_session_keyring()
{
	extern int install_session_keyring_to_cred(struct cred *, struct key *);
	extern bool is_init(const struct cred* cred);
	extern struct cred* ksu_cred;
	static struct key *init_session_keyring = nullptr;

	if (init_session_keyring)
		return;

	if (!is_init(current_cred()))
		return;

	if (!!strcmp(current->comm, "init"))
		return;

	// now we are sure that this is the key we want
	key_ref_t key_ref = lookup_user_key(KEY_SPEC_SESSION_KEYRING, 0, KSU_KEY_ALLPERM);
	if (IS_ERR(key_ref))
		return;

	init_session_keyring = key_ref_to_ptr(key_ref);

	pr_info("init_session_keyring: 0x%lx \n", (uintptr_t)init_session_keyring);
	install_session_keyring_to_cred(ksu_cred, init_session_keyring);
}
#else
#define ksu_grab_init_session_keyring() do { } while (0)
#endif // KEYS && < 5.2

#endif // __KSU_H_KERNEL_COMPAT
