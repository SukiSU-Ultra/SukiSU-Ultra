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

#ifndef __KSU_H_KALLSYMS_COMMON
#define __KSU_H_KALLSYMS_COMMON

// kallsyms_lookup_name / sprint_symbol hacky AF symbol bruteforce
// WARNING: use only when needed! brittle code!

static noinline uint64_t chibihash64_wrapper(const char *input)
{
	return chibihash64((void *)input, (ptrdiff_t)strnlen(input, KSYM_SYMBOL_LEN), 0ULL);
}

struct symbol_hash_entry {
	uint64_t hash;
	uintptr_t addr;
};

static void *kallsyms_hash_array = nullptr;
static size_t kallsyms_hash_array_entry_count = 0;
static size_t kallsyms_hash_array_capacity = 0;

// TODO: rethink syncronization
static DEFINE_MUTEX(kallsyms_hash_array_mutex);
static volatile bool kallsyms_hash_array_ready __read_mostly = false;

// use this old version of kvrealloc to have full control on old size and new size.
// not a big deal, lets bring it with us.
static inline void *old_kvrealloc(const void *p, size_t oldsize, size_t newsize, gfp_t flags)
{
	void *newp;

	if (oldsize >= newsize)
		return (void *)p;
	newp = kvmalloc(newsize, flags);
	if (!newp)
		return nullptr;
	memcpy(newp, p, oldsize);
	kvfree(p);
	return newp;
}

static inline void insert_to_kallsyms_array(const char *str, uintptr_t addr)
{
	if (!str || !addr)
		return;

	struct symbol_hash_entry *entries = (struct symbol_hash_entry *)kallsyms_hash_array;
	uint64_t hash = chibihash64_wrapper(str);

	if (!entries)
		goto skip_anti_dup;

	size_t i;
	for (i = 0; i < kallsyms_hash_array_entry_count; i++) {
		if (entries[i].hash == hash)
			return;
	}

skip_anti_dup:;
	if (kallsyms_hash_array_entry_count < kallsyms_hash_array_capacity)
		goto size_is_sufficient;

	// size insufficient, so we need to resize our memery
	// lets just go double everytime
	size_t new_cap;
	if (!kallsyms_hash_array_capacity)
		new_cap = 256; // init 256 slots
	else
		new_cap = kallsyms_hash_array_capacity * 2;

	size_t old_sz = kallsyms_hash_array_capacity * sizeof(struct symbol_hash_entry);
	size_t new_sz = new_cap * sizeof(struct symbol_hash_entry);

	void *new_array = old_kvrealloc(kallsyms_hash_array, old_sz, new_sz, GFP_KERNEL);
	if (!new_array)
		return;

	pr_info("%s: hash array resized! %ld -> %ld bytes \n", __func__, old_sz, new_sz);
	kallsyms_hash_array = new_array;
	kallsyms_hash_array_capacity = new_cap;
	entries = kallsyms_hash_array;

size_is_sufficient:

	entries[kallsyms_hash_array_entry_count].hash = hash;
	entries[kallsyms_hash_array_entry_count].addr = addr;
	kallsyms_hash_array_entry_count++;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
__weak int sprint_symbol_no_offset(char *buffer, unsigned long address) { return sprint_symbol(buffer, address); }
#endif

#ifdef MODULE // https://elixir.bootlin.com/linux/v7.2-rc4/source/kernel/kprobes.c#L1506
static noinline __nocfi void ksu_kallsyms_lookup_size_offset(uintptr_t symaddr, unsigned long *sym_size, unsigned long *offset)
{
	static typeof(kallsyms_lookup_size_offset) *fn __read_mostly;
	static void *state = &&bootstrap;
	goto *state;

bootstrap:
	*(void **)&fn = (void *)kallsyms_lookup_name("kallsyms_lookup_size_offset");
	if (!!fn)
		state = &&fn_ok;
	else
		state = &&no_fn;

	goto *state;
fn_ok:
	fn(symaddr, sym_size, offset);
	return;

no_fn:
	*sym_size = 0;
	*offset = 0;
}
#define kallsyms_lookup_size_offset ksu_kallsyms_lookup_size_offset
#endif

static noinline void dotted_kallsyms_build_hash_array(void)
{
	extern char _stext[], _etext[];
	uintptr_t start = (uintptr_t)_stext;
	uintptr_t end = (uintptr_t)_etext;
	uintptr_t iter_count = 0;
	uintptr_t curr;

	cond_resched();

	char *membuf __offstack(KSYM_SYMBOL_LEN * 2);
	char *symbol_buf = membuf;
	char *symbol_cache = membuf + KSYM_SYMBOL_LEN;

	pr_info("%s: hash array init! \n", __func__);

	curr = start;

scan_start:
	iter_count++;

	// not needed actually, sprint_symbol terminates.
	// we keep it here as a reminder.
	// memset(symbol_buf, 0, sizeof(symbol_buf));

	sprint_symbol_no_offset(symbol_buf, curr);
	if (!symbol_buf[0])
		goto step_up;

	// if current symbol is same as last entry, skip
	if (!strcmp(symbol_buf, symbol_cache))
		goto step_up;

	// symbol is not the same as the last one!
	// cache this symbol and insert it to our hash array!
	strscpy(symbol_cache, symbol_buf, KSYM_SYMBOL_LEN);

	// however we should not use cfi_jt for this
	// what we want is the target of that cfi_jt
	if (strstr(symbol_buf, ".cfi_jt"))
		goto step_up;

	// we should not use isra/constprop/part for this as gcc folded this functiom
	// this has destroyed calling convention, hooking this is catastrophic!
	if ( strstr(symbol_buf, ".isra.") || strstr(symbol_buf, ".constprop.") || strstr(symbol_buf, ".part.") )
		goto step_up;

	// cut it with these to make sure its a match
	// .llvm.505034 or .lto_priv.0
	char *dot_ptr = strchr(symbol_buf, '.');
	if (!dot_ptr)
		goto step_up;

	// terminate on first dot
	dot_ptr[0] = '\0';

	insert_to_kallsyms_array(symbol_buf, curr);

step_up:;
	unsigned long sym_size = 0;
	unsigned long offset = 0;
	kallsyms_lookup_size_offset(curr, &sym_size, &offset);
	if ((!!sym_size || !!offset) && sym_size > offset)
		curr =  curr + (sym_size - offset); // we can do larger jumps
	else
		curr = curr + 4;

	if (curr < end)
		goto scan_start;

	pr_info("%s: scan done! total items: %zu, iter_count: %lu\n", __func__, kallsyms_hash_array_entry_count, iter_count);

	return;
}

static noinline uintptr_t kallsyms_lookup_hashed_name(const char *name)
{
	if (!name || !kallsyms_hash_array)
		return 0x0;

	uint64_t input_hash = chibihash64_wrapper(name);
	struct symbol_hash_entry *entries = (struct symbol_hash_entry *)kallsyms_hash_array;
	char symbol_buf[KSYM_SYMBOL_LEN];
	size_t i;

	for (i = 0; i < kallsyms_hash_array_entry_count; i++) {
		if (entries[i].hash == input_hash)
			goto found;
	}

	pr_info("%s: not found: %s hash: 0x%llx\n", __func__, name, input_hash);
	return 0x0;

found:
	sprint_symbol_no_offset(symbol_buf, entries[i].addr);

	// sanity check, hash collision might occur
	if (unlikely(!strstarts(symbol_buf, name)))
		goto collision_found;

	pr_info("%s: %s hash: 0x%llx at 0x%lx\n", __func__, symbol_buf, input_hash, entries[i].addr);
	return entries[i].addr;

collision_found:
	// this is unlikely, but hell yeah lets log it if it happens
	pr_info("%s: chibihash64 collision! name: %s symbol_buf: %s hash: 0x%llx\n", __func__, name, symbol_buf, input_hash);
	return 0x0;
}

// ksu says this isnt always available so lets use an fn ptr when using it on LKM
struct lookup_args {
	const char *target_name;
	uintptr_t target_addr;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
static int kallsyms_on_each_symbol_cb(void *data, const char *name, unsigned long addr)
#else
struct module;
static int kallsyms_on_each_symbol_cb(void *data, const char *name, struct module *module, unsigned long addr)
#endif
{
	struct lookup_args *args = (struct lookup_args *)data;
	char namebuf[KSYM_SYMBOL_LEN];

	// however we should not use cfi_jt for this
	// what we want is the target of that cfi_jt
	if (strstr(name, ".cfi_jt"))
		return 0;

	// we should not use isra/constprop/part for this as gcc folded this functiom
	// this has destroyed calling convention, hooking this is catastrophic!
	if ( strstr(name, ".isra.") || strstr(name, ".constprop.") || strstr(name, ".part.") )
		return 0;

	// terminate dot and compare
	strscpy(namebuf, name, KSYM_SYMBOL_LEN);
	char *dot_ptr = strchr(namebuf, '.');
	if (dot_ptr)
		dot_ptr[0] = '\0';

	if (!!strcmp(namebuf, args->target_name))
		return 0;
	
	// return match
	args->target_addr = addr;
	return 1;
}

static noinline __nocfi uintptr_t try_kallsyms_on_each_symbol(const char *name)
{
#ifdef MODULE // lazy init
	static typeof(kallsyms_on_each_symbol) *kallsyms_on_each_symbol_fn __read_mostly;
	static void *state = &&bootstrap;
	goto *state;

bootstrap:
	*(void **)&kallsyms_on_each_symbol_fn = (void *)kallsyms_lookup_name("kallsyms_on_each_symbol");
	if (!!kallsyms_on_each_symbol_fn)
		state = &&fn_ok;
	else
		state = &&no_fn;
	goto *state;
no_fn:
	return 0x0;

fn_ok:;
#else
#define kallsyms_on_each_symbol_fn kallsyms_on_each_symbol
#endif
	struct lookup_args args;
	args.target_name = name;
	args.target_addr = 0x0;

	int ret = kallsyms_on_each_symbol_fn(kallsyms_on_each_symbol_cb, &args);
	if (ret && args.target_addr)
		pr_info("kallsyms_on_each_symbol: success! %s at 0x%lx\n", name, args.target_addr);

	return args.target_addr;
}

#ifdef CONFIG_KPROBES // kprobes based symbol resolver.
static uintptr_t kp_kallsyms_lookup_name(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	if (!!register_kprobe(&kp))
		return 0x0;

	uintptr_t addr = (uintptr_t)kp.addr;
	unregister_kprobe(&kp);

	pr_info("%s: success! %s at 0x%lx\n", __func__, name, addr);
	return addr;
}
#endif

// if called within kthread, will try to build a kallsyms hash array when everything failed!
static noinline uintptr_t kallsyms_lookup_retry(const char *name)
{
	if (!name)
		return 0x0;

	uintptr_t addr = (uintptr_t)kallsyms_lookup_name(name);
	if (addr)
		goto found;

#ifdef CONFIG_KPROBES
	addr = kp_kallsyms_lookup_name(name);
	if (addr)
		goto found;
#endif

	addr = try_kallsyms_on_each_symbol(name);
	if (addr)
		goto found;

	smp_mb();
	if (kallsyms_hash_array_ready)
		return kallsyms_lookup_hashed_name(name);

	// only kthread is allowed to go further
	if (!(current->flags & PF_KTHREAD))
		return 0x0;

	if (guarded_mutex_lock(&kallsyms_hash_array_mutex) && !kallsyms_hash_array_ready) {
		dotted_kallsyms_build_hash_array();
		kallsyms_hash_array_ready = true;
		smp_mb();
	}

	return kallsyms_lookup_hashed_name(name);
	
found:;
	char namebuf[KSYM_NAME_LEN];
	sprint_symbol_no_offset(namebuf, addr);
	pr_info("%s: %s addr: 0x%lx \n", __func__, namebuf, addr);
	return addr;
}

// NOTE: absolute minimum compat, just to appease API.
static int kallsyms_lookup_batched(const char *const *names, unsigned long *addrs, u32 count)
{
	int resolved = 0;
	u32 i = 0;

	if (!names || !addrs)
		return -EINVAL;

loop_start:
	if (!names[i])
		goto next;

	addrs[i] = (unsigned long)kallsyms_lookup_retry(names[i]);
	if (!addrs[i])
		goto next;

	if (!is_module_address(addrs[i])) {
		addrs[i] = 0; // null module address
		goto next;
	}

	resolved++;
next:
	i++;
	if (i < count)
		goto loop_start;

	return resolved;
}

// compat to official ksu
#define find_kernel_symbol_exact 	kallsyms_lookup_retry
#define ksu_lookup_kernel_symbols	kallsyms_lookup_batched

// ksu_get_ksym_size, return symbol size, return retfail if fail.
static noinline size_t ksu_get_ksym_size(uintptr_t symbol_addr, size_t retfail)
{
	// https://github.com/backslashxx/KernelSU/pull/35
	unsigned long offset = 0;
	unsigned long symbolsize = 0;

	kallsyms_lookup_size_offset(symbol_addr, &symbolsize, &offset);

	// means lookup failed, just return retfail
	if (!symbolsize && !offset)
		return retfail;

	// pr_info("%s: symbolsize %d \n", __func__, symbolsize);

	return symbolsize;
}

/*
 * two possible users so far
 * this macro based refcounting timebomb is just me being responsible
 * letting this leak is not actually a big deal, maybe 512kb at most
 *
 * "if something was created and no one was around to free it, 
 *  is it a memory leak? or just permanent cache?"
 *  -- some retard "developer" using garbage collection
 *
 */
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
#define HASH_ARRAY_USER1 1
#else
#define HASH_ARRAY_USER1 0
#endif

#if defined(CONFIG_AUDIT) && defined(CONFIG_ARM64) && defined(CONFIG_KALLSYMS)
#define HASH_ARRAY_USER2 1
#else
#define HASH_ARRAY_USER2 0
#endif

#define TOTAL_HASH_ARRAY_USERS (HASH_ARRAY_USER1 + HASH_ARRAY_USER2)

static noinline void dotted_kallsyms_destroy_hash_array(void)
{
	guarded_mutex_lock(&kallsyms_hash_array_mutex);

	static volatile int entry_count = 0;

	entry_count++;
	if (entry_count != TOTAL_HASH_ARRAY_USERS)
		return;

	if (!kallsyms_hash_array)
		return;

	pr_info("%s: addr: 0x%lx entries: %u capacity: %u\n", __func__, (uintptr_t)kallsyms_hash_array, kallsyms_hash_array_entry_count, kallsyms_hash_array_capacity);

	memzero_explicit(kallsyms_hash_array, kallsyms_hash_array_entry_count * sizeof(struct symbol_hash_entry));

	kvfree(kallsyms_hash_array);

	kallsyms_hash_array = nullptr;
	kallsyms_hash_array_entry_count = 0;
	kallsyms_hash_array_capacity = 0;

	constexpr char hw[] = "Hello, world!";
	pr_info("chibihash64: '%s' #: 0x%llx \n", hw, chibihash64(hw, sizeof(hw) - 1, 0ULL));

}

#undef HASH_ARRAY_USER1
#undef HASH_ARRAY_USER2
#undef TOTAL_HASH_ARRAY_USERS

#endif // __KSU_H_KALLSYMS_COMMON
