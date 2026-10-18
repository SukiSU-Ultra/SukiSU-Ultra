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

#ifndef __KSU_H_VMAP_PATCH
#define __KSU_H_VMAP_PATCH

// vmap_patch.h safely write to read-only fn_ptr slots or syscall table.

/**
 * normally we want this on stop_machine, but we don't need HARD synchronization
 * we just let !cpuX use what they have in cache while we patch what is on cpuX.
 * not a big deal. this is safe since, pointer-write is atomic and the old ptr
 * still exists while in-patching.
 *
 * then we can just kick all the cpus, so they see the change and refetch.
 */
static inline void patch_ptr_slot_kick_cpu(void **target_slot, void *new_ptr)
{
// __atomic_store_n((uintptr_t *)target_slot, (uintptr_t)new_ptr, __ATOMIC_RELAXED);
	assume_dereferenceable((void *)target_slot, sizeof(uintptr_t));
	WRITE_ONCE(*target_slot, new_ptr);
	kick_all_cpus_sync();
}

static noinline int ksu_write_to_readonly_slot(uintptr_t slot_ptr, uintptr_t new_ptr)
{
	if (!slot_ptr || !new_ptr)
		return -EINVAL;

	uintptr_t addr = slot_ptr;
	uintptr_t base = addr & PAGE_MASK;
	uintptr_t offset = addr & ~PAGE_MASK;

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return -EFAULT;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return -ENOMEM;

	void **target_slot = (void **)((uintptr_t)writable_addr + offset);

	patch_ptr_slot_kick_cpu(target_slot, (void *)new_ptr);

	vunmap(writable_addr);
	smp_mb();

	return 0;
}

// WARNING!!! void * abuse ahead! (type-punning, pointer-hiding!)
// for 4.19+ old_ptr is actually syscall_fn_t *, which is just long * so we can consider this void **
// for 4.19- old_ptr is actually void **
// target_table is void *target_table[];
static noinline void read_and_replace_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr, void *target_table)
{
	void **sctable = (void **)target_table;
	void **syscall_slot_addr = &sctable[syscall_nr];

	if (!*syscall_slot_addr)
		return;

	// check that the pointer points inside kernel text
	extern char _stext[], _etext[];
	uintptr_t sc_slot = (uintptr_t)*syscall_slot_addr;
	if (!(sc_slot > (uintptr_t)_stext && sc_slot < (uintptr_t)_etext)) {
		pr_info("%s: syscall #%d at 0x%lx NOT pointing to kernel text!\n", __func__, syscall_nr, (long)syscall_slot_addr);
		return;
	}

	pr_info("%s: hooking syscall #%d at 0x%lx\n", __func__, syscall_nr, (long)syscall_slot_addr);

	/*
	 * basically the trick is
	 * addr, say 0xffff1234, this is READ-ONLY
	 * align it, 0xffff0000
	 * ptrdiff 0xffff1234 - 0xffff0000, 0x00001234
	 * vmap 0xffff0000, say we get 0xcccc0000 , now WRITABLE
	 * write on 0xcccc0000 + 0x00001234
	 *
	 */

	// prep vmap alias
	unsigned long addr = (unsigned long)syscall_slot_addr;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK; // offset_in_page

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	// use the alias
	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	// copy syscall's addr to storage variable
	*(void **)old_ptr = *target_slot;
	barrier();

	patch_ptr_slot_kick_cpu(target_slot, (void *)new_ptr);

	vunmap(writable_addr);
	smp_mb(); 
}

static noinline void restore_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr, void *target_table)
{
	void **sctable = (void **)target_table;
	void **syscall_slot_addr = &sctable[syscall_nr];

	if (!*syscall_slot_addr)
		return;

	/*
	 * we do this to make sure that old_ptr is filled.
	 * we risk a dead syscall !!!
	 * if read_and_replace failed or we restore again, it wont be pointing to anything
	 * it just copies wordsize of whatever is in *old_ptr, it should fill up a wordzie atleast
	 * yeah it really just dummy copies machine instructions at this point.
	 *
	 * normally we use probe_kernel_address / get_kernel_nofault here but the API is 
	 * so inconsistent across kernel versions, and since its just a dummied wrapper 
	 * for copy_from_kernel_nofault we can do it ourselves
	 *
	 */
	long dummy = 0;
	if (copy_from_kernel_nofault((void *)&dummy, *(void **)old_ptr, sizeof(long)))
		return;

	pr_info("%s: restore syscall #%d at 0x%lx\n", __func__, syscall_nr, (long)syscall_slot_addr);

	// prep vmap alias
	unsigned long addr = (unsigned long)syscall_slot_addr;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK; // offset_in_page

	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return;

	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	// use the alias
	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	// check if its ours
	if (*target_slot != new_ptr) {
		pr_info("%s: syscall is not ours!\n", __func__);
		goto out;
	}
	
	pr_info("%s: syscall is ours! *target_slot: 0x%lx new_ptr: 0x%lx\n", __func__, (long)*target_slot, (long)new_ptr);

	patch_ptr_slot_kick_cpu(target_slot, *(void **)old_ptr);

	// reset storage variable
	WRITE_ONCE(*(void **)old_ptr, NULL);
out:
	vunmap(writable_addr);
	smp_mb(); 
}

// just so we can print out syscall_nr
#define do_read_and_replace_syscall read_and_replace_syscall
#define read_and_replace_syscall(old_p, syscall_nr, new_p, table) ({		\
	pr_info("read_and_replace_syscall: hooking %s\n", #syscall_nr);		\
	do_read_and_replace_syscall(old_p, syscall_nr, new_p, table);		\
})

#define do_restore_syscall restore_syscall
#define restore_syscall(old_p, syscall_nr, new_p, table) ({			\
	pr_info("restore_syscall: unhooking %s\n", #syscall_nr);		\
	do_restore_syscall(old_p, syscall_nr, new_p, table);			\
})

#endif // __KSU_H_VMAP_PATCH
