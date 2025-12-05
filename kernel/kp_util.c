#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/printk.h>
#include <linux/preempt.h>
#include <asm/current.h>

#include "kernel_compat.h"
#include "kp_util.h"

static bool try_set_access_flag(unsigned long addr)
{
#ifdef CONFIG_ARM64
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	spinlock_t *ptl;
	bool ret = false;

	if (!mm)
		return false;

	if (!mmap_read_trylock(mm))
		return false;

	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start)
		goto out_unlock;

	pgd = pgd_offset(mm, addr);
	if (!pgd_present(*pgd))
		goto out_unlock;

	p4d = p4d_offset(pgd, addr);
	if (!p4d_present(*p4d))
		goto out_unlock;

	pud = pud_offset(p4d, addr);
	if (!pud_present(*pud))
		goto out_unlock;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd))
		goto out_unlock;

	if (pmd_trans_huge(*pmd))
		goto out_unlock;

	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (!ptep)
		goto out_unlock;

	pte = *ptep;

	if (!pte_present(pte))
		goto out_pte_unlock;

	if (pte_young(pte)) {
		ret = true;
		goto out_pte_unlock;
	}

	ptep_set_access_flags(vma, addr, ptep, pte_mkyoung(pte), 0);
	pr_info("set AF for addr %lx\n", addr);
	ret = true;

out_pte_unlock:
	pte_unmap_unlock(ptep, ptl);
out_unlock:
	mmap_read_unlock(mm);
	return ret;
#else
	return false;
#endif
}

bool ksu_strncpy_retry(const char __user **char_usr_ptr, char *dest,
		    size_t dest_len, bool exit_atomic_ctx)
{
	unsigned long addr;
	const char __user *fn;
	long ret;

	if (!char_usr_ptr)
		return false;

	addr = untagged_addr((unsigned long)*char_usr_ptr);
#ifdef CONFIG_KSU_DEBUG
	pr_info("got addr: %lu\n", addr);
#endif
	fn = (const char __user *)addr;
	memset(dest, 0, dest_len);
	ret = ksu_strncpy_from_user_nofault(dest, fn, dest_len);

	if (ret < 0 && try_set_access_flag(addr)) {
		ret = ksu_strncpy_from_user_nofault(dest, fn, dest_len);
	}

	/*
	 * This is crazy, but we know what we are doing:
         * Temporarily exit atomic context to handle page faults, then restore it.
         */
	if (exit_atomic_ctx) {
		if (ret < 0 && preempt_count()) {
#ifdef CONFIG_KSU_DEBUG
			pr_info("access to pointer failed, attempting to rescue..\n");
#endif
			preempt_enable_no_resched_notrace();
			ret = strncpy_from_user(dest, fn, dest_len);
			preempt_disable_notrace();
		}
	}

	if (ret < 0) {
		pr_err("strncpy_retry: all fallback were tried. err: %lu\n", ret);
		return false;
	}

	return true;
}
