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

// selinux_hide's list, hand-rolled hazard pointers via C11 atomics

#ifndef __KSU_H_SELINUX_HIDE
#define __KSU_H_SELINUX_HIDE

void ksu_selinux_hide_init();
void ksu_selinux_hide_exit();

static int sepol_expected_argc(u32 cmd);

// flex array
struct ksu_hide_buf {
	size_t len;
	char data[];
} __attribute__((aligned(sizeof(size_t))));

// types
// :type1:\0:type2:\0:type3:\0
static struct ksu_hide_buf *ksu_hide_type_list __read_mostly = nullptr;

// rules
// :src1:\0:tgt1:\0:src2:\0:tgt2:\0:src3:\0:tgt3:\0
static struct ksu_hide_buf *ksu_hide_rule_list __read_mostly = nullptr;

static DEFINE_MUTEX(selinux_hide_list_mutex);

static struct ksu_hide_buf *__percpu *ksu_selinux_hide_hazptr_slot __read_mostly = nullptr;

static inline void ksu_selinux_hide_alloc_hazptr_slot(void)
{
	ksu_selinux_hide_hazptr_slot = alloc_percpu(struct ksu_hide_buf *);

	// asshole assert nofail.
	if (!ksu_selinux_hide_hazptr_slot) {
		__builtin_trap();
		__builtin_unreachable();
	}

	unsigned int cpu;
	for_each_possible_cpu(cpu) {
		struct ksu_hide_buf **slot = per_cpu_ptr(ksu_selinux_hide_hazptr_slot, cpu);
		pr_info("selinux_hide: hazptr_slot: 0x%lx cpu: %u \n", (uintptr_t)slot, cpu );
	}
}

// NOTE: can ret null on uninitialized state
static inline struct ksu_hide_buf *ksu_selinux_hide_get_buf(struct ksu_hide_buf **g_buf)
{
	// reader has to pin its own slot
	preempt_disable();
	struct ksu_hide_buf **slot = this_cpu_ptr(ksu_selinux_hide_hazptr_slot);
	struct ksu_hide_buf *buf;

check_buf:
	buf = __atomic_load_n(g_buf, __ATOMIC_ACQUIRE);
	__atomic_store_n(slot, buf, __ATOMIC_RELEASE);

	if (buf != __atomic_load_n(g_buf, __ATOMIC_ACQUIRE))
		goto check_buf;

	return buf;
}

static inline void ksu_selinux_hide_put_buf(struct ksu_hide_buf **unused)
{
	struct ksu_hide_buf **slot = this_cpu_ptr(ksu_selinux_hide_hazptr_slot);
	__atomic_store_n(slot, NULL, __ATOMIC_RELEASE);
	
	preempt_enable();
}

static inline void ksu_selinux_hide_hazptr_free(struct ksu_hide_buf *old_ptr)
{
	if (!old_ptr)
		return;

	// acquire it on ALL cpus!
	// only free it once ALL slots say that their slot no longer contains old ptr
	unsigned int cpu;
	for_each_possible_cpu(cpu) {
		struct ksu_hide_buf **slot = per_cpu_ptr(ksu_selinux_hide_hazptr_slot, cpu);
		while (__atomic_load_n(slot, __ATOMIC_ACQUIRE) == old_ptr)
			cpu_relax();
	}

	kfree(old_ptr);
}

static noinline void ksu_add_shit_to_list(u32 cmd, const char *args[])
{
	if (!args || !args[0])
		return;

	guarded_mutex_lock(&selinux_hide_list_mutex);

	int argc = sepol_expected_argc(cmd);

	if (cmd == KSU_SEPOLICY_CMD_TYPE || cmd == KSU_SEPOLICY_CMD_TYPE_ATTR || cmd == KSU_SEPOLICY_CMD_TYPE_STATE || cmd == KSU_SEPOLICY_CMD_ATTR) {
		
		const char *name = args[0];
		size_t needed_len = strlen(name) + 3; // :type:\0

		if (!ksu_hide_type_list)
			goto skip_type_dup_check;

		// anti duplicate
		size_t offset = 0;
		while (ksu_hide_type_list->len > offset) {
			const char *current_type = ksu_hide_type_list->data + offset;

			char tmp_buf[64];
			snprintf(tmp_buf, sizeof(tmp_buf), ":%s:", name);

			if (!strcmp(current_type, tmp_buf))
				return;

			offset = offset + strlen(current_type) + 1;
		}

	skip_type_dup_check:;
		size_t old_len = (ksu_hide_type_list) ? ksu_hide_type_list->len : 0;
		size_t new_total_len = old_len + needed_len;

		struct ksu_hide_buf *new_ptr = kmalloc(sizeof(*new_ptr) + new_total_len, GFP_KERNEL | __GFP_NOFAIL);
		new_ptr->len = new_total_len;

		if (ksu_hide_type_list && old_len > 0)
			memcpy(new_ptr->data, ksu_hide_type_list->data, old_len);

		char *w_ptr = new_ptr->data + old_len;
		sprintf(w_ptr, ":%s:", name);

		struct ksu_hide_buf *old_ptr = __atomic_exchange_n(&ksu_hide_type_list, new_ptr, __ATOMIC_ACQ_REL);
		ksu_selinux_hide_hazptr_free(old_ptr);

		pr_info("selinux_hide: tracking type: %s\n", w_ptr);


	} else if (argc >= 2) {

		if (!args[1])
			return;

		const char *src = args[0];
		const char *tgt = args[1];

		size_t src_needed = strlen(src) + 3; // :src:\0
		size_t tgt_needed = strlen(tgt) + 3; // :tgt:\0
		size_t needed_len = src_needed + tgt_needed;

		if (!ksu_hide_rule_list)
			goto skip_rule_dup_check;

		// anti duplicate
		size_t offset = 0;
		while (ksu_hide_rule_list->len > offset) {
			const char *src_chk = ksu_hide_rule_list->data + offset;
			size_t src_sz = strlen(src_chk) + 1; // for \0

			const char *tgt_chk = src_chk + src_sz;
			size_t tgt_sz = strlen(tgt_chk) + 1; // for \0

			char src_buf[64], tgt_buf[64];
			snprintf(src_buf, sizeof(src_buf), ":%s:", src);
			snprintf(tgt_buf, sizeof(tgt_buf), ":%s:", tgt);

			if (!strcmp(src_chk, src_buf) && !strcmp(tgt_chk, tgt_buf))
				return;

			offset = offset + src_sz + tgt_sz;
		}

	skip_rule_dup_check:;
		size_t old_len = (ksu_hide_rule_list) ? ksu_hide_rule_list->len : 0;
		size_t new_total_len = old_len + needed_len;

		struct ksu_hide_buf *new_ptr = kmalloc(sizeof(*new_ptr) + new_total_len, GFP_KERNEL | __GFP_NOFAIL);
		new_ptr->len = new_total_len;

		if (ksu_hide_rule_list && old_len > 0)
			memcpy(new_ptr->data, ksu_hide_rule_list->data, old_len);

		char *w_ptr_src = new_ptr->data + old_len;
		sprintf(w_ptr_src, ":%s:", src);

		char *w_ptr_tgt = w_ptr_src + strlen(w_ptr_src) + 1;
		sprintf(w_ptr_tgt, ":%s:", tgt);

		struct ksu_hide_buf *old_ptr = __atomic_exchange_n(&ksu_hide_rule_list, new_ptr, __ATOMIC_ACQ_REL);
		ksu_selinux_hide_hazptr_free(old_ptr);

		pr_info("selinux_hide: tracking rule: %s %s\n", w_ptr_src, w_ptr_tgt);

	}

	return;
}

static bool ksu_should_destroy_context(char *str)
{
	if (!str)
		return false;

{ // scope++
	struct ksu_hide_buf *type_buf __cleanup(ksu_selinux_hide_put_buf) = ksu_selinux_hide_get_buf(&ksu_hide_type_list);
	if (unlikely(!type_buf))
		goto check_rule;

	size_t offset = 0;
	while (type_buf->len > offset) {
		const char *current_entry = type_buf->data + offset;

		if (strstr(str, current_entry))
			return true;

		offset = offset + strlen(current_entry) + 1;
	}
} // scope--

check_rule:; // double strstr
	const char *str2 = strnchr(str, 128, ' ');
	if (!str2)
		return false;

{ // scope++
	struct ksu_hide_buf *rule_buf __cleanup(ksu_selinux_hide_put_buf) = ksu_selinux_hide_get_buf(&ksu_hide_rule_list);
	if (unlikely(!rule_buf))
		return false;
	
	size_t offset = 0;
	while (rule_buf->len > offset) {
		const char *src_rule = rule_buf->data + offset;
		size_t src_sz = strlen(src_rule) + 1;

		const char *tgt_rule = src_rule + src_sz;
		size_t tgt_sz = strlen(tgt_rule) + 1;

		if (strnstr(str, src_rule, str2 - str) && strstr(str2, tgt_rule))
			return true;

		offset = offset + src_sz + tgt_sz;
	}
} // scope--
	return false;
}

#endif
