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

/**
 *  NOTE: this isnt the fullblown thing like upstream's where we straight up backport
 *  SELinux. This is just questionable to do when we want to support a plethora of
 *  non-standard kernels.
 *
 *  While what we are doing here is kinda improper, for most cases this should be
 *  more than enough.
 *
 *  this will hook the ff:
 *	sel_open_handle_status
 *	selinux_transaction_write
 *	selinux_setprocattr
 *	slow_avc_audit (attempt, not available upstream)
 *
 *  our goal for this one is to be self contained as much as possible
 *  with only one call from ksu's initcall.
 *
 */

// enabled by default
static bool ksu_selinux_hide_enabled __read_mostly = true;

// selinux_setprocattr handler
static __always_inline int ksu_hide_setprocattr_inline(const char *name, void *value, size_t size)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		return 0;

	// only hook when seccomp is enabled
	if (!ksu_is_seccomp_enabled())
		return 0;

	// only appuid
	if (current_uid().val < 10000)
		return 0;

	if (!size)
		return 0;

	if (!name)
		return 0;

	constexpr char c[] = "current";
	if (!!memcmp_inline(name, c, sizeof(c)))
		return 0;

	char *str = (char *)value;
	if (!str || !str[0])
		return 0;

	// two cachelines
	char buf[128];
	size_t len = (size < 128) ? size : 127;

	memcpy(buf, str, len);
	buf[len] = '\0';

	if (!ksu_should_destroy_context(buf))
		return 0;
	
	pr_info("selinux_hide: setprocattr: destroy: %s\n", buf);
	str[1] = '1';

	return 0;
}

// selinux_transaction_write hijack
static ssize_t (*selinux_transaction_write_fn)(struct file *file, const char __user *buf, size_t size, loff_t *pos) __read_mostly = nullptr;
static __nocfi ssize_t ksu_selinux_transaction_write(struct file *file, const char __user *buf, size_t size, loff_t *pos)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		goto skip_destroy;

	if (!ksu_is_seccomp_enabled())
		goto skip_destroy;

	if (current_uid().val < 10000)
		goto skip_destroy;

#define SEL_CONTEXT 5
#define SEL_ACCESS 6
	ino_t ino = file_inode(file)->i_ino;
	if (ino != SEL_CONTEXT && ino != SEL_ACCESS)
		goto skip_destroy;

	// two cachelines
	char kbuf[128];
	size_t len = (size < 128) ? size : 127;

	if (copy_from_user_retry(kbuf, buf, len))
		goto skip_destroy;

	kbuf[len] = '\0';
	if (ksu_should_destroy_context(kbuf)) {
		pr_info("selinux_hide: selinux_transaction_write: destroy: %s \n", kbuf);
		buf = (const char __user *)current->mm->start_stack;
	}

	ssize_t ret = selinux_transaction_write_fn(file, buf, size, pos);
	if (!(ret > 0))
		return ret;

	if (ino != SEL_ACCESS)
		return ret;

	// simple_transaction_get()
	struct simple_transaction_argresp *ar = file->private_data;
	if (!ar)
		return ret;

	uint32_t avd_allowed, ff, avd_auditallow, avd_auditdeny, avd_seqno, avd_flags;
	if (sscanf(ar->data, "%x %x %x %x %u %x", &avd_allowed, &ff, &avd_auditallow, &avd_auditdeny, &avd_seqno, &avd_flags) != 6)
		return ret;

	avd_seqno = 1;
	scnprintf(ar->data, SIMPLE_TRANSACTION_LIMIT, "%x %x %x %x %u %x", avd_allowed, ff, avd_auditallow, avd_auditdeny, avd_seqno, avd_flags);

	return ret;

skip_destroy:
	return selinux_transaction_write_fn(file, buf, size, pos);
}

static void ksu_init_hook_transaction_ops_write()
{
	struct path path;
	const char *selinux_context = "/sys/fs/selinux/context";

	int error = kern_path(selinux_context, LOOKUP_FOLLOW, &path);
	if (error) {
		pr_info("selinux_hide: kern_path err: %d\n", error);
		return;
	}

	pr_info("selinux_hide: kern_path %s ok!\n", selinux_context);

	if (!path.dentry)
		goto bail_out;

	if (!d_inode(path.dentry))
		goto bail_out;		

	struct file_operations *fops = (struct file_operations *)d_inode(path.dentry)->i_fop;
	if (!fops)
		goto bail_out;

	if (!fops->write)
		goto bail_out;

	pr_info("selinux_hide: found transaction_ops->write at 0x%lx \n", (uintptr_t)fops->write);
	selinux_transaction_write_fn = fops->write;

	int ret = ksu_write_to_readonly_slot((uintptr_t)&fops->write, (uintptr_t)ksu_selinux_transaction_write);
	pr_info("selinux_hide: transaction_ops->write hijack ret: %d\n", ret);

bail_out:
	path_put(&path);
}

// sel_open_handle_status hijack
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0) && defined(KSU_COMPAT_HAS_SELINUX_STATE)
extern struct selinux_state selinux_state;
#define ksu_selinux_kernel_status_page() selinux_kernel_status_page(&selinux_state)
#else
#define ksu_selinux_kernel_status_page() selinux_kernel_status_page()
#endif

static struct page *ksu_fake_status_page __read_mostly = nullptr;
static int ksu_prepare_fake_status_page()
{
	struct page *real_page = ksu_selinux_kernel_status_page();
	if (!real_page)
		return -ENOMEM;

	// this is the page we present
	struct page *new_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!new_page)
		return -ENOMEM;

	// we will leak one page but thats fine
	// not a leak when it is used forever :)
	struct selinux_kernel_status *real_status = page_address(real_page);
	struct selinux_kernel_status *fake_status = page_address(new_page);
    
	memcpy(fake_status, real_status, sizeof(*real_status));

	fake_status->enforcing = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	fake_status->sequence = 4;
	fake_status->policyload = 1;
#else
	fake_status->sequence = 0;
	fake_status->policyload = 0;
#endif

	ksu_fake_status_page = new_page;
    
	pr_info("selinux_hide: ksu_fake_status_page ready! seq=%d\n", fake_status->sequence);
            
	return 0;
}

static int (*sel_open_handle_status_fn)(struct inode *inode, struct file *filp) __read_mostly = nullptr;
static __nocfi int ksu_sel_open_handle_status(struct inode *inode, struct file *filp)
{
	if (unlikely(!ksu_selinux_hide_enabled))
		goto orig_page;

	if (!ksu_is_seccomp_enabled())
		goto orig_page;

	if (current_uid().val < 10000)
		goto orig_page;

	assume(!!ksu_fake_status_page);
	if (unlikely(!ksu_fake_status_page))
		goto orig_page;

	filp->private_data = ksu_fake_status_page;

	pr_info("selinux_hide: sel_open_handle_status: served fake_page\n");
	return 0;

orig_page:
	return sel_open_handle_status_fn(inode, filp);
}

static void ksu_init_hook_sel_handle_status_ops_open()
{
	struct path path;
	const char *selinux_status = "/sys/fs/selinux/status";

	int error = kern_path(selinux_status, LOOKUP_FOLLOW, &path);
	if (error) {
		pr_info("selinux_hide: kern_path err: %d\n", error);
		return;
	}
	
	pr_info("selinux_hide: kern_path %s ok!\n", selinux_status);

	if (!path.dentry)
		goto bail_out;

	if (!d_inode(path.dentry))
		goto bail_out;	

	struct file_operations *fops = (struct file_operations *)d_inode(path.dentry)->i_fop;
	if (!fops)
		goto bail_out;

	if (!fops->open)
		goto bail_out;

	pr_info("selinux_hide: found sel_handle_status_ops->open at 0x%lx\n", (uintptr_t)fops->open);

	sel_open_handle_status_fn = fops->open;

	int ret = ksu_write_to_readonly_slot((uintptr_t)&fops->open, (uintptr_t)ksu_sel_open_handle_status);
	pr_info("selinux_hide: sel_handle_status_ops->open hijack ret: %d\n", ret);

bail_out:
	path_put(&path);
}

// init kthread
static int ksu_selinux_hide_init_thread(void *data)
{
	set_user_nice(current, 19); // low prio

wait_start:
	// in input hook got turned off means we have ksud!
	if (!*(volatile bool *)&ksu_input_hook)
		goto init_hooks;

	msleep(5000);

	goto wait_start;

init_hooks:; // apply_kernelsu_rules_fn
	const char *ksu_domain_args[] = { KERNEL_SU_DOMAIN, NULL };
	ksu_add_shit_to_list(KSU_SEPOLICY_CMD_TYPE, ksu_domain_args);

	const char *ksu_file_args[] = { KERNEL_SU_FILE, NULL };
	ksu_add_shit_to_list(KSU_SEPOLICY_CMD_TYPE, ksu_file_args);

	const char *init_adb_args[] = { "init", "adb_data_file", NULL };
	ksu_add_shit_to_list(KSU_SEPOLICY_CMD_NORMAL_PERM, init_adb_args);

	// we move this to a module instead
	// const char *adbroot_args[] = { "adbroot", NULL };
	// ksu_add_shit_to_list(KSU_SEPOLICY_CMD_TYPE, adbroot_args);

	int tries = 0;
try_again:
	if (!ksu_prepare_fake_status_page())
		goto page_ok;
		
	msleep(1000);
	tries = tries + 1;
	if (tries > 10)
		return 0;

	goto try_again;

page_ok:
	ksu_init_hook_sel_handle_status_ops_open();
	ksu_init_hook_transaction_ops_write();

	// selinux_setprocattr hook init is on lsm.
	
	// downstream/slow_avc_audit_defs.h
	ksu_init_slow_avc_audit_hook();

	return 0;
}

static int selinux_hide_feature_get(u64 *value)
{
	*value = ksu_selinux_hide_enabled ? 1 : 0;
	return 0;
}

static int selinux_hide_feature_set(u64 value)
{
	bool enable = value != 0;
	int ret = 0;

	if (enable == ksu_selinux_hide_enabled)
		return 0;

	pr_info("selinux_hide: set to %d\n", enable);

	if (enable)
		ksu_selinux_hide_enabled = true;
	else
		ksu_selinux_hide_enabled = false;

	return ret;
}

static const struct ksu_feature_handler selinux_hide_handler = {
	.feature_id = KSU_FEATURE_SELINUX_HIDE,
	.name = "selinux_hide",
	.get_handler = selinux_hide_feature_get,
	.set_handler = selinux_hide_feature_set,
};

void __init ksu_selinux_hide_init()
{
	ksu_selinux_hide_alloc_hazptr_slot();

	// we init this on a kthread
	kthread_run(ksu_selinux_hide_init_thread, NULL, "kthread");

	if (ksu_register_feature_handler(&selinux_hide_handler)) {
		pr_err("Failed to register selinux_hide feature handler\n");
	}
}

void __exit ksu_selinux_hide_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);
}

