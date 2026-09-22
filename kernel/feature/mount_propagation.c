// SPDX-License-Identifier: GPL-2.0
/**
 * @file mount_propagation.c
 * @brief KernelSU hook to dynamically pause shared mount propagation during boot.
 *
 * This file implements a feature to temporarily prevent new mounts from
 * inheriting the "shared" property from their destination using a kretprobe.
 *
 * The mechanism uses a kretprobe on the internal VFS function 
 * `attach_recursive_mnt`. An entry handler temporarily clears the MNT_SHARED
 * flag on the destination mount, and then a return handler restores the
 * original flags, ensuring consistency.
 */

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/path.h>

#if __has_include("../../fs/mount.h")
#include "../../fs/mount.h"
#elif __has_include(<../fs/mount.h>)
#include <../fs/mount.h>
#else
struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;
	struct list_head mnt_child;
	struct list_head mnt_instance;
	const char *mnt_devname;
	struct list_head mnt_list;
	struct list_head mnt_expire;
	struct list_head mnt_share;
	struct list_head mnt_slave_list;
	struct list_head mnt_slave;
	struct mount *mnt_master;
	struct mnt_namespace *mnt_ns;
	struct mountpoint *mnt_mp;
	union {
		struct hlist_node mnt_mp_list;
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting;
#ifdef CONFIG_FSNOTIFY
	struct fsnotify_mark_connector __rcu *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;
	int mnt_group_id;
	int mnt_expiry_mark;
	struct hlist_head mnt_pins;
	struct hlist_node mnt_pinned;
	struct vfsmount *mnt_mntpoint;
};
#endif

#include "mount_propagation.h"
#include "arch.h"
#include "klog.h"

// State variable to track if Zygote has been initialized.
static atomic_t ksu_zygote_started = ATOMIC_INIT(0);
// State and storage for the KernelSU modules' device name.
static atomic_t ksu_modules_devname_initialized = ATOMIC_INIT(0);
static char ksu_modules_devname[256];
static bool ksu_mount_propagation_registered = false;

#ifdef CONFIG_KPROBES

/**
 * @brief Private data structure passed from entry to return handler.
 */
struct ksu_attach_mnt_state {
	struct mount *dest_mnt;
	int original_flags;
	bool spoofed;
};

static int ksu_attach_recursive_mnt_entry(struct kretprobe_instance *ri,
					  struct pt_regs *regs)
{
	struct mount *source_mnt = (struct mount *)PT_REGS_PARM1(regs);
	struct mount *dest_mnt = (struct mount *)PT_REGS_PARM2(regs);
	struct ksu_attach_mnt_state *state;

	state = (struct ksu_attach_mnt_state *)ri->data;
	state->spoofed = false;

	// Always validate pointers from hooks before dereferencing.
	if (!source_mnt || !dest_mnt) {
		return 0;
	}

	// --- Step 1: Dynamically capture the modules device name (runs once) ---
	if (atomic_read(&ksu_modules_devname_initialized) == 0 &&
	    source_mnt->mnt_devname &&
	    strncmp(source_mnt->mnt_devname, "/dev/block/loop", 15) == 0) {
		strncpy(ksu_modules_devname, source_mnt->mnt_devname,
			sizeof(ksu_modules_devname) - 1);
		// Ensure null termination.
		ksu_modules_devname[sizeof(ksu_modules_devname) - 1] = '\0';

		atomic_set(&ksu_modules_devname_initialized, 1);
		pr_info("KernelSU modules devname captured: %s\n",
			ksu_modules_devname);
	}

	// --- Step 2: Check conditions for skipping the spoof ---
	// Skip if Zygote has started AND the source device is NOT our modules device.
	if (atomic_read(&ksu_zygote_started) != 0 &&
	    (atomic_read(&ksu_modules_devname_initialized) == 0 ||
	     (source_mnt->mnt_devname &&
	      strcmp(source_mnt->mnt_devname, ksu_modules_devname) != 0))) {
		return 0;
	}

	// We only need to act if the destination is a shared mount.
	if (!(dest_mnt->mnt.mnt_flags & MNT_SHARED)) {
		return 0;
	}

	pr_info("Spoofing shared mount %p to private.\n", dest_mnt);

	// --- The Spoof ---
	state->dest_mnt = dest_mnt;
	state->original_flags = dest_mnt->mnt.mnt_flags;
	state->spoofed = true;
	dest_mnt->mnt.mnt_flags &= ~MNT_SHARED;

	return 0;
}

static int ksu_attach_recursive_mnt_ret(struct kretprobe_instance *ri,
					struct pt_regs *regs)
{
	struct ksu_attach_mnt_state *state =
		(struct ksu_attach_mnt_state *)ri->data;

	if (!state->spoofed) {
		return 0;
	}

	// --- The Restoration ---
	pr_info("Restoring original shared flags to mount %p.\n",
		state->dest_mnt);
	state->dest_mnt->mnt.mnt_flags = state->original_flags;

	return 0;
}

static struct kretprobe attach_recursive_mnt_krp = {
	.handler = ksu_attach_recursive_mnt_ret,
	.entry_handler = ksu_attach_recursive_mnt_entry,
	.data_size = sizeof(struct ksu_attach_mnt_state),
	.maxactive = 64, // Max concurrent probed instances.
	.kp.symbol_name = "attach_recursive_mnt",
};

#endif // CONFIG_KPROBES

void ksu_set_zygote_started(void)
{
	pr_info("Zygote started, mount propagation logic is now active.\n");
	atomic_set(&ksu_zygote_started, 1);
}

int ksu_mount_propagation_init(void)
{
#ifdef CONFIG_KPROBES
	int ret;

	if (ksu_mount_propagation_registered)
		return 0;

	ret = register_kretprobe(&attach_recursive_mnt_krp);
	if (ret < 0) {
		pr_err("mount propagation kretprobe registration failed, returned %d\n", ret);
		return ret;
	}

	ksu_mount_propagation_registered = true;
	pr_info("Mount propagation hook registered successfully.\n");
	return 0;
#else
	pr_info("Mount propagation hook not enabled (CONFIG_KPROBES not set).\n");
	return 0;
#endif
}

void ksu_mount_propagation_exit(void)
{
#ifdef CONFIG_KPROBES
	if (!ksu_mount_propagation_registered)
		return;

	unregister_kretprobe(&attach_recursive_mnt_krp);
	ksu_mount_propagation_registered = false;
	pr_info("Mount propagation hook unregistered.\n");

	if (attach_recursive_mnt_krp.nmissed > 0) {
		pr_warn("Missed %u instances of attach_recursive_mnt probe.\n",
			attach_recursive_mnt_krp.nmissed);
	}
#endif
}
