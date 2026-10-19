#ifdef MODULE
#ifndef CONFIG_ARM64
#error "LKM is only supported on ARM64!"
#endif

// for OOT builds like on ddk, just enable everything
#ifndef CONFIG_KSU_HEURISTIC_IN_TREE_BUILD
	#define CONFIG_KSU_LSM_SECURITY_HOOKS 1
	#define CONFIG_KSU_HACK_ARM64_BRANCH_LINK 1
	#define CONFIG_KSU_FEATURE_SULOG 1
	#define CONFIG_KSU_FEATURE_ADBROOT 1
	#define CONFIG_KSU_THRONE_TRACKER_ALWAYS_THREADED 1
#endif // CONFIG_KSU_HEURISTIC_IN_TREE_BUILD

// for in-tree, this has to be detected
#ifndef CONFIG_KALLSYMS_ALL
#error "LKM requires KALLSYMS_ALL!"
#endif
#endif // MODULE

#include "kernel_includes.h"

// selinux includes
#include "avc_ss.h"
#include "objsec.h"
#include "ss/services.h"
#include "ss/symtab.h"
#include "xfrm.h"
#ifndef KSU_COMPAT_USE_SELINUX_STATE
#include "avc.h"
#endif

// uapi
#include "include/uapi/app_profile.h"
#include "include/uapi/feature.h"
#include "include/uapi/selinux.h"
#include "include/uapi/supercall.h"
#include "include/uapi/sulog.h"
#include "include/uapi/manager.h"
#include "include/uapi/extension.h"

// includes
#include "include/arch.h"
#include "include/klog.h"
#include "include/ksu.h"

// kernel compat
#include "kernel_compat.h"
#include "include/util.h"

#include "policy/app_profile.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"
#include "supercall/internal.h"
#include "supercall/supercall.h"
#include "infra/su_mount_ns.h"
#include "infra/file_wrapper.h"
#include "infra/event_queue.h"
#include "feature/adb_root.h"
#include "feature/kernel_umount.h"
#include "feature/selinux_hide.h"
#include "feature/shell_su_adb_only.h"
#include "feature/sucompat.h"
#include "feature/sulog.h"
#include "feature/mount_hide.h"
#include "runtime/ksud_boot.h"
#include "runtime/ksud.h"
#include "sulog/event.h"
#include "sulog/fd.h"

#include "selinux/selinux.h"
#include "selinux/sepolicy.h"

#ifdef CONFIG_KSU_DISABLE_32BIT_HOOKS
#undef CONFIG_COMPAT
#endif

#ifdef CONFIG_KPROBES
#include "downstream/kprobes_common.h"
#endif

#ifdef CONFIG_KALLSYMS
#include "external/chibihash64.h"
#include "downstream/kallsyms_common.h"
#else
#define find_kernel_symbol_exact(...) ({ 0x0; })
#define ksu_lookup_kernel_symbols(...) ({ -ENOSYS; })
#endif

#ifdef CONFIG_ARM64
#include "downstream/arm64_branch_insn.h"
#endif

#include "downstream/slow_avc_audit_defs.h"
#include "downstream/tiny_sulog.h"
#include "downstream/toolkit.h"
#include "downstream/vmap_patch.h"

#ifdef CONFIG_KSU_HOSTSREDIRECT
#include "downstream/ksu_hostsredirect.h"
#endif

#include "extension/extension.h"
#include "extension/cpu_spoof.h"
#include "extension/umount_paths.h"
#include "extension/dynamic_manager.h"
#include "extension/kpm.h"
#include "extension/kpm/kpm.h"
#include "extension/kpm/compact.h"
#include "extension/kpm/super_access.h"

// unity build
#include "extension/extension.c"
#include "extension/cpu_spoof.c"
#include "extension/umount_paths.c"
#include "extension/dynamic_manager.c"
#include "extension/kpm.c"
#include "extension/kpm/kpm.c"
#include "extension/kpm/compact.c"
#include "extension/kpm/super_access.c"

#include "policy/allowlist.c"
#include "policy/app_profile.c"
#include "policy/feature.c"
#include "manager/apk_sign.c"
#include "manager/pkg_observer.c"
#include "manager/throne_tracker.c"

#include "supercall/perm.c"
#include "supercall/dispatch.c"
#include "supercall/supercall.c"

#include "infra/su_mount_ns.c"
#include "infra/file_wrapper.c"
#include "infra/event_queue.c"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0) && defined(CONFIG_KALLSYMS_ALL) && defined(CONFIG_MODULES)
#define KSU_CAN_USE_MODULE_BLACKLIST
#include "feature/module_blacklist.h"
#include "feature/module_blacklist.c"
#endif

#include "feature/adb_root.c"
#include "feature/kernel_umount.c"
#include "feature/selinux_hide.c"
#include "feature/shell_su_adb_only.c"
#include "feature/sucompat.c"
#include "feature/sulog.c"
#include "feature/mount_hide.c"
#include "runtime/boot_event.c"
#include "runtime/ksud_integration.c"

#include "sulog/event.c"
#include "sulog/fd.c"

#include "hook/setuid_hook.c"

#ifdef CONFIG_KSU_LSM_SECURITY_HOOKS
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
	#include "hook/lsm_hooks_static.c"
	#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	#include "hook/lsm_hooks_list.c"
	#else
	#include "hook/lsm_hooks_ultralegacy.c"
	#endif
#else
	#include "hook/lsm_hooks_manual.c"
#endif

#include "selinux/selinux.c"
#include "selinux/sepolicy.c"
#include "selinux/rules.c"

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
#ifdef CONFIG_ARM64
	#include "hook/syscall_table_hook_arm64.c"
#elif defined(CONFIG_ARM)
	#include "hook/syscall_table_hook_arm.c"
#endif
#endif /* CONFIG_KSU_TAMPER_SYSCALL_TABLE */

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
#undef syscall_table_sucompat_enable
#undef syscall_table_sucompat_disable
#include "hook/syscall_table_hook_arm64.c" // included as fallback
#include "hook/branch_link_hook_arm64.c"
#endif

#if defined(CONFIG_KSU_KPROBES_KSUD) && !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
#include "hook/kp_ksud.c"
#endif

// track backports and other quirks here
// ref: kernel_compat.c, Makefile
// yes looks nasty
#if defined(CONFIG_KSU_DEBUG)
	#define FEAT_1 " +debug"
#else
	#define FEAT_1 ""
#endif
#if defined(CONFIG_KSU_KPROBES_KSUD) && !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
	#define FEAT_2 " +kp_ksud"
#else
	#define FEAT_2 ""
#endif
#if defined(CONFIG_KSU_EXTRAS)
	#define FEAT_3 " +extras"
#else
	#define FEAT_3 ""
#endif
#if defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
	#define FEAT_4 " +syscall_table_hook"
#else
	#define FEAT_4 ""
#endif
#if !defined(CONFIG_KSU_LSM_SECURITY_HOOKS)
	#define FEAT_5 " -lsm_hooks"
#else
	#define FEAT_5 ""
#endif
#if defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
	#define FEAT_6 " +arm64_branch_link"
#else
	#define FEAT_6 ""
#endif
#if defined(KSU_COMPAT_HAS_EXPORTED_POLICY_RWLOCK)
	#define FEAT_7 " +policy_rwlock"
#else
	#define FEAT_7 ""
#endif
#if defined(MODULE)
	#define FEAT_8 " +lkm"
#else
	#define FEAT_8 ""
#endif

#define EXTRA_FEATURES FEAT_1 FEAT_2 FEAT_3 FEAT_4 FEAT_5 FEAT_6 FEAT_7 FEAT_8

static inline void ksu_print_build_info(void)
{
	pr_info("welcome to KernelSU version " __stringify(KERNEL_SU_VERSION) ", package name " KSU_PACKAGE_NAME "\n");
	pr_info("Initialized on: %s (%s)%s\n", UTS_RELEASE, UTS_MACHINE, EXTRA_FEATURES);

#if defined(__VERSION__) && defined(__STDC_VERSION__)
#if defined(__clang_version__)
	pr_info("Built with: Clang %d.%d.%d w/ stdc: %ld\n", __clang_major__, __clang_minor__, __clang_patchlevel__, __STDC_VERSION__);
#else
	pr_info("Built with: GCC %s w/ stdc: %ld\n", __VERSION__, __STDC_VERSION__);
#endif
#endif

}

static int __init kernelsu_init(void)
{
	ksu_print_build_info();

#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**	 NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE	**");
	pr_alert("**														 **");
	pr_alert("**		 You are running KernelSU in DEBUG mode		  **");
	pr_alert("**														 **");
	pr_alert("**	 NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE	**");
	pr_alert("*************************************************************");
#endif
	if (allow_shell)
		pr_alert("shell is allowed at init!");

	ksu_cred = prepare_creds();
	if (!ksu_cred) {
		pr_err("prepare cred failed!\n");
		return -ENOSYS;
	}

#ifdef KSU_CAN_USE_MODULE_BLACKLIST
	ksu_module_blacklist_init(); // Block modules early, before vendor modules are loaded in second stage.
#endif
	// register features
	ksu_feature_init();
	 ksu_extension_init();
	ksu_extension_register_all();
	ksu_sucompat_init();
	ksu_kernel_umount_init();
	ksu_mount_hide_init();
#ifdef CONFIG_KSU_FEATURE_SULOG	
	ksu_sulog_init();
#endif
#ifdef CONFIG_KSU_FEATURE_ADBROOT
	ksu_adb_root_init();
#endif
	ksu_selinux_hide_init();
	ksu_shell_su_adb_only_init();

	ksu_core_init();
	ksu_supercalls_init();

#if defined(CONFIG_KSU_KPROBES_KSUD) && !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && !defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
	kp_ksud_init();
#endif

	ksu_allowlist_init();
	// dynamic manager must be loaded before throne tracker, as throne tracker may depend on it
	ksu_dynamic_manager_load();
	ksu_throne_tracker_init();
	ksu_ksud_init();
	ksu_file_wrapper_init();

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
	ksu_syscall_table_hook_init();
#endif

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
	ksu_branch_link_patch_init();
#endif

	return 0;
}

#if !defined(MODULE)
device_initcall(kernelsu_init);
#else

#ifndef CONFIG_KSU_SHELL_HAS_SU_ALWAYS
/**
 * as per tiann/KernelSU ca2799c, lkm is allowed to flip this param post-compile.
 * however this is also offerred to be overriden by a kconfig. so if kconfig is
 * enabled, we must compile-out this option.
 *
 */
module_param(allow_shell, bool, 0); 
#endif

static int __init kernelsu_lkm_init(void)
{
	kernelsu_init();

	// list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj); // tiann/KernelSU fefb02e

#if 0
	if (current->pid == 1)
		return 0;

	escape_to_root_forced();

	stop_vfs_read_hook();
	apply_kernelsu_rules();
	cache_sid();
	setup_ksu_cred();
	on_post_fs_data();
	on_boot_completed();
	ksu_feature_apply_forced();
	ksu_extension_apply_forced();

	if (!!getenforce())
		return 0;
	pr_info("Permissive SELinux, enforcing\n");
	setenforce(true);
#endif
	return 0;
}

static void __exit kernelsu_lkm_exit(void)
{
	__builtin_trap();
	__builtin_unreachable();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

module_init(kernelsu_lkm_init);
module_exit(kernelsu_lkm_exit);
#endif // MODULE

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
