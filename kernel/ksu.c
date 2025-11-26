#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <generated/utsrelease.h>
#include <generated/compile.h>
#include <linux/version.h> /* LINUX_VERSION_CODE, KERNEL_VERSION macros */

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif

#include "allowlist.h"
#include "ksu.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "throne_tracker.h"
#ifndef CONFIG_KSU_SUSFS
#include "syscall_hook_manager.h"
#endif
#include "ksud.h"
#include "supercalls.h"

#include "sulog.h"
#include "throne_comm.h"
#include "dynamic_manager.h"

static struct workqueue_struct *ksu_workqueue;

bool ksu_queue_work(struct work_struct *work)
{
	return queue_work(ksu_workqueue, work);
}

void sukisu_custom_config_init(void)
{
}

void sukisu_custom_config_exit(void)
{
	ksu_uid_exit();
	ksu_throne_comm_exit();
	ksu_dynamic_manager_exit();
#if __SULOG_GATE
	ksu_sulog_exit();
#endif
}

int __init kernelsu_init(void)
{
	pr_info("Initialized on: %s (%s) with driver version: %u\n",
		UTS_RELEASE, UTS_MACHINE, KSU_VERSION);
		
#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**	 NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE	**");
	pr_alert("**														 **");
	pr_alert("**		 You are running KernelSU in DEBUG mode		  **");
	pr_alert("**														 **");
	pr_alert("**	 NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE	**");
	pr_alert("*************************************************************");
#endif

	ksu_feature_init();

	ksu_lsm_hook_init();

	ksu_supercalls_init();

	sukisu_custom_config_init();

	ksu_syscall_hook_manager_init();

	ksu_workqueue = alloc_ordered_workqueue("kernelsu_work_queue", 0);

	ksu_allowlist_init();

	ksu_throne_tracker_init();

#ifdef CONFIG_KSU_SUSFS
	susfs_init();
#endif

#if defined(CONFIG_KPROBES) && !defined(CONFIG_KSU_SUSFS)
	ksu_ksud_init();
#endif

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
	return 0;
}

extern void ksu_observer_exit(void);
void kernelsu_exit(void)
{
	ksu_allowlist_exit();

	ksu_observer_exit();

	ksu_throne_tracker_exit();

	destroy_workqueue(ksu_workqueue);

#if defined(CONFIG_KPROBES) && !defined(CONFIG_KSU_SUSFS)
	ksu_ksud_exit();
#endif

	ksu_syscall_hook_manager_exit();

	sukisu_custom_config_exit();

	ksu_supercalls_exit();
	
	ksu_feature_exit();
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
#endif