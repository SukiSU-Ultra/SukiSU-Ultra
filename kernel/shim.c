#include <linux/version.h>
#include <linux/compat.h>
#include <linux/fs.h>

// unity build idea from backslashxx, not full, we only use it for shim ksu hooks

#include "allowlist.h"
#include "arch.h"
#include "kp_hook.h"
#include "ksu.h"
#include "klog.h" // IWYU pragma: keep
#include "ksud.h"
#include "kernel_compat.h"
#include "kp_util.h"
#include "supercalls.h"
#include "sucompat.h"
#include "setuid_hook.h"
#include "syscall_handler.h"
#include "selinux/selinux.h"
#include "throne_tracker.h"

#include "lsm_hook.c"

#ifdef CONFIG_KSU_SYSCALL_HOOK
#include "kp_hook.c"
#include "kp_util.c"
#include "syscall_handler.c"
#endif

#if defined(CONFIG_KSU_SYSCALL_HOOK) || defined(CONFIG_KSU_SUSFS) ||           \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0) &&                      \
	 defined(CONFIG_KSU_MANUAL_HOOK))
// + ksu_handle_setresuid hook for 6.8+
#include "pkg_observer.c"
#endif
