// SPDX-License-Identifier: GPL-2.0
/*
 * Manager-Auth: 第三方管理器签名降级支持。
 *
 * 问题：第三方管理器包名可能不匹配 KSU_PACKAGE_NAME，需要通过签名验证。
 *
 * 两个 Hook 函数：
 *   1. maybe_manager_apk_dir - 目录路径验证
 *   2. is_manager_apk        - APK 文件验证
 *
 * 两层验证（按优先级）：
 *   L1: 内置签名（不限包名）
 *   L2: dynamic_manager 表（包名 + 签名同时匹配）
 *
 * 扫描和包名匹配逻辑由 throne_tracker.c 提供。
 */

#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <linux/module.h>
#include <linux/kstrtox.h>

#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "uapi/manager.h"
#include "infra/symbol_resolver.h"
#include "hook/patch_memory.h"
#include "util.h"
#include "manager_auth_patch.h"
#include "dynamic_manager.h"

extern struct ksu_manager_entry dynamic_managers[];
extern __u32 dynamic_manager_count;
extern rwlock_t dynamic_manager_lock;
extern int get_pkg_from_apk_dir_path(char *pkg, const char *path);
extern bool ksu_check_apk_signature(const char *path, unsigned int size, const char *hash);
extern bool maybe_manager_apk_dir(const char *path);
extern bool is_manager_apk(char *path);

_Static_assert(sizeof(bool) == 1,
	       "hot-patch: bool must be 1 byte to round-trip via x0");
_Static_assert(sizeof(char *) == sizeof(void *),
	       "hot-patch: pointer width must match target architecture");

#define MA_MAX_REENTRANCY 1
static DEFINE_PER_CPU(int, ma_handler_depth);

#define MA_RECURSED() (this_cpu_read(ma_handler_depth) > MA_MAX_REENTRANCY)

static bool __must_check ma_enter_handler(void)
{
	int cur = this_cpu_read(ma_handler_depth) + 1;

	if (WARN_ONCE(cur > MA_MAX_REENTRANCY || MA_RECURSED(),
		      "Manager-Auth: handler re-entered (depth=%d); "
		      "check call graph from patched functions\n",
		      cur))
		return false;
	this_cpu_write(ma_handler_depth, cur);
	return true;
}

static void ma_exit_handler(void)
{
	int cur = this_cpu_read(ma_handler_depth);
	WARN_ONCE(cur <= 0,
		  "Manager-Auth: ma_exit_handler called without matching enter (depth=%d)\n",
		  cur);
	this_cpu_write(ma_handler_depth, cur - 1);
}

#define MA_HANDLER_BEGIN()                         \
	do {                                       \
		if (unlikely(!ma_enter_handler())) \
			return false;              \
	} while (0)

#define MA_HANDLER_END()               \
	do {                           \
		ma_exit_handler();     \
	} while (0)

#define MAX_MANAGER_AUTH_PATCHES 2

struct auth_patch_entry {
	const char *target_name;
	void *target_func;
	void *handler;
	void *trampoline;
	void *original_backup;
	size_t backup_size;
	bool installed;
};

static struct auth_patch_entry auth_auth_patch_table[MAX_MANAGER_AUTH_PATCHES];
static int auth_auth_patch_count;

static DEFINE_MUTEX(manager_auth_lock);
static bool manager_auth_enabled;

/*
 * Layer 1: Built-in signature check (third-party manager with same signature)
 */
static bool built_in_manager_signature_matches(const char *path)
{
	return ksu_check_apk_signature(path, EXPECTED_SIZE, EXPECTED_HASH);
}

/*
 * Layer 2: dynamic_manager table (package name + signature)
 */
static bool resolve_pkg_for_dynamic_lookup(const char *path, char *pkg)
{
	memset(pkg, 0, KSU_MAX_PACKAGE_NAME);

	if (get_pkg_from_apk_dir_path(pkg, path) < 0)
		return false;
	pkg[KSU_MAX_PACKAGE_NAME - 1] = '\0';
	return true;
}

static bool dynamic_manager_entry_matches(const char *path, const char *pkg,
					  const struct ksu_manager_entry *e)
{
	_Static_assert(sizeof(e->package) <= KSU_MAX_PACKAGE_NAME,
		       "dynamic_manager_entry_matches package buffer too small");
	if (memchr(e->package, '\0', sizeof(e->package)) == NULL) {
		pr_warn_once("Manager-Auth: dynamic_manager entry has unterminated package name\n");
		return false;
	}
	if (strncmp(e->package, pkg, sizeof(e->package)) != 0)
		return false;
	return ksu_check_apk_signature(path, e->cert_size, e->hash);
}

static bool dynamic_manager_table_matches_locked(const char *path, const char *pkg)
{
	unsigned i;
	__u32 n;

	if (!ksu_manager_enabled())
		return false;

	n = READ_ONCE(dynamic_manager_count);
	if (n > KSU_MAX_DYNAMIC_MANAGERS) {
		pr_warn_once("Manager-Auth: dynamic_manager_count=%u exceeds array size %u\n",
			     (unsigned)n,
			     (unsigned)KSU_MAX_DYNAMIC_MANAGERS);
		return false;
	}

	for (i = 0; i < n; ++i) {
		const struct ksu_manager_entry *e = &dynamic_managers[i];
		if (dynamic_manager_entry_matches(path, pkg, e)) {
			pr_info("Manager-Auth: dynamic_manager[%u] matched %s\n", i, path);
			return true;
		}
	}
	return false;
}

/*
 * Handler for is_manager_apk()
 * Checks: L1 (built-in sig) -> L2 (dynamic_manager table)
 */
static bool ma_is_manager_apk_handler(char *path)
{
	char pkg[KSU_MAX_PACKAGE_NAME];
	bool matched;

	MA_HANDLER_BEGIN();

	/* Layer 1: built-in signature */
	if (built_in_manager_signature_matches(path)) {
		MA_HANDLER_END();
		return true;
	}

	/* Layer 2: dynamic_manager table */
	if (resolve_pkg_for_dynamic_lookup(path, pkg)) {
		read_lock(&dynamic_manager_lock);
		matched = dynamic_manager_table_matches_locked(path, pkg);
		read_unlock(&dynamic_manager_lock);
		if (matched) {
			MA_HANDLER_END();
			return true;
		}
	}

	MA_HANDLER_END();
	return false;
}

/*
 * Handler for maybe_manager_apk_dir()
 * Checks: L2 (dynamic_manager table) only
 */
static bool ma_maybe_manager_apk_dir_handler(const char *path)
{
	char pkg[KSU_MAX_PACKAGE_NAME];
	bool matched;

	MA_HANDLER_BEGIN();

	/* Layer 2: dynamic_manager table */
	if (!resolve_pkg_for_dynamic_lookup(path, pkg)) {
		MA_HANDLER_END();
		return false;
	}

	read_lock(&dynamic_manager_lock);
	matched = dynamic_manager_table_matches_locked(path, pkg);
	read_unlock(&dynamic_manager_lock);

	MA_HANDLER_END();
	return matched;
}

#define TRAMPOLINE_SIZE 64
#define MA_MAX_BACKUP_SIZE 64

static void *alloc_trampoline(void)
{
	void *mem;

	/*
	 * Allocate from the kernel linear (direct-mapped) region via
	 * __get_free_pages.  The linear region is guaranteed to be within
	 * ±4 GiB of kernel text on any 48-bit or 52-bit VA arm64 kernel,
	 * so both ADRP (±4 GiB) and LDR literal (±1 MiB) can always reach
	 * any text address from here.
	 */
	mem = (void *)(uintptr_t)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						   get_order(TRAMPOLINE_SIZE));
	if (!mem)
		return NULL;

	return mem;
}

static void free_trampoline(void *mem)
{
	if (!mem)
		return;
	free_pages((unsigned long)mem, get_order(TRAMPOLINE_SIZE));
}

static inline void ma_ipi_noop(void *unused)
{
	(void)unused;
}

static void dispose_trampoline(void *mem)
{
	on_each_cpu(ma_ipi_noop, NULL, 1);
	synchronize_rcu();
#ifdef CONFIG_TASKS_RCU
	synchronize_rcu_tasks();
#endif
	free_trampoline(mem);
}

static bool target_in_kernel_text(void *addr)
{
	if (!addr)
		return false;
#if defined(CONFIG_KALLSYMS) || defined(CONFIG_KALLSYMS_ALL)
	return __kernel_text_address((unsigned long)addr);
#else
	pr_warn_once("Manager-Auth: CONFIG_KALLSYMS disabled, refusing to install\n");
	return false;
#endif
}

static int validate_target_prologue(void *target)
{
	if ((uintptr_t)target & 3) {
		pr_warn("Manager-Auth: arm64 target %pS not 4-byte aligned\n",
			target);
		return -EINVAL;
	}
	return 0;
}

#if defined(CONFIG_ARM64)

#define MA_NOP 0xd503201f

/*
 * arm64 trampoline that has no range limitation relative to the handler.
 * Uses MOVZ/MOVK sequence to materialize the 64-bit handler address.
 */
static int arm64_build_trampoline(void *trampoline, void *handler)
{
	u32 *code = (u32 *)trampoline;
	uintptr_t h = (uintptr_t)handler;
	int i;

#define MOVZ(r, imm, hw_)                                                                \
	(0xD2800000U | (((imm) & 0xFFFFU) << 5) | ((unsigned)(hw_) << 21) | (unsigned)(r))
#define MOVK(r, imm, hw_)                                                                \
	(0xF2800000U | (((imm) & 0xFFFFU) << 5) | ((unsigned)(hw_) << 21) | (unsigned)(r))
#define BR(r)    (0xD61F0200U | ((unsigned)(r) << 5))

	code[0] = MOVZ(16, (h >> 0) & 0xFFFF, 0);
	code[1] = MOVK(16, (h >> 16) & 0xFFFF, 1);
	code[2] = MOVK(16, (h >> 32) & 0xFFFF, 2);
	code[3] = MOVK(16, (h >> 48) & 0xFFFF, 3);
	code[4] = BR(16);

	code[5] = 0xa9bf7bfdU;                                      /* STP X29,X30,[SP,#-16]! */
	code[6] = 0xa8c17bfdU;                                      /* LDP X29,X30,[SP],#16   */
	code[7] = 0xd65f03c0U;                                      /* RET                    */

	for (i = 8; i < TRAMPOLINE_SIZE / 4; i++)
		code[i] = MA_NOP;

	return ksu_patch_text(trampoline, code, TRAMPOLINE_SIZE,
			      KSU_PATCH_TEXT_FLUSH_ICACHE);
}

static int arm64_install(struct auth_patch_entry *entry)
{
	u32 patch[20 / sizeof(u32)];
	int ret;
	size_t bs = entry->backup_size;

	if (bs < 12)
		return -EINVAL;

	entry->trampoline = alloc_trampoline();
	if (!entry->trampoline)
		return -ENOMEM;

	ret = arm64_build_trampoline(entry->trampoline, entry->handler);
	if (ret != 0) {
		pr_warn("Manager-Auth: arm64_build_trampoline failed: %d\n", ret);
		free_trampoline(entry->trampoline);
		entry->trampoline = NULL;
		return ret;
	}

	/*
	 * Site patch: replace the first N bytes of target_func with a jump to
	 * the trampoline.  Use MOVZ/MOVK (20 B, no range limit).
	 */
	if (bs >= 20) {
		uintptr_t t = (uintptr_t)entry->trampoline;

		memcpy(entry->original_backup, entry->target_func, 20);

		patch[0] = MOVZ(16, (t >> 0) & 0xFFFF, 0);
		patch[1] = MOVK(16, (t >> 16) & 0xFFFF, 1);
		patch[2] = MOVK(16, (t >> 32) & 0xFFFF, 2);
		patch[3] = MOVK(16, (t >> 48) & 0xFFFF, 3);
		patch[4] = BR(16);
		ret = ksu_patch_text(entry->target_func, patch, 20,
				      KSU_PATCH_TEXT_FLUSH_ICACHE);
	} else {
		/* 12-byte fallback: ADRP + ADD + BR */
		uintptr_t t = (uintptr_t)entry->trampoline;
		u64 t_page = (u64)t & ~0xfffULL;
		u64 t_off  = (u64)t & 0xfffULL;
		int64_t tp = (int64_t)t_page -
			     (int64_t)((u64)(uintptr_t)patch & ~0xfffULL);

		memcpy(entry->original_backup, entry->target_func, bs);

		if ((tp & 0xfff) != 0 ||
		    (tp >>= 12, tp < -(1LL << 20) || tp >= (1LL << 20))) {
			pr_warn("Manager-Auth: trampoline out of ADRP range "
				"(pcrel=%lld pages) and bs=%zu < 20\n",
				(long long)tp, bs);
			free_trampoline(entry->trampoline);
			entry->trampoline = NULL;
			return -ERANGE;
		}
		patch[0] = 0x90000010U | (u32)(tp & 0x1FFFFFU);
		patch[1] = 0x91000210U | ((u32)t_off << 10);
		patch[2] = 0xd61f0200U;
		ret = ksu_patch_text(entry->target_func, patch, 12,
				      KSU_PATCH_TEXT_FLUSH_ICACHE);
	}

	if (ret != 0) {
		int rr = ksu_patch_text(entry->target_func,
					entry->original_backup, bs,
					KSU_PATCH_TEXT_FLUSH_ICACHE);
		free_trampoline(entry->trampoline);
		entry->trampoline = NULL;
		if (rr != 0) {
			pr_err("Manager-Auth: self-restore failed (%d); leaving "
			       "installed=true for future rollback\n", rr);
		} else {
			entry->installed = false;
		}
		return ret;
	}

	entry->installed = true;
	return 0;
}

static int arm64_remove(struct auth_patch_entry *entry)
{
	int ret;

	if (!entry->installed)
		return 0;

	ret = ksu_patch_text(entry->target_func, entry->original_backup,
			     entry->backup_size, KSU_PATCH_TEXT_FLUSH_ICACHE);
	if (ret != 0) {
		pr_err("Manager-Auth: failed to restore original bytes, patch still active\n");
		return ret;
	}
	if (entry->trampoline)
		dispose_trampoline(entry->trampoline);
	entry->trampoline = NULL;
	entry->installed = false;
	return 0;
}
#else /* !CONFIG_ARM64 */
static int arm64_build_trampoline(void *trampoline, void *handler) { return -EINVAL; }
static int arm64_install(struct auth_patch_entry *entry) { return -EINVAL; }
static int arm64_remove(struct auth_patch_entry *entry) { return -EINVAL; }
#endif /* CONFIG_ARM64 */

static const struct ma_arch_ops {
	int (*build_trampoline)(void *trampoline, void *handler);
	int (*install)(struct auth_patch_entry *);
	int (*remove)(struct auth_patch_entry *);
	size_t backup_size;
} ma_arch = {
	.build_trampoline = arm64_build_trampoline,
	.install = arm64_install,
	.remove = arm64_remove,
	.backup_size = 20,
};

static void *resolve_symbol(const char *name)
{
	void *addr;

#if defined(CONFIG_KALLSYMS) || defined(CONFIG_KALLSYMS_ALL)
	addr = (void *)kallsyms_lookup_name(name);
	if (!addr) {
		pr_err("Manager-Auth: symbol '%s' not found in kallsyms\n", name);
		return NULL;
	}
	pr_info("Manager-Auth: resolved '%s' -> %pS\n", name, addr);
	return addr;
#else
	pr_err("Manager-Auth: CONFIG_KALLSYMS required\n");
	return NULL;
#endif
}

static int ma_install_one(struct auth_patch_entry *entry)
{
	int ret;

	entry->target_func = resolve_symbol(entry->target_name);
	if (!entry->target_func)
		return -ENOENT;

	if (entry->backup_size == 0)
		entry->backup_size = ma_arch.backup_size;
	if (!target_in_kernel_text(entry->target_func)) {
		pr_warn("Manager-Auth: target %pS is not in kernel text\n",
			entry->target_func);
		return -ENOENT;
	}
	ret = validate_target_prologue(entry->target_func);
	if (ret != 0)
		return ret;

	entry->original_backup = kzalloc(entry->backup_size, GFP_KERNEL);
	if (!entry->original_backup)
		return -ENOMEM;

	ret = ma_arch.install(entry);
	if (ret != 0) {
		if (!entry->installed) {
			kfree(entry->original_backup);
			entry->original_backup = NULL;
		}
		return ret;
	}
	return 0;
}

static void do_remove_manager_auth_patch_locked(void)
{
	int restore_failed = 0;
	int i;

	if (!READ_ONCE(manager_auth_enabled))
		return;

	for (i = auth_auth_patch_count - 1; i >= 0; --i)
		if (ma_arch.remove(&auth_auth_patch_table[i]) != 0)
			restore_failed = 1;

	if (restore_failed) {
		pr_err("Manager-Auth: remove incomplete, retaining live patches for retry\n");
		return;
	}

	for (i = 0; i < auth_auth_patch_count; ++i) {
		kfree(auth_auth_patch_table[i].original_backup);
		auth_auth_patch_table[i].original_backup = NULL;
	}
	memset(auth_auth_patch_table, 0, sizeof(auth_auth_patch_table));
	auth_auth_patch_count = 0;
	WRITE_ONCE(manager_auth_enabled, false);
	pr_info("Manager-Auth: patches removed\n");
}

int install_manager_auth_patch(void)
{
#if !defined(CONFIG_ARM64)
	return -EINVAL;
#else
	int ret = 0;

	mutex_lock(&manager_auth_lock);
	if (READ_ONCE(manager_auth_enabled)) {
		pr_info("Manager-Auth: already active, removing first\n");
		do_remove_manager_auth_patch_locked();
		if (READ_ONCE(manager_auth_enabled)) {
			mutex_unlock(&manager_auth_lock);
			pr_err("Manager-Auth: self-heal remove failed; reload module to recover\n");
			return -EALREADY;
		}
	}

	memset(auth_auth_patch_table, 0, sizeof(auth_auth_patch_table));
	auth_auth_patch_count = 0;

	/* Hook 1: maybe_manager_apk_dir */
	auth_auth_patch_table[0].target_name = "maybe_manager_apk_dir";
	auth_auth_patch_table[0].handler = (void *)ma_maybe_manager_apk_dir_handler;
	ret = ma_install_one(&auth_auth_patch_table[0]);
	if (ret != 0) {
		pr_warn("Manager-Auth: install maybe_manager_apk_dir failed: %d\n", ret);
		goto out;
	}
	auth_auth_patch_count = 1;

	/* Hook 2: is_manager_apk */
	auth_auth_patch_table[1].target_name = "is_manager_apk";
	auth_auth_patch_table[1].handler = (void *)ma_is_manager_apk_handler;
	ret = ma_install_one(&auth_auth_patch_table[1]);
	if (ret != 0) {
		pr_warn("Manager-Auth: install is_manager_apk failed: %d\n", ret);
		goto out;
	}
	auth_auth_patch_count = 2;

out:
	if (ret == 0) {
		WRITE_ONCE(manager_auth_enabled, true);
		pr_info("Manager-Auth: installed (patches=%d)\n", auth_auth_patch_count);
	} else {
		int rollback_failed = 0;
		int i;

		for (i = auth_auth_patch_count - 1; i >= 0; --i)
			if (ma_arch.remove(&auth_auth_patch_table[i]) != 0)
				rollback_failed = 1;

		if (rollback_failed) {
			pr_err("Manager-Auth: install rollback incomplete\n");
			WRITE_ONCE(manager_auth_enabled, true);
		} else {
			for (i = 0; i < auth_auth_patch_count; ++i) {
				kfree(auth_auth_patch_table[i].original_backup);
				auth_auth_patch_table[i].original_backup = NULL;
			}
			auth_auth_patch_count = 0;
		}
	}

	mutex_unlock(&manager_auth_lock);
	return ret;
#endif /* CONFIG_ARM64 */
}

void remove_manager_auth_patch(void)
{
	mutex_lock(&manager_auth_lock);
	do_remove_manager_auth_patch_locked();
	mutex_unlock(&manager_auth_lock);
}
