// SPDX-License-Identifier: GPL-2.0
/*
 * Hot-patch infrastructure for signature-fallback support.
 *
 * We patch two functions so that third-party manager APKs whose package
 * name does NOT match the compiled KSU_PACKAGE_NAME can still be
 * recognized:
 *   1. maybe_manager_apk_dir  — apply the layered gate (built-in sig >
 *      legacy package-name match > dynamic_manager double check).
 *   2. is_manager_apk         — try compiled EXPECTED_SIZE/HASH first;
 *      on failure, run the dynamic_manager double check.
 *
 * Per-entry double check: an entry in the dynamic_manager table only
 * authorizes the APK when BOTH the APK's resolved package name AND its
 * signature match the entry. A signature-only or package-only match is
 * not sufficient.
 *
 * The dynamic_manager feature switch (`ksu_manager_enabled()`) gates
 * layer 3 entirely — when disabled, the table is treated as empty and
 * the dynamic managers behave exactly like uninstalled regular managers.
 *
 * Architecture trampoline sizes (must be a multiple of 16, and large
 * enough to hold the prologue + handler call + epilogue + NOP tail):
 *   ARM64   : 64 bytes  (16 arm64 instructions)
 *   x86_64  : 48 bytes  (uses ~13 bytes of real code; rest NOP-sled)
 *   others  : 32 bytes  (compiled as stubs, install refused at runtime)
 *
 * ksu_patch_text() on vmalloc memory: ksu_patch_text writes through a
 * FIX_TEXT_POKE0 fixmap entry after looking up the physical address via
 * init_mm page tables (see hook/<arch>/patch_memory.c).  This works for
 * any kernel virtual address — kernel .text AND vmalloc regions — so it
 * is safe to use for both the trampoline (vmalloc, just marked +X) and
 * the target function (kernel .text, default +X + RO on STRICT_KERNEL_RWX
 * kernels; ksu_patch_text flips the page to RW around the write).
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "klog.h" // IWYU pragma: keep
#include "dynamic_manager.h"
#include "manager/apk_sign.h"
#include "manager/throne_tracker.h"
#include "uapi/manager.h"
#include "infra/symbol_resolver.h"
#include "hook/patch_memory.h"

#include "extension/hot_patch.h"

extern struct ksu_manager_entry dynamic_managers[];
extern __u32 dynamic_manager_count;
extern rwlock_t dynamic_manager_lock;

#define MAX_HOT_PATCHES 2

struct patch_entry {
    void *target_func;         /* address to patch */
    void *handler;             /* trampoline entry handler */
    void *trampoline;          /* allocated trampoline */
    void *original_backup;     /* backed-up original bytes */
    size_t backup_size;        /* how many bytes were backed up */
    bool   installed;
};

static struct patch_entry patch_table[MAX_HOT_PATCHES];
static int patch_count;

static DEFINE_MUTEX(hot_patch_lock);
static bool hot_patch_enabled;

static bool maybe_manager_apk_dir_impl(const char *path)
{
    char pkg[KSU_MAX_PACKAGE_NAME];
    if (get_pkg_from_apk_dir_path(pkg, path) < 0)
        return false;
    return strcmp(pkg, KSU_PACKAGE_NAME) == 0;
}

static bool built_in_manager_signature_matches(const char *path)
{
    return ksu_check_apk_signature(path, EXPECTED_SIZE, EXPECTED_HASH);
}

static bool apk_path_resolves_to_package(const char *path, char *pkg)
{
    return get_pkg_from_apk_dir_path(pkg, path) >= 0;
}

static bool dynamic_manager_entry_matches(const char *path, const char *pkg,
                                          const struct ksu_manager_entry *e)
{
    if (WARN_ON_ONCE(memchr(e->package, '\0', sizeof(e->package)) == NULL))
        return false;
    if (strncmp(e->package, pkg, sizeof(e->package)) != 0)
        return false;
    return ksu_check_apk_signature(path, e->cert_size, e->hash);
}

static bool dynamic_manager_table_matches_locked(const char *path, const char *pkg)
{
    unsigned i;

    if (!ksu_manager_enabled())
        return false;

    for (i = 0; i < dynamic_manager_count; ++i) {
        const struct ksu_manager_entry *e = &dynamic_managers[i];
        if (dynamic_manager_entry_matches(path, pkg, e)) {
            pr_debug("Hot-patch: dynamic_manager[%u] matched %s\n", i, path);
            return true;
        }
    }
    return false;
}

static bool hot_patch_maybe_manager_apk_dir_handler(const char *path)
{
    char pkg[KSU_MAX_PACKAGE_NAME];
    bool matched;

    if (built_in_manager_signature_matches(path))
        return true;
    if (maybe_manager_apk_dir_impl(path))
        return true;
    if (!apk_path_resolves_to_package(path, pkg))
        return false;

    read_lock(&dynamic_manager_lock);
    matched = dynamic_manager_table_matches_locked(path, pkg);
    read_unlock(&dynamic_manager_lock);
    return matched;
}

static bool hot_patch_is_manager_apk_handler(char *path)
{
    char pkg[KSU_MAX_PACKAGE_NAME];
    bool matched;

    if (built_in_manager_signature_matches(path))
        return true;
    if (!apk_path_resolves_to_package(path, pkg))
        return false;

    read_lock(&dynamic_manager_lock);
    matched = dynamic_manager_table_matches_locked(path, pkg);
    read_unlock(&dynamic_manager_lock);
    return matched;
}

#if defined(CONFIG_ARM64)
#define TRAMPOLINE_SIZE 64
#elif defined(CONFIG_X86_64)
#define TRAMPOLINE_SIZE 48
#else
#define TRAMPOLINE_SIZE 32
#endif

static int make_page_executable(void *addr, size_t size)
{
#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
    int npages = DIV_ROUND_UP(size, PAGE_SIZE);
    return set_memory_x((unsigned long)addr, npages);
#else
    (void)addr;
    (void)size;
    return 0;
#endif
}

static void *alloc_trampoline(size_t backup_size)
{
    size_t total = TRAMPOLINE_SIZE;
    if (backup_size > TRAMPOLINE_SIZE)
        total = backup_size;
    void *mem = __vmalloc(total, GFP_KERNEL, PAGE_KERNEL);
    if (!mem)
        return NULL;
    if (make_page_executable(mem, total) != 0) {

#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
        int npages = DIV_ROUND_UP(total, PAGE_SIZE);
        int nx_ret = set_memory_nx((unsigned long)mem, npages);
        if (nx_ret != 0)
            pr_warn("Hot-patch: rollback set_memory_nx failed: %d\n",
                    nx_ret);
#endif
        vfree(mem);
        return NULL;
    }
    return mem;
}

static void free_trampoline(void *mem, size_t backup_size)
{
    if (!mem)
        return;
    size_t total = TRAMPOLINE_SIZE;
    if (backup_size > TRAMPOLINE_SIZE)
        total = backup_size;
#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
    int npages = DIV_ROUND_UP(total, PAGE_SIZE);
    if (set_memory_nx((unsigned long)mem, npages) != 0)
        pr_warn("Hot-patch: set_memory_nx failed, releasing executable memory\n");
#endif
    (void)backup_size;
    vfree(mem);
}

#if defined(CONFIG_ARM64)

/* ARM64 NOP */
#define HP_NOP 0xd503201f

static bool arm64_within_bl_range(void *target, void *pc)
{
    ptrdiff_t off = (ptrdiff_t)target - (ptrdiff_t)pc;
    return (off & 3) == 0 && off >= -(1LL << 27) && off < (1LL << 27);
}

static int build_arm64_trampoline(void *trampoline, void *handler)
{
    u32 *code = (u32 *)trampoline;

    ptrdiff_t bl_off = (ptrdiff_t)handler - (ptrdiff_t)(&code[1]);
    if ((bl_off & 3) != 0 || bl_off < -(1LL << 27) || bl_off >= (1LL << 27)) {
        pr_warn("Hot-patch: handler out of BL range from trampoline\n");
        return -ERANGE;
    }
    int32_t imm26 = (int32_t)(bl_off >> 2); /* truncate → natural sign-extends */
    code[0] = 0xa9bf7bfdU;                            /* STP X29, X30, [SP, #-16]! */
    code[1] = 0x94000000U | (u32)(imm26 & 0x03ffffffU); /* BL handler */
    code[2] = 0xa8cf7bfdU;                            /* LDP X29, X30, [SP], #16 */
    code[3] = 0xd65f03c0U;                            /* RET */

    for (int i = 4; i < TRAMPOLINE_SIZE / 4; i++)
        code[i] = HP_NOP;

    int ret = ksu_patch_text(trampoline, code, TRAMPOLINE_SIZE,
                             KSU_PATCH_TEXT_FLUSH_ICACHE);
    if (ret != 0)
        return ret;
    return 0;
}

static int install_arm64_patch(struct patch_entry *entry)
{
    size_t bs = entry->backup_size;

    if (bs < 12)
        return -EINVAL;

    if (WARN_ON((uintptr_t)entry->target_func & 3))
        return -EINVAL;

    entry->trampoline = alloc_trampoline(entry->backup_size);
    if (!entry->trampoline)
        return -ENOMEM;

    memcpy(entry->original_backup, entry->target_func, bs);

    int build_ret = build_arm64_trampoline(entry->trampoline, entry->handler);
    if (build_ret != 0) {
        pr_warn("Hot-patch: build_arm64_trampoline failed: %d\n", build_ret);
        free_trampoline(entry->trampoline, entry->backup_size);
        entry->trampoline = NULL;
        return build_ret;
    }

    if (!arm64_within_bl_range(entry->trampoline,
                               (u8 *)entry->target_func + 4)) {
        pr_warn("Hot-patch: trampoline out of BL range\n");
        free_trampoline(entry->trampoline, entry->backup_size);
        entry->trampoline = NULL;
        return -ERANGE;
    }

    ptrdiff_t off = (ptrdiff_t)entry->trampoline -
                    (ptrdiff_t)(entry->target_func + 4);
    int32_t imm26 = (int32_t)(off >> 2);

    u32 patch[3] = { 0x14000000U | (u32)(imm26 & 0x03ffffffU), HP_NOP, HP_NOP };
    int ret = ksu_patch_text(entry->target_func, patch, sizeof(patch),
                            KSU_PATCH_TEXT_FLUSH_ICACHE);
    if (ret != 0) {
        free_trampoline(entry->trampoline, entry->backup_size);
        entry->trampoline = NULL;
        return ret;
    }
    entry->installed = true;
    return 0;
}

static int remove_arm64_patch(struct patch_entry *entry)
{

    if (!entry->installed)
        return 0;

    int ret = ksu_patch_text(entry->target_func, entry->original_backup,
                             entry->backup_size, KSU_PATCH_TEXT_FLUSH_ICACHE);
    if (ret != 0) {
        pr_err("Hot-patch: failed to restore original bytes, patch still active\n");
        return ret;
    }
    if (entry->trampoline)
        free_trampoline(entry->trampoline, entry->backup_size);
    entry->trampoline = NULL;
    entry->installed = false;
    return 0;
}

#elif defined(CONFIG_X86_64)

static int build_x86_64_trampoline(void *trampoline, void *handler)
{
    u8 *code = (u8 *)trampoline;
    int pos = 0;

    code[pos++] = 0x48;
    code[pos++] = 0x83;
    code[pos++] = 0xec;
    code[pos++] = 0x08;

    int32_t rel = (int32_t)((uintptr_t)handler - (uintptr_t)(code + pos + 5));
    code[pos++] = 0xe8;
    memcpy(&code[pos], &rel, 4);
    pos += 4;              /* pos = 9 after writing immediate */

    code[pos++] = 0x48;
    code[pos++] = 0x83;
    code[pos++] = 0xc0;
    code[pos++] = 0x08;

    code[pos++] = 0xc3;    /* RET */

    while (pos < TRAMPOLINE_SIZE)
        code[pos++] = 0x90;

    int ret = ksu_patch_text(trampoline, code, TRAMPOLINE_SIZE,
                             KSU_PATCH_TEXT_FLUSH_ICACHE);
    if (ret != 0)
        return ret;
    return 0;
}

static int install_x86_64_patch(struct patch_entry *entry)
{
    if (entry->backup_size < 16)
        return -EINVAL;

    entry->trampoline = alloc_trampoline(entry->backup_size);
    if (!entry->trampoline)
        return -ENOMEM;

    memcpy(entry->original_backup, entry->target_func, entry->backup_size);

    int build_ret = build_x86_64_trampoline(entry->trampoline, entry->handler);
    if (build_ret != 0) {
        free_trampoline(entry->trampoline, entry->backup_size);
        entry->trampoline = NULL;
        return build_ret;
    }

    u8 *tgt = (u8 *)entry->target_func;
    int64_t off = (int64_t)((uintptr_t)entry->trampoline -
                            (uintptr_t)(tgt + 5));
    if (off < INT32_MIN || off > INT32_MAX) {
        pr_warn("Hot-patch: trampoline out of JMP range\n");
        free_trampoline(entry->trampoline, entry->backup_size);
        entry->trampoline = NULL;
        return -ERANGE;
    }
    int32_t rel = (int32_t)off;
    u8 patch[16] = {
        0xe9, 0x00, 0x00, 0x00, 0x00, /* JMP rel32 (5 bytes) */
        [5 ... 15] = 0x90              /* NOP-sled to 16 bytes */
    };
    memcpy(&patch[1], &rel, 4);

    int ret = ksu_patch_text(tgt, patch, sizeof(patch),
                             KSU_PATCH_TEXT_FLUSH_ICACHE);
    if (ret != 0) {
        free_trampoline(entry->trampoline, entry->backup_size);
        entry->trampoline = NULL;
        return ret;
    }
    entry->installed = true;
    return 0;
}

static int remove_x86_64_patch(struct patch_entry *entry)
{
    if (!entry->installed)
        return 0;

    int ret = ksu_patch_text(entry->target_func, entry->original_backup,
                             entry->backup_size, KSU_PATCH_TEXT_FLUSH_ICACHE);
    if (ret != 0) {
        pr_err("Hot-patch: failed to restore original bytes, patch still active\n");
        return ret;
    }
    if (entry->trampoline)
        free_trampoline(entry->trampoline, entry->backup_size);
    entry->trampoline = NULL;
    entry->installed = false;
    return 0;
}

#else /* !CONFIG_ARM64 && !CONFIG_X86_64 */
#warning "Hot-patch not supported on this architecture"
static int install_arm64_patch(struct patch_entry *e) { return -EOPNOTSUPP; }
static int remove_arm64_patch(struct patch_entry *e) { return 0; }
#define install_x86_64_patch install_arm64_patch
#define remove_x86_64_patch  remove_arm64_patch
#endif /* CONFIG_ARCH */

int install_signature_fallback_hot_patch(void)
{
    int ret = 0;

#if !defined(CONFIG_ARM64) && !defined(CONFIG_X86_64)
    pr_warn("Hot-patch: architecture unsupported, install refused\n");
    return -EOPNOTSUPP;
#endif

    mutex_lock(&hot_patch_lock);
    if (hot_patch_enabled) {
        mutex_unlock(&hot_patch_lock);
        pr_info("Hot-patch: state already active — "
                "either fully installed, or a prior failed rollback "
                "left live patches; call remove_signature_fallback_"
                "hot_patch to recover before retrying install\n");
        return 0;
    }

    memset(patch_table, 0, sizeof(patch_table));

    patch_table[0].target_func =
        ksu_resolve_symbol_for_functable_hook("maybe_manager_apk_dir");
    if (!patch_table[0].target_func) {
        pr_warn("Hot-patch: maybe_manager_apk_dir not found in kallsyms\n");
        ret = -ENOENT;
        goto out;
    }
    patch_table[0].handler = (void *)hot_patch_maybe_manager_apk_dir_handler;
#if defined(CONFIG_ARM64)
    patch_table[0].backup_size = 12; /* B (4) + NOP + NOP */
#elif defined(CONFIG_X86_64)
    patch_table[0].backup_size = 16; /* JMP (5) + NOP-sled (11) */
#endif
    patch_table[0].original_backup = kzalloc(patch_table[0].backup_size, GFP_KERNEL);
    if (!patch_table[0].original_backup) {
        ret = -ENOMEM;
        goto out;
    }

    patch_table[1].target_func =
        ksu_resolve_symbol_for_functable_hook("is_manager_apk");
    if (!patch_table[1].target_func) {
        pr_warn("Hot-patch: is_manager_apk not found in kallsyms\n");
        ret = -ENOENT;
        goto out;
    }
    patch_table[1].handler = (void *)hot_patch_is_manager_apk_handler;
#if defined(CONFIG_ARM64)
    patch_table[1].backup_size = 12; /* B (4) + NOP + NOP */
#elif defined(CONFIG_X86_64)
    patch_table[1].backup_size = 16; /* JMP (5) + NOP-sled (11) */
#endif
    patch_table[1].original_backup = kzalloc(patch_table[1].backup_size, GFP_KERNEL);
    if (!patch_table[1].original_backup) {
        kfree(patch_table[0].original_backup);
        patch_table[0].original_backup = NULL;
        ret = -ENOMEM;
        goto out;
    }

    patch_count = 2;

#if defined(CONFIG_ARM64)
    ret = install_arm64_patch(&patch_table[0]);
    if (ret == 0)
        ret = install_arm64_patch(&patch_table[1]);
#elif defined(CONFIG_X86_64)
    ret = install_x86_64_patch(&patch_table[0]);
    if (ret == 0)
        ret = install_x86_64_patch(&patch_table[1]);
#endif

out:
    if (ret == 0) {
        hot_patch_enabled = true;
        pr_info("Hot-patch: signature-fallback installed (patches=%d)\n",
                patch_count);
    } else {
        int rollback_failed = 0;
#if defined(CONFIG_ARM64)
        if (remove_arm64_patch(&patch_table[0]) != 0)
            rollback_failed = 1;
        if (remove_arm64_patch(&patch_table[1]) != 0)
            rollback_failed = 1;
#elif defined(CONFIG_X86_64)
        if (remove_x86_64_patch(&patch_table[0]) != 0)
            rollback_failed = 1;
        if (remove_x86_64_patch(&patch_table[1]) != 0)
            rollback_failed = 1;
#endif
        if (rollback_failed) {
            pr_err("Hot-patch: install rollback incomplete, "
                   "keeping live patches for retry\n");
            hot_patch_enabled = true;
        } else {
            kfree(patch_table[0].original_backup);
            patch_table[0].original_backup = NULL;
            kfree(patch_table[1].original_backup);
            patch_table[1].original_backup = NULL;
            patch_count = 0;
        }
    }

    mutex_unlock(&hot_patch_lock);
    return ret;
}

void remove_signature_fallback_hot_patch(void)
{
    int restore_failed = 0;

    mutex_lock(&hot_patch_lock);
    if (!hot_patch_enabled) {
        mutex_unlock(&hot_patch_lock);
        return;
    }

#if defined(CONFIG_ARM64)
    for (int i = patch_count - 1; i >= 0; --i)
        if (remove_arm64_patch(&patch_table[i]) != 0)
            restore_failed = 1;
#elif defined(CONFIG_X86_64)
    for (int i = patch_count - 1; i >= 0; --i)
        if (remove_x86_64_patch(&patch_table[i]) != 0)
            restore_failed = 1;
#endif

    if (restore_failed) {
        pr_err("Hot-patch: remove incomplete, retaining live patches for retry\n");
        mutex_unlock(&hot_patch_lock);
        return;
    }

    kfree(patch_table[0].original_backup);
    patch_table[0].original_backup = NULL;
    kfree(patch_table[1].original_backup);
    patch_table[1].original_backup = NULL;
    memset(patch_table, 0, sizeof(patch_table));
    patch_count = 0;
    hot_patch_enabled = false;
    pr_info("Hot-patch: signature-fallback removed\n");

    mutex_unlock(&hot_patch_lock);
}
