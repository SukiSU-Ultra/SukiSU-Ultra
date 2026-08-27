#include <linux/version.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/types.h>

#include "feature/mount_hide.h"
#include "feature/kernel_umount.h"
#include "infra/symbol_resolver.h"
#include "hook/patch_memory.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "runtime/ksud_boot.h"
#include "klog.h" // IWYU pragma: keep

/*
 * Mount-view hiding.
 *
 * Two mount-based root probes are defeated here:
 *   1. A classic isolated process that inherits AID_READPROC (gid 3009) and reads
 *      every process's /proc/<pid>/{mountinfo,mounts,mountstats} - it flags module
 *      marker substrings AND a differential (distinct mount views vs propagation
 *      classes).
 *   2. An Android 17 zygote_next native isolated process that reads its OWN
 *      /proc/self/mountinfo but from init's GLOBAL namespace, where the module
 *      mounts are still present.
 *
 * We do NOT strip AID_READPROC, do NOT unmount in a shared namespace, and do NOT
 * spoof the Groups line - any of those is itself a non-stock deviation. Instead we
 * filter the per-record 'show' output of the three mount files, keyed on the READER
 * (current), applied uniformly to its own file and every pid it reads. Because the
 * same set of records is removed from every view, views never diverge and the
 * differential probe cannot fire; because it works by filtering (not unmounting) it
 * is safe in the global namespace too. procfs reports st_size == 0 for these files,
 * so removing records leaves no size tell.
 *
 * The kernel-side umount path (feature/kernel_umount.c) is kept as-is for classic
 * private-namespace apps; this filter is complementary.
 *
 * HIDE DECISION - three complementary matchers.
 * ---------------------------------------------------------
 * Both probes parse the WHOLE rendered mountinfo line and match markers anywhere in
 * it - crucially in the mount-root field (field 4, e.g. "/adb/modules/...") and in
 * the super-/mount-options (overlay "lowerdir=/data/adb/..."), not just the
 * mountpoint. So the primary matcher lets the ORIGINAL show function render the record
 * into the seq_file buffer, then scans exactly those bytes; on a marker hit we rewind
 * m->count to erase the record. This mirrors the probes byte-for-byte on the mountinfo
 * format.
 *
 * The text scan alone is NOT enough for /proc/pid/mounts and mountstats: those formats
 * omit the mount-root field, so a module bind mount (e.g. bindhosts binding
 * /adb/modules/.../system/etc/hosts onto /system/etc/hosts) renders with only a
 * block-device source and no visible marker. Two format-independent backstops cover it:
 *   (a) a match of the record text against the registered umount list
 *       (feature/kernel_umount.h) - the mountpoint appears in every format; note this
 *       list is empty when kernel_umount is disabled, so it cannot be relied on alone;
 *   (b) inspection of the mount's real root dentry path (ksu_mnt_root_hidden), which
 *       reveals /adb/modules/... regardless of the printed format and needs no umount
 *       list. It allocates a page and computes a dentry path, but only for a non-fs-root
 *       mount (IS_ROOT short-circuits the common whole-filesystem case).
 * To avoid over-hiding stock submounts, coarse/stock ancestors are never used for the
 * umount-list match (see ksu_region_has_mount_list()).
 */

/*
 * View of the kernel's `struct proc_mounts` (fs/mount.h, private header).
 *
 * Only the first three members - ns, root, show - are touched here, and their
 * order/type is ABI-stable across every GKI version this fork targets
 * (5.10 / 5.15 / 6.1 / 6.6 / 6.12). We never allocate one of these, never index
 * past ->show, and only ever dereference ->show on a kernel-allocated object.
 *
 * The `struct mount cursor;` tail was added in commit 9f6c61f96f2d (v5.8-rc1), so
 * ALL supported targets (>=5.8) carry the cursor layout; the older
 * `void *cached_mount; u64 cached_event; loff_t cached_index;` tail existed only
 * before 5.8, which this fork does not target. Either way the head (ns/root/show)
 * is identical and the tail is never accessed, so we deliberately omit it - it
 * embeds `struct mount` by value, whose layout is __randomize_layout and whose
 * header (fs/mount.h) is kernel-private.
 */
struct ksu_proc_mounts {
    struct mnt_namespace *ns;
    struct path root;
    int (*show)(struct seq_file *, struct vfsmount *);
    /* kernel-private tail intentionally omitted - see comment above */
};

typedef int (*ksu_proc_open_fn)(struct inode *, struct file *);
typedef int (*ksu_show_fn)(struct seq_file *, struct vfsmount *);

static DEFINE_MUTEX(ksu_mount_hide_mutex);
static bool ksu_mount_hide_enabled __read_mostly = true;
static bool ksu_mount_hide_running __read_mostly = false;

/* patched .open slots inside the resolved const file_operations (rodata) */
static ksu_proc_open_fn *ksu_mounts_open_slot;
static ksu_proc_open_fn *ksu_mountinfo_open_slot;
static ksu_proc_open_fn *ksu_mountstats_open_slot;

/* saved originals (called through raw pointers -> callers are __nocfi) */
static ksu_proc_open_fn ksu_orig_mounts_open;
static ksu_proc_open_fn ksu_orig_mountinfo_open;
static ksu_proc_open_fn ksu_orig_mountstats_open;
static ksu_show_fn ksu_orig_show_vfsmnt;
static ksu_show_fn ksu_orig_show_mountinfo;
static ksu_show_fn ksu_orig_show_vfsstat;

/*
 * High-confidence markers - substrings that only appear in a rendered mount record
 * because of a root solution, never on a stock device. Matched case-insensitively
 * to mirror both probes (ZygoteNextProbe uses contains_ignore_case; Privisolated's
 * "/adb/" / "magisk" checks land here too). "/adb/" is the fs-relative form seen in
 * the mount-root field and overlay lowerdir; "/data/adb" additionally covers a bare
 * "/data/adb" mountpoint (no trailing slash).
 */
static const char *const ksu_mount_markers[] = {
    "/adb/", "/data/adb", "kernelsu", "magisk", "zygisk", "/debug_ramdisk",
};

/*
 * Stock ancestors that must NEVER drive a mount_list subtree match: a coarse umount
 * entry (ksud may register these for the recursive-detach path) would otherwise
 * over-hide genuine stock submounts, and removing a stock mount is as detectable as
 * leaving a module one (it can collapse two propagation-class views into one and
 * fire Privisolated's set.size() != popcount differential).
 */
static const char *const ksu_stock_ancestors[] = {
    "/",    "/system", "/system_ext", "/vendor", "/product",  "/odm",   "/data",        "/mnt",         "/storage",
    "/dev", "/proc",   "/sys",        "/apex",   "/metadata", "/cache", "/system_dlkm", "/vendor_dlkm", "/odm_dlkm",
};

/* case-insensitive substring search over a non-NUL-terminated region */
static bool ksu_region_contains(const char *hay, size_t hlen, const char *needle, size_t nlen)
{
    size_t i, j;

    if (!nlen)
        return true;
    if (!hay || nlen > hlen)
        return false;
    for (i = 0; i + nlen <= hlen; i++) {
        for (j = 0; j < nlen; j++) {
            char a = hay[i + j];
            char b = needle[j];

            if (a >= 'A' && a <= 'Z')
                a += 'a' - 'A';
            if (b >= 'A' && b <= 'Z')
                b += 'a' - 'A';
            if (a != b)
                break;
        }
        if (j == nlen)
            return true;
    }
    return false;
}

static bool ksu_region_has_marker(const char *buf, size_t len)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ksu_mount_markers); i++) {
        if (ksu_region_contains(buf, len, ksu_mount_markers[i], strlen(ksu_mount_markers[i])))
            return true;
    }
    return false;
}

static bool ksu_path_is_stock_ancestor(const char *s)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ksu_stock_ancestors); i++) {
        if (!strcmp(s, ksu_stock_ancestors[i]))
            return true;
    }
    return false;
}

/* number of non-empty '/'-separated components ("/system/app/foo" -> 3) */
static int ksu_path_depth(const char *s)
{
    int d = 0;

    if (!s)
        return 0;
    while (*s) {
        while (*s == '/')
            s++;
        if (!*s)
            break;
        d++;
        while (*s && *s != '/')
            s++;
    }
    return d;
}

/*
 * Backstop match against the registered umount list. The mountpoint path appears in
 * every one of the three formats (mounts/mountinfo/mountstats), so a substring hit
 * here hides the record consistently across all of them.
 *
 * Guards against over-hiding (see ksu_stock_ancestors above):
 *   - never match on a stock ancestor entry;
 *   - require at least two path components, so a coarse top-level entry cannot
 *     swallow stock submounts (deep module mountpoints are unique enough that a
 *     substring hit is unambiguous).
 *
 * Lock order: this runs inside the seq ->show callback, which the mounts iterator
 * invokes with namespace_sem held for read (m_start). The umount path takes
 * mount_list_lock(R) -> namespace_sem(W); taking mount_list_lock(R) here under
 * namespace_sem(R) would invert that and, with a queued mount_list_lock writer,
 * deadlock. We therefore use down_read_trylock and simply skip the backstop on
 * contention (the intrinsic marker scan still applies) - correctness of the hide
 * never depends on winning a racing writer.
 */
static bool ksu_region_has_mount_list(const char *buf, size_t len)
{
    struct mount_entry *entry;
    bool hidden = false;

    if (!down_read_trylock(&mount_list_lock))
        return false;

    list_for_each_entry (entry, &mount_list, list) {
        const char *e = entry->umountable;
        size_t elen;

        if (!e)
            continue;
        if (ksu_path_is_stock_ancestor(e))
            continue;
        if (ksu_path_depth(e) < 2)
            continue;
        elen = strlen(e);
        if (elen && ksu_region_contains(buf, len, e, elen)) {
            hidden = true;
            break;
        }
    }
    up_read(&mount_list_lock);
    return hidden;
}

/*
 * Format-independent module check: look at the mount's real root DENTRY path rather
 * than the rendered text. A module is a bind mount whose source subtree lives under
 * /data/adb (shown as /adb/... relative to the data superblock), e.g. bindhosts binds
 * /adb/modules/bindhosts/system/etc/hosts onto /system/etc/hosts. Only /proc/pid/
 * mountinfo prints that root field; /proc/pid/mounts and mountstats do not, so a
 * text scan misses such records there. Inspecting mnt_root catches them everywhere
 * and needs no populated umount list (which is empty when kernel_umount is off).
 *
 * A whole-filesystem mount has mnt_root == the fs root (IS_ROOT), never a module
 * bind, so we skip the path computation for those - the common case.
 */
static bool ksu_mnt_root_hidden(struct vfsmount *mnt)
{
    char *buf, *p;
    bool hit = false;

    if (!mnt || !mnt->mnt_root || IS_ROOT(mnt->mnt_root))
        return false;

    buf = (char *)__get_free_page(GFP_KERNEL);
    if (!buf)
        return false;

    p = dentry_path_raw(mnt->mnt_root, buf, PAGE_SIZE);
    if (!IS_ERR(p))
        hit = ksu_region_has_marker(p, strlen(p));

    free_page((unsigned long)buf);
    return hit;
}

/*
 * Decide whether the CURRENT task's mount views should be filtered at all. This is
 * evaluated once, at open() time, so the reader identity is fixed for the file.
 *
 * Predicate (per design):
 *   (is_appuid || is_isolated) && (is_isolated || ksu_uid_should_umount)
 *
 * ksu_uid_should_umount already excludes the manager, su-granted apps and the
 * webview zygote, so those keep the real view. Isolated processes are always
 * filtered (they can never legitimately need the module view, and this is what
 * defeats the zygote_next global-namespace probe). We intentionally do NOT require
 * is_zygote() here (unlike the umount path): the zygote_next probe reads from the
 * global namespace and is not necessarily zygote-descended in that sense.
 */
#define KSU_APP_ZYGOTE_ISOLATED_FIRST 90000

/*
 * "Isolated" for the hide predicate covers BOTH ranges an isolated process can land
 * in: the app-zygote isolated range [90000, 98999] and the regular isolated range
 * [99000, 99999]. The shared is_isolated_process() only knows the latter; an
 * app-zygote isolated spawn would otherwise read an unfiltered view.
 */
static bool ksu_is_isolated_for_hide(uid_t uid)
{
    uid_t appid = uid % PER_USER_RANGE;

    return appid >= KSU_APP_ZYGOTE_ISOLATED_FIRST && appid <= LAST_ISOLATED_UID;
}

static bool ksu_should_hide_mount_for_current(void)
{
    uid_t uid;
    bool isolated;

    /*
     * Intentionally independent of ksu_module_mounted: module mounts may be
     * established outside KernelSU's own path (e.g. NeoZygisk), so that flag does
     * not reflect whether an isolated view contains module records. The filter only
     * ever removes lines that match a marker or the umount list, so running it for
     * every hide target is safe (no module mounts => nothing removed).
     */
    if (!ksu_mount_hide_enabled)
        return false;

    uid = current_uid().val;
    isolated = ksu_is_isolated_for_hide(uid);
    if (!is_appuid(uid) && !isolated)
        return false;
    if (!isolated && !ksu_uid_should_umount(uid))
        return false;

    return true;
}

/*
 * Core filter. Let the original show render the record into the seq buffer, then scan
 * those bytes AND inspect the mount's real root dentry path; on a match from either, we
 * rewind m->count so the record leaves zero output (the seq iterator simply skips a
 * zero-length element). The dentry-path check is what catches module bind mounts in
 * /proc/pid/mounts and mountstats, whose text carries no marker.
 *
 * On overflow the record did not fully fit; the seq layer restores the pre-record
 * offset, doubles the buffer and re-invokes ->show, so we pass through untouched and
 * do the scan on the full retry. On a nonzero return (SEQ_SKIP / error) the seq layer
 * discards the bytes itself, so we pass the code through unchanged.
 *
 * Called through the seq iterator's function pointer and calling the original through
 * a raw pointer -> __nocfi.
 */
static int __nocfi ksu_filter_show(struct seq_file *m, struct vfsmount *mnt, ksu_show_fn orig)
{
    size_t start;
    int ret;

    if (!m)
        return orig(m, mnt);

    start = m->count;
    ret = orig(m, mnt);
    if (ret)
        return ret; /* SEQ_SKIP / error: seq layer handles the bytes */
    if (seq_has_overflowed(m))
        return 0; /* record truncated; seq will realloc and retry */
    if (m->count <= start)
        return 0; /* nothing emitted */

    if (ksu_region_has_marker(m->buf + start, m->count - start) ||
        ksu_region_has_mount_list(m->buf + start, m->count - start) || ksu_mnt_root_hidden(mnt))
        m->count = start; /* erase the record */

    return 0;
}

static int __nocfi ksu_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)
{
    return ksu_filter_show(m, mnt, ksu_orig_show_vfsmnt);
}

static int __nocfi ksu_show_mountinfo(struct seq_file *m, struct vfsmount *mnt)
{
    return ksu_filter_show(m, mnt, ksu_orig_show_mountinfo);
}

static int __nocfi ksu_show_vfsstat(struct seq_file *m, struct vfsmount *mnt)
{
    return ksu_filter_show(m, mnt, ksu_orig_show_vfsstat);
}

/*
 * .open shims. Each calls the saved original open (which populates the seq_file and
 * proc_mounts, setting proc_mounts::show to the kernel original), then - if the
 * reader is a hide target - swaps proc_mounts::show to the matching filter. That
 * swap is a plain store to the per-file, kmalloc'd proc_mounts (NOT rodata), so no
 * text patching is involved here.
 *
 * Called through the rodata file_operations table and calling the original through a
 * raw pointer -> __nocfi.
 */
static int __nocfi ksu_install_filter(struct file *file, ksu_show_fn filter)
{
    struct seq_file *m = file->private_data;
    struct ksu_proc_mounts *p;

    if (!m || !m->private)
        return 0;
    p = (struct ksu_proc_mounts *)m->private;
    p->show = filter;
    return 0;
}

static int __nocfi ksu_mounts_open(struct inode *inode, struct file *file)
{
    int ret = ksu_orig_mounts_open(inode, file);
    if (!ret && ksu_should_hide_mount_for_current())
        ksu_install_filter(file, ksu_show_vfsmnt);
    return ret;
}

static int __nocfi ksu_mountinfo_open(struct inode *inode, struct file *file)
{
    int ret = ksu_orig_mountinfo_open(inode, file);
    if (!ret && ksu_should_hide_mount_for_current())
        ksu_install_filter(file, ksu_show_mountinfo);
    return ret;
}

static int __nocfi ksu_mountstats_open(struct inode *inode, struct file *file)
{
    int ret = ksu_orig_mountstats_open(inode, file);
    if (!ret && ksu_should_hide_mount_for_current())
        ksu_install_filter(file, ksu_show_vfsstat);
    return ret;
}

/* patch one file_operations::open; record slot + original for teardown */
static int ksu_patch_open(struct file_operations *ops, ksu_proc_open_fn newfn, ksu_proc_open_fn **slot_out,
                          ksu_proc_open_fn *orig_out, const char *name)
{
    ksu_proc_open_fn *slot = &ops->open;
    ksu_proc_open_fn nf = newfn;
    int ret;

    *orig_out = *slot;
    pr_info("mount_hide: %s.open: 0x%lx [%pSb]\n", name, (unsigned long)*slot, *slot);
    ret = ksu_patch_text(slot, &nf, sizeof(nf), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (ret) {
        pr_err("mount_hide: patch_text %s.open err: %d\n", name, ret);
        *orig_out = NULL;
        return ret;
    }
    *slot_out = slot;
    return 0;
}

static void ksu_unhook_one(ksu_proc_open_fn **slot, ksu_proc_open_fn *orig, const char *name)
{
    int ret;

    if (!*slot || !*orig)
        return;
    ret = ksu_patch_text(*slot, orig, sizeof(*orig), KSU_PATCH_TEXT_FLUSH_DCACHE);
    if (ret)
        pr_err("mount_hide: exit: patch_text %s err: %d\n", name, ret);
    *slot = NULL;
    /*
     * Deliberately keep *orig non-NULL: a shim already past the .open restore, or a
     * seq_file already opened while hooked (its proc_mounts::show still points at our
     * filter, which calls *orig), may still dereference it. The unhook path issues a
     * synchronize_rcu() after restoring all three slots to drain such in-flight shims
     * before teardown proceeds, so leaving *orig valid until then is safe; NULLing it
     * would instead hand an in-flight shim a NULL call.
     */
}

static void ksu_mount_hide_unhook(void)
{
    ksu_unhook_one(&ksu_mounts_open_slot, &ksu_orig_mounts_open, "proc_mounts_operations");
    ksu_unhook_one(&ksu_mountinfo_open_slot, &ksu_orig_mountinfo_open, "proc_mountinfo_operations");
    ksu_unhook_one(&ksu_mountstats_open_slot, &ksu_orig_mountstats_open, "proc_mountstats_operations");
    /* drain shims that already entered .open before the restore above */
    synchronize_rcu();
}

/*
 * Resolve every symbol and hook all three files ATOMICALLY, or none.
 *
 * If only some files were hooked, /proc/pid/mounts, mountinfo and mountstats would
 * disagree for a hide target - a trivial cross-file differential that no stock system
 * exhibits. So a single unresolved symbol (any show fn or any ops struct) makes the
 * whole feature no-op rather than hooking a subset.
 *
 * Both the static show_* functions AND the proc_*_operations structs live outside the
 * export table and depend on CONFIG_KALLSYMS_ALL (which GKI enables); if that ever
 * fails to resolve on some target, the intended fallback is an LSM file_open hook
 * (KSU_LSM_HOOK_INIT(file_open, "selinux_file_open", ...)) plus a read wrapper
 * (infra/file_wrapper.c pattern) that materializes the full output, drops hidden
 * lines and serves from a per-file side buffer freed in .release.
 */
static int ksu_mount_hide_enable(void)
{
    struct file_operations *ops_mounts, *ops_mountinfo, *ops_mountstats;
    int ret;

    pr_info("mount_hide: init mount hide\n");

    ksu_orig_show_vfsmnt = (ksu_show_fn)find_kernel_symbol_exact("show_vfsmnt");
    ksu_orig_show_mountinfo = (ksu_show_fn)find_kernel_symbol_exact("show_mountinfo");
    /* NOTE: the mountstats show symbol is show_vfsstat, NOT show_mountstats */
    ksu_orig_show_vfsstat = (ksu_show_fn)find_kernel_symbol_exact("show_vfsstat");
    if (!ksu_orig_show_vfsmnt || !ksu_orig_show_mountinfo || !ksu_orig_show_vfsstat) {
        pr_err("mount_hide: show fns unresolved (vfsmnt=%d mountinfo=%d vfsstat=%d), refusing partial hook\n",
               !!ksu_orig_show_vfsmnt, !!ksu_orig_show_mountinfo, !!ksu_orig_show_vfsstat);
        return -ENOSYS;
    }

    ops_mounts = (struct file_operations *)find_kernel_symbol_exact("proc_mounts_operations");
    ops_mountinfo = (struct file_operations *)find_kernel_symbol_exact("proc_mountinfo_operations");
    ops_mountstats = (struct file_operations *)find_kernel_symbol_exact("proc_mountstats_operations");
    if (!ops_mounts || !ops_mountinfo || !ops_mountstats) {
        pr_err("mount_hide: ops unresolved (mounts=%d mountinfo=%d mountstats=%d), refusing partial hook\n",
               !!ops_mounts, !!ops_mountinfo, !!ops_mountstats);
        return -ENOSYS;
    }

    ret = ksu_patch_open(ops_mounts, ksu_mounts_open, &ksu_mounts_open_slot, &ksu_orig_mounts_open,
                         "proc_mounts_operations");
    if (ret)
        goto fail;
    ret = ksu_patch_open(ops_mountinfo, ksu_mountinfo_open, &ksu_mountinfo_open_slot, &ksu_orig_mountinfo_open,
                         "proc_mountinfo_operations");
    if (ret)
        goto fail;
    ret = ksu_patch_open(ops_mountstats, ksu_mountstats_open, &ksu_mountstats_open_slot, &ksu_orig_mountstats_open,
                         "proc_mountstats_operations");
    if (ret)
        goto fail;

    pr_info("mount_hide: enabled (3/3 files hooked)\n");
    return 0;

fail:
    /* roll back any slot already patched so the three files stay consistent */
    ksu_mount_hide_unhook();
    return ret;
}

static void ksu_mount_hide_disable(void)
{
    pr_info("mount_hide: exit mount hide\n");
    ksu_mount_hide_unhook();
}

static int mount_hide_feature_get(u64 *value)
{
    *value = ksu_mount_hide_enabled ? 1 : 0;
    return 0;
}

static int mount_hide_feature_set(u64 value)
{
    bool enable = value != 0;
    int ret = 0;

    pr_info("mount_hide: set to %d\n", enable);
    mutex_lock(&ksu_mount_hide_mutex);
    ksu_mount_hide_enabled = enable;
    if (enable) {
        if (!ksu_mount_hide_running) {
            ret = ksu_mount_hide_enable();
            if (!ret)
                ksu_mount_hide_running = true;
        }
    } else {
        /*
         * Leave the .open hooks installed; ksu_should_hide_mount_for_current()
         * already gates on ksu_mount_hide_enabled, so a disabled toggle makes every
         * open a pure pass-through. This keeps the toggle cheap and avoids repeated
         * rodata patching. The hooks are only torn down at module exit.
         */
    }
    mutex_unlock(&ksu_mount_hide_mutex);
    return ret;
}

static const struct ksu_feature_handler mount_hide_handler = {
    .feature_id = KSU_FEATURE_MOUNT_HIDE,
    .name = "mount_hide",
    .get_handler = mount_hide_feature_get,
    .set_handler = mount_hide_feature_set,
};

void __init ksu_mount_hide_init(void)
{
    if (ksu_register_feature_handler(&mount_hide_handler))
        pr_err("Failed to register mount_hide feature handler\n");

    /* default enabled: install the hooks up front */
    mutex_lock(&ksu_mount_hide_mutex);
    if (ksu_mount_hide_enabled && !ksu_mount_hide_running) {
        if (!ksu_mount_hide_enable())
            ksu_mount_hide_running = true;
    }
    mutex_unlock(&ksu_mount_hide_mutex);
}

void __exit ksu_mount_hide_exit(void)
{
    mutex_lock(&ksu_mount_hide_mutex);
    if (ksu_mount_hide_running) {
        ksu_mount_hide_disable();
        ksu_mount_hide_running = false;
    }
    mutex_unlock(&ksu_mount_hide_mutex);
    ksu_unregister_feature_handler(KSU_FEATURE_MOUNT_HIDE);
}
