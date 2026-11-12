#include <linux/version.h>
#include <linux/cache.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/types.h>

#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif


/*
 * Mount-view hiding.
 *
 * Two mount-based root probes are defeated here:
 *   1. A classic isolated process that inherits AID_READPROC (gid 3009) and reads
 *	  every process's /proc/<pid>/{mountinfo,mounts,mountstats} - it flags module
 *	  marker substrings AND a differential (distinct mount views vs propagation
 *	  classes).
 *   2. An Android 17 zygote_next native isolated process that reads its OWN
 *	  /proc/self/mountinfo but from init's GLOBAL namespace, where the module
 *	  mounts are still present.
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
 * WHY THE OPEN IS NEVER REFUSED.
 * ---------------------------------------------------------
 * Hiding the file by failing open() with -ENOENT is not an option: userspace cannot
 * tell a hidden file from a broken one, and stock code treats the failure as fatal.
 * AOSP libincfs builds its MountRegistry with std::ifstream("/proc/mounts") and
 * PLOG(FATAL)s on failure, so every process that maps an uncompressed APK entry
 * (SystemUI, launcher, WebView renderers) aborts in a loop. The open must succeed and
 * the record content must be filtered instead.
 *
 * HOW THE FILTER IS INSTALLED.
 * ---------------------------------------------------------
 * This fork ships without kernel/hook/patch_memory.h and the per-arch patch_memory.c
 * implementations of ksu_patch_text(), so the upstream design that rewrites the
 * .open pointer of proc_{mounts,mountinfo,mountstats}_operations (rodata) is not
 * available here. The same point is reached through the LSM framework this fork
 * already wires up via kernel/hook/lsm_hook.c - but not from file_open:
 * security_file_open() runs BEFORE f_op->open() (4.14 .. 6.12), so the proc seq_file
 * does not exist yet at that point. security_file_permission() runs on the first read
 * (rw_verify_area() calls it before any data is produced) with the file fully opened,
 * which is where proc_mounts::show is swapped for our filter.
 *
 * That swap is a plain store to the per-file, kmalloc'd proc_mounts (NOT rodata), so
 * no text patching is involved. We never compare the slot against a kallsyms
 * address: under CFI it holds the function's jump-table entry, not the function
 * body, and a SUSFS mounts_open() replaces it with susfs_show_vfsmnt(). Instead we
 * chain to whatever pointer is actually installed and swap in our own wrapper, so
 * the original show (or its SUSFS replacement) still runs. Once swapped, the filter
 * runs for every record of that file, including after lseek/rewind, and the file
 * still opens and reads normally - it just never shows module records.
 *
 * struct proc_mounts moved around over the years: 3.4 .. 4.3 embed struct seq_file
 * at the start of proc_mounts (file->private_data is &p->m, seq_file::private stays
 * NULL), while 4.4+ use seq_open_private() and keep seq_file::private pointing at a
 * separately allocated proc_mounts. Both shapes are handled by testing
 * seq_file::private at runtime, so the filter covers the whole 3.4 .. 5.x range this
 * fork supports; the seq overflow check is shimmed for kernels older than 3.19.
 *
 * HIDE DECISION.
 * ---------------------------------------------------------
 * (is_appuid || is_isolated) && (is_isolated || ksu_uid_should_umount)
 *
 * ksu_uid_should_umount already excludes the manager, su-granted apps and the
 * webview zygote, so those keep the real view. Isolated processes are always
 * filtered (they can never legitimately need the module view, and this is what
 * defeats the zygote_next global-namespace probe).
 *
 * "Isolated" means both ranges an isolated process can land in: the app-zygote
 * range [90000, 98999] and the regular one [99000, 99999]. is_isolated_process()
 * in policy/allowlist.h spans both, so the umount path and this filter agree on
 * who counts as isolated.
 */

struct ksu_proc_mounts {
	void *ns; /* struct mnt_namespace *, never dereferenced */
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
	/* kernel-private tail omitted */
};

/*
 * Kernels before ~4.4 (before seq_open_private() was used by
 * mounts_open_common()) embed struct seq_file at the start of struct
 * proc_mounts instead of pointing seq_file::private at it. Mirror that
 * layout so the same filter covers 3.4 .. 4.3 too; the two are told apart
 * at runtime by seq_file::private being non-NULL on the newer layout.
 */
struct ksu_proc_mounts_legacy {
	struct seq_file m;
	void *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
};

typedef int (*ksu_show_fn)(struct seq_file *, struct vfsmount *);

/* seq_has_overflowed() only appeared in 3.19; use our own name to avoid
 * clashing with trees that backported it.
 */
static inline bool ksu_seq_has_overflowed(struct seq_file *m)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	return seq_has_overflowed(m);
#else
	return m->count == m->size;
#endif
}

static DEFINE_MUTEX(ksu_mount_hide_mutex);
static bool ksu_mount_hide_enabled __read_mostly = false;

/*
 * The show function each proc mount file was opened with. Set from
 * proc_mounts::show on the first read of a file, so it is whatever
 * mounts_open() installed: show_vfsmnt()/show_mountinfo()/show_vfsstat(),
 * or a SUSFS replacement. Under CFI this is a jump-table entry, which is
 * exactly what must be called back.
 */
static ksu_show_fn ksu_orig_show_vfsmnt;
static ksu_show_fn ksu_orig_show_mountinfo;
static ksu_show_fn ksu_orig_show_vfsstat;

static const char *const ksu_mount_markers[] = {
	"/adb/", "/data/adb", "kernelsu", "magisk", "zygisk", "/debug_ramdisk",
};

static const char *const ksu_stock_ancestors[] = {
	"/",	"/system", "/system_ext", "/vendor", "/product",  "/odm",   "/data",		"/mnt",		 "/storage",
	"/dev", "/proc",   "/sys",		"/apex",   "/metadata", "/cache", "/system_dlkm", "/vendor_dlkm", "/odm_dlkm",
};

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

static bool ksu_should_hide_mount_for_current(void)
{
	uid_t uid;
	bool isolated;

	if (!ksu_mount_hide_enabled)
		return false;

	uid = current_uid().val;
	isolated = is_isolated_process(uid);
	if (!is_appuid(uid) && !isolated)
		return false;
	if (!isolated && !ksu_uid_should_umount(uid))
		return false;

	return true;
}

static int __nocfi ksu_filter_show(struct seq_file *m, struct vfsmount *mnt, ksu_show_fn orig)
{
	size_t start;
	int ret;

	if (unlikely(!orig))
		return 0; /* installed before the original show was captured */

	if (!m)
		return orig(m, mnt);

	start = m->count;
	ret = orig(m, mnt);
	if (ret)
		return ret; /* SEQ_SKIP / error: seq layer handles the bytes */
	if (ksu_seq_has_overflowed(m))
		return 0; /* record truncated; seq will realloc and retry */
	if (m->count <= start)
		return 0; /* nothing emitted */

	// Decide on the READER at show time, not only at install time: an fd may
	// be handed to another process, and the feature can be toggled while a
	// file is already open.
	if (!ksu_should_hide_mount_for_current())
		return 0;

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

enum ksu_mount_file {
	KSU_MOUNT_FILE_NONE = 0,
	KSU_MOUNT_FILE_MOUNTS,
	KSU_MOUNT_FILE_MOUNTINFO,
	KSU_MOUNT_FILE_MOUNTSTATS,
};

static enum ksu_mount_file ksu_mount_file_type(struct file *file)
{
	const char *name;

	if (unlikely(!file || !file->f_path.dentry))
		return KSU_MOUNT_FILE_NONE;
	if (file->f_path.dentry->d_sb->s_magic != PROC_SUPER_MAGIC)
		return KSU_MOUNT_FILE_NONE;

	name = file->f_path.dentry->d_name.name;
	if (!name || name[0] != 'm')
		return KSU_MOUNT_FILE_NONE;
	if (!strcmp(name, "mounts"))
		return KSU_MOUNT_FILE_MOUNTS;
	if (!strcmp(name, "mountinfo"))
		return KSU_MOUNT_FILE_MOUNTINFO;
	if (!strcmp(name, "mountstats"))
		return KSU_MOUNT_FILE_MOUNTSTATS;
	return KSU_MOUNT_FILE_NONE;
}

int ksu_mount_hide_file_permission(struct file *file, int mask)
{
	struct seq_file *m;
	ksu_show_fn *orig, *slot, filter;

	if (!(mask & MAY_READ))
		return 0;
	if (unlikely(!ksu_mount_hide_enabled))
		return 0;

	switch (ksu_mount_file_type(file)) {
	case KSU_MOUNT_FILE_MOUNTS:
		orig = &ksu_orig_show_vfsmnt;
		filter = ksu_show_vfsmnt;
		break;
	case KSU_MOUNT_FILE_MOUNTINFO:
		orig = &ksu_orig_show_mountinfo;
		filter = ksu_show_mountinfo;
		break;
	case KSU_MOUNT_FILE_MOUNTSTATS:
		orig = &ksu_orig_show_vfsstat;
		filter = ksu_show_vfsstat;
		break;
	default:
		return 0;
	}

	if (!ksu_should_hide_mount_for_current())
		return 0;

	m = file->private_data;
	if (unlikely(!m))
		return 0;

	if (m->private) {
		/* 4.4+ ..: mounts_open_common() uses seq_open_private(). */
		struct ksu_proc_mounts *p = m->private;

		slot = &p->show;
	} else {
		/* 3.4 .. 4.3: seq_file is embedded in struct proc_mounts. */
		struct ksu_proc_mounts_legacy *p = (void *)m;

		slot = &p->show;
	}

	if (unlikely(!*slot))
		return 0;
	if (*slot == filter)
		return 0; /* already installed for this file */

	/*
	 * Chain to whatever mounts_open() installed. Do NOT compare it with the
	 * kallsyms address: under CFI the slot holds the function's jump-table
	 * entry (e.g. show_vfsmnt.<hash>.cfi_jt), and with SUSFS sus_mount on it
	 * holds susfs_show_vfsmnt() instead. Calling the stored pointer keeps the
	 * original filtering (and CFI) intact.
	 */
	WRITE_ONCE(*orig, *slot);
	*slot = filter;
	return 0;
}

static int mount_hide_feature_get(u64 *value)
{
	*value = ksu_mount_hide_enabled ? 1 : 0;
	return 0;
}

static int mount_hide_feature_set(u64 value)
{
	bool enable = value != 0;

	pr_info("mount_hide: set to %d\n", enable);
	mutex_lock(&ksu_mount_hide_mutex);
	ksu_mount_hide_enabled = enable;
	mutex_unlock(&ksu_mount_hide_mutex);
	return 0;
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
}

void __exit ksu_mount_hide_exit(void)
{
	mutex_lock(&ksu_mount_hide_mutex);
	ksu_mount_hide_enabled = false;
	mutex_unlock(&ksu_mount_hide_mutex);
	ksu_unregister_feature_handler(KSU_FEATURE_MOUNT_HIDE);
}
