// SPDX-License-Identifier: GPL-2.0
#ifndef __KSU_H_SUKISU_FS
#define __KSU_H_SUKISU_FS

#include <linux/types.h>
#include <linux/version.h>
#include "uapi/sukisu_fs.h"

/* Versioning / compat shims.
 *
 * The supported matrix:
 *   - 5.10 / 5.15  : idmap = user_namespace*  (pre-6.3)
 *   - 6.1  / 6.6   : idmap = mnt_idmap*       (6.3+)
 *   - 6.12         : idmap = mnt_idmap* + static-call LSM hooks
 *                    (sukisu-fs itself does not depend on LSM hooks,
 *                     only the su-* sibling does)
 *   - 6.18         : idmap = mnt_idmap* + minor kiocb / iterate tweaks
 *                    (covered by the LINUX_VERSION_CODE guards below)
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
typedef struct mnt_idmap *sukisu_idmap_t;
#else
typedef struct user_namespace *sukisu_idmap_t;
#endif

/* read_iter / write_iter changed calling convention in 6.12: the
 * struct kiocb argument is read-mostly; the same signature works
 * for 5.10..6.18 today, but leave a marker here in case 6.20+ ever
 * moves to iov_iter-based dispatch without kiocb. */
#define SUKISU_FS_KIOCB_ITER_OK 1

/* iterate_dir() vs iterate_shared() — sukisu-fs only operates on
 * directories owned by a single mount, so iterate_dir is safe across
 * the entire 5.10..6.18 matrix. */
#define SUKISU_FS_USE_ITERATE_DIR 1

/* folio API migration: we are read-write capable but the only
 * address_space we touch is the underlying file's, so we never
 * need to call read_folio / write_begin directly. */
#define SUKISU_FS_NEEDS_FOLIO_API 0

/*
 * sukisu-fs internal header
 *
 * sukisu-fs is a stacking filesystem: it has no on-disk format of its
 * own. Instead it sits on top of an existing mount and forwards every
 * inode/file/dir operation to the underlying real filesystem. What it
 * adds is a per-uid visibility layer driven by a small rule table.
 *
 *   - readdir() filters out entries that the caller's uid is not
 *     supposed to see (HIDE) or hides them from every other uid
 *     (SHOW, i.e. an "only this uid range can see" rule).
 *   - lookup() and getattr() return -ENOENT for hidden entries so
 *     that a process cannot even open a file it cannot list.
 *
 * The control surface is a set of ioctls (KSU_IOCTL_SUKISU_FS_*) on
 * the existing KSU supercall fd, see uapi/sukisu_fs.h.
 */

struct path;

#define SUKISU_FS_MAGIC 0x534B5355 /* "SKSU" */

void sukisu_fs_init(void);
void sukisu_fs_exit(void);

/* Rule table API - implemented in sukisu_fs_rule.c */
int sukisu_fs_rule_add(const struct sukisu_fs_rule *rule);
int sukisu_fs_rule_remove(const char *path);
void sukisu_fs_rule_clear(void);
u32 sukisu_fs_rule_get_count(void);
int sukisu_fs_rule_get_at(u32 index, struct sukisu_fs_rule *out);

/* True when at least one sukisu-fs mount is currently active. */
bool sukisu_fs_is_active(void);

/* Return the sukisu-fs superblock (used by readdir callback) */
struct super_block *sukisu_fs_get_sb(void);

/* Acquire a reference to the underlying inode of the given dentry's
 * path inside a sukisu-fs mount. Returns 0 on success, -errno on
 * failure. The inode is wrapped; the caller does not own an
 * additional reference. */
struct inode *sukisu_fs_get_inode(struct super_block *sb, struct inode *under);

/* Rebuild and cache the absolute path for a dentry. Returns 0 on
 * success, -errno on failure. The path is stored on the inode. */
int sukisu_fs_revalidate_path_for(struct dentry *dentry);

/* Apply uid view rules to a path lookup.
 * Returns true if the path should be hidden from current_uid().
 */
bool sukisu_fs_should_hide_path(const char *path, unsigned int path_len);

bool sukisu_fs_match_rule(const char *full_path, unsigned int path_len);

#endif
