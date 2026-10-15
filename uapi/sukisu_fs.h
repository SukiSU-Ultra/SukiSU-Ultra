#ifndef __KSU_UAPI_SUKISU_FS_H
#define __KSU_UAPI_SUKISU_FS_H

#include <linux/ioctl.h>
#include <linux/types.h>

/*
 * sukisu-fs UAPI
 *
 * sukisu-fs is a virtual filesystem layered on top of an existing mount
 * (e.g. /data/adb) that provides a per-uid view of the directory tree.
 * It does NOT have a backing image - operations are forwarded to a real
 * underlying filesystem and only the visibility layer (readdir/getattr
 * and selected lookups) is virtualized.
 *
 * The control surface is exposed through three ioctls on the KSU
 * supercall fd:
 *   KSU_IOCTL_SUKISU_FS_MOUNT  - register a new sukisu-fs mount point
 *   KSU_IOCTL_SUKISU_FS_UMOUNT - unregister an existing mount point
 *   KSU_IOCTL_SUKISU_FS_RULE   - add / remove / list uid-view rules
 *
 * Mount points are addressed by a path that must already exist on a
 * real filesystem. sukisu-fs only changes the visibility, not the
 * underlying storage.
 */

#define SUKISU_FS_MAX_MOUNTS 16
#define SUKISU_FS_MAX_RULES 256
#define SUKISU_FS_MAX_PATH 256
#define SUKISU_FS_MAX_NAME 128

/* Operations on a single rule */
#define SUKISU_FS_RULE_ADD 1
#define SUKISU_FS_RULE_REMOVE 2
#define SUKISU_FS_RULE_LIST 3
#define SUKISU_FS_RULE_CLEAR 4

/* View mode - controls how a rule affects uid visibility */
#define SUKISU_FS_VIEW_HIDE 0  /* entry is invisible to the target uids */
#define SUKISU_FS_VIEW_SHOW 1  /* entry is only visible to the target uids */

/* A single visibility rule.
 *
 *  path     - absolute path (or path prefix) the rule applies to
 *  view     - SUKISU_FS_VIEW_HIDE or SUKISU_FS_VIEW_SHOW
 *  uid_min  - inclusive lower bound of the matching uid range
 *  uid_max  - inclusive upper bound of the matching uid range
 *
 * Both uid bounds are interpreted against the *real* (unmodified) uid
 * as seen by the kernel, i.e. uid % 100000. The rules therefore
 * naturally cover all users in the system.
 */
struct sukisu_fs_rule {
    __u32 view;
    __u32 uid_min;
    __u32 uid_max;
    char path[SUKISU_FS_MAX_PATH];
};

/* Mount registration request.
 *
 *  source - the existing on-disk directory sukisu-fs will layer over
 *  target - the desired mount point (created by the kernel on mount)
 *
 * On KSU_IOCTL_SUKISU_FS_MOUNT the kernel invokes fs_context based
 * mount internally; on KSU_IOCTL_SUKISU_FS_UMOUNT only `target` is
 * used and `source` is ignored.
 */
struct sukisu_fs_mount_cmd {
    char source[SUKISU_FS_MAX_PATH];
    char target[SUKISU_FS_MAX_PATH];
};

/* Rule operation request.
 *
 *  operation - SUKISU_FS_RULE_*
 *  rule      - populated for ADD/REMOVE; ignored for LIST/CLEAR
 *  index     - populated for LIST: index of the returned rule
 *  total     - populated for LIST: total number of stored rules
 */
struct sukisu_fs_rule_cmd {
    __u32 operation;
    __u32 index;
    __u32 total;
    struct sukisu_fs_rule rule;
};

#endif
