# sukisu-fs

A stacking filesystem module for KernelSU that exposes a per-uid view
of an existing directory tree.

## Design

Unlike the full sukisu-fs described in the project design doc, this
implementation is **stacking-only**: it does not introduce a new
on-disk format. Instead it sits on top of an existing mount
(e.g. `/data/adb`) and forwards every inode/file/dir operation to
the underlying real filesystem. What it adds is a per-uid visibility
layer driven by a small rule table.

The control surface is a set of ioctls on the existing KSU
supercall fd (`KSU_IOCTL_SUKISU_FS_*`, see `uapi/sukisu_fs.h`).

## Files

| File | Role |
|------|------|
| `sukisu_fs.h`        | internal header (structs, function exports) |
| `sukisu_fs.c`        | registration, fs_context, super_operations |
| `sukisu_fs_rule.c`   | uid-visibility rule table |
| `sukisu_fs_inode.c`  | inode operations (lookup, create, mkdir, unlink, rename, getattr, setattr) |
| `sukisu_fs_file.c`   | file operations (open, read, write, fsync, llseek) |
| `sukisu_fs_dir.c`    | readdir with per-uid filtering |
| `sukisu_fs_ioctl.c`  | ioctl dispatch helpers |

## Usage

From `ksud`:

```text
ksud sukisu-fs mount <source> <target>   # mount the layer
ksud sukisu-fs umount <target>            # tear it down
ksud sukisu-fs rule-add --view HIDE --uid-min 10000 --uid-max 19999 /data/adb/secret
ksud sukisu-fs rule-rm /data/adb/secret
ksud sukisu-fs rule-clear
ksud sukisu-fs rule-list
```

The mount step requires that the user also runs the standard Linux
`mount(2)` syscall against the `sukisu` filesystem type, e.g.

```sh
mount -t sukisu -o source=/data/adb /data/adb /data/adb/sukisu
```

The kernel-side `KSU_IOCTL_SUKISU_FS_MOUNT` only validates the
parameters and stores the requested layer; the actual `mount(2)` is
performed by userspace.

## Visibility model

Rules are matched against absolute paths inside the sukisu-fs mount.
The first matching rule wins.

- `HIDE <range> <path>`: the path (and everything below it) becomes
  invisible to UIDs in `<range>`.
- `SHOW <range> <path>`: the path becomes visible *only* to UIDs in
  `<range>`.

A UID outside any matching rule sees the unmodified underlying
filesystem.

## Kernel version matrix

| Kernel | Status | Notes |
|--------|--------|-------|
| 5.10   | ✅      | idmap = `user_namespace*` |
| 5.15   | ✅      | main target |
| 6.1    | ✅      | idmap = `mnt_idmap*` |
| 6.6    | ✅      | idmap = `mnt_idmap*` |
| 6.12   | ✅ (fs) | sukisu-fs compiles; the su-* sibling (sukisu-sus) needs v2 for static-call LSM hooks |
| 6.18   | ✅ (fs) | iterate_dir / vfs_iocb_read|write still work as wired |

sukisu-fs (this module) is intentionally a pure stacking filesystem
that uses only the stable VFS surface (`vfs_getattr`, `vfs_setattr`,
`vfs_read`, `vfs_write`, `vfs_create`, `vfs_mkdir`, `vfs_unlink`,
`vfs_rename`, `lookup_one_len`, `iterate_dir`, `filp_open`).
None of those have been removed in 6.12 or 6.18, so the same .o
files build unchanged against the full matrix.

