
#include <asm/ptrace.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/static_key.h>
#include <linux/slab.h>

#include "adb_root.h"
#include "arch.h"
#include "policy/feature.h"
#include "selinux/selinux.h"

#include "klog.h" // IWYU pragma: keep

DEFINE_STATIC_KEY_FALSE(ksu_adb_root);

static long is_exec_adbd(struct pt_regs *regs)
{
    static const char kAdbd[] = "/adbd";
    static const size_t kAdbdLen = sizeof(kAdbd) - 1;
    char __user *filename_user = (char __user *)PT_REGS_PARM1(regs);
    // should be bigger than `/apex/com.android.adbd/bin/adbd`
    char buf[40];
    char __user *fn;
    long ret;
    fn = (char __user *)untagged_addr((unsigned long)filename_user);
    memset(buf, 0, sizeof(buf));

    ret = strncpy_from_user(buf, fn, sizeof(buf));
    if (ret < 0) {
        pr_warn("Access filename when adb_root_handle_execve failed: %ld\n", ret);
        return ret;
    }

    // strncpy_from_user may copy `sizeof(buf)` bytes
    if (ret < kAdbdLen || ret >= sizeof(buf) || memcmp(buf + ret - kAdbdLen, kAdbd, kAdbdLen + 1) != 0) {
        return 0;
    }

    return 1;
}

static long is_libadbroot_ok()
{
    static const char kLibAdbRoot[] = "/data/adb/ksu/lib/libadbroot.so";
    struct path path;
    long ret = kern_path(kLibAdbRoot, 0, &path);
    if (ret < 0) {
        if (ret == -ENOENT) {
            pr_err("libadbroot.so not exists, skip adb root. Please run `ksud install`\n");
            ret = 0;
        } else {
            pr_err("access libadbroot.so failed: %ld, skip adb root\n", ret);
        }
        return ret;
    } else {
        ret = 1;
    }
    path_put(&path);
    return ret;
}

/*
 * Reads a NUL-terminated user-space string into a fresh kernel buffer.
 * Returns NULL if it's missing, unreadable, or longer than the cap.
 */
static char *dup_user_env_string(unsigned long uptr)
{
    static const size_t kMaxEnvValueLen = 4096;
    char *buf;
    long len;

    buf = kmalloc(kMaxEnvValueLen, GFP_KERNEL);
    if (!buf)
        return NULL;

    len = strncpy_from_user(buf, (const char __user *)uptr, kMaxEnvValueLen);
    if (len < 0 || (size_t)len >= kMaxEnvValueLen) {
        kfree(buf);
        return NULL;
    }

    return buf;
}

static bool env_entry_matches(const char *entry, const char *name)
{
    size_t name_len = strlen(name);

    return strncmp(entry, name, name_len) == 0 && entry[name_len] == '=';
}

static char *build_env_string(const char *name, const char *value)
{
    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    size_t total_len = name_len + 1 + value_len + 1; /* NAME=VALUE\0 */
    char *out = kmalloc(total_len, GFP_KERNEL);

    if (!out)
        return NULL;

    memcpy(out, name, name_len);
    out[name_len] = '=';
    memcpy(out + name_len + 1, value, value_len);
    out[total_len - 1] = '\0';
    return out;
}

/* "NAME=<existing's value>:<extra_value>", reusing an already-present entry */
static char *merge_env_value(const char *existing_entry, const char *name, const char *extra_value)
{
    size_t name_len = strlen(name);
    const char *existing_value = existing_entry + name_len + 1;
    size_t existing_len = strlen(existing_value);
    size_t extra_len = strlen(extra_value);
    size_t total_len = name_len + 1 + existing_len + 1 + extra_len + 1; /* NAME=existing:extra\0 */
    char *out = kmalloc(total_len, GFP_KERNEL);

    if (!out)
        return NULL;

    memcpy(out, name, name_len);
    out[name_len] = '=';
    memcpy(out + name_len + 1, existing_value, existing_len);
    out[name_len + 1 + existing_len] = ':';
    memcpy(out + name_len + 1 + existing_len + 1, extra_value, extra_len);
    out[total_len - 1] = '\0';
    return out;
}

static long setup_ld_preload(struct pt_regs *regs)
{
    static const char kLdPreloadName[] = "LD_PRELOAD";
    static const char kLdPreloadValue[] = "/data/adb/ksu/lib/libadbroot.so";
    static const char kLdLibraryPathName[] = "LD_LIBRARY_PATH";
    static const char kLdLibraryPathValue[] = "/data/adb/ksu/lib";
    static const size_t kReadEnvBatch = 16;
    static const size_t kPtrSize = sizeof(unsigned long);
    unsigned long stackp = user_stack_pointer(regs);
    unsigned long envp, ld_preload_p, ld_library_path_p;
    unsigned long *envp_p = (unsigned long *)&PT_REGS_PARM3(regs);
    unsigned long *tmp_env_p = NULL, *tmp_env_p2 = NULL;
    char *ld_preload_str = NULL, *ld_library_path_str = NULL, *merged;
    long ld_preload_idx = -1, ld_library_path_idx = -1;
    size_t env_count = 0, total_size, i;
    long ret;

    envp = (char __user **)untagged_addr((unsigned long)*envp_p);

    for (;;) {
        tmp_env_p2 = krealloc(tmp_env_p, (env_count + kReadEnvBatch + 2) * kPtrSize, GFP_KERNEL);
        if (tmp_env_p2 == NULL) {
            pr_err("alloc tmp env failed\n");
            ret = -ENOMEM;
            goto out_release_env_p;
        }
        tmp_env_p = tmp_env_p2;
        ret = copy_from_user(&tmp_env_p[env_count], envp + env_count * kPtrSize, kReadEnvBatch * kPtrSize);
        if (ret < 0) {
            pr_warn("Access envp when adb_root_handle_execve failed: %ld\n", ret);
            ret = -EFAULT;
            goto out_release_env_p;
        }
        size_t read_count = kReadEnvBatch * kPtrSize - ret;
        size_t max_new_env_count = read_count / kPtrSize, new_env_count = 0;
        bool meet_zero = false;
        for (; new_env_count < max_new_env_count; new_env_count++) {
            if (!tmp_env_p[new_env_count + env_count]) {
                meet_zero = true;
                break;
            }
        }
        if (!meet_zero) {
            if (read_count % kPtrSize != 0) {
                pr_err("unaligned envp array!\n");
                ret = -EFAULT;
                goto out_release_env_p;
            } else if (ret != 0) {
                pr_err("truncated envp array!\n");
                ret = -EFAULT;
                goto out_release_env_p;
            }
        }
        env_count += new_env_count;
        if (meet_zero)
            break;
    }

    /*
     * Reuse an existing LD_PRELOAD / LD_LIBRARY_PATH if adbd's environment
     * already set one, instead of appending a second, conflicting entry.
     */
    for (i = 0; i < env_count; i++) {
        char *val;

        if (ld_preload_idx >= 0 && ld_library_path_idx >= 0)
            break;

        val = dup_user_env_string(tmp_env_p[i]);
        if (!val)
            continue;

        if (ld_preload_idx < 0 && env_entry_matches(val, kLdPreloadName)) {
            ld_preload_str = val;
            ld_preload_idx = (long)i;
            continue;
        }
        if (ld_library_path_idx < 0 && env_entry_matches(val, kLdLibraryPathName)) {
            ld_library_path_str = val;
            ld_library_path_idx = (long)i;
            continue;
        }
        kfree(val);
    }

    if (ld_preload_str) {
        merged = merge_env_value(ld_preload_str, kLdPreloadName, kLdPreloadValue);
        kfree(ld_preload_str);
        ld_preload_str = merged;
    } else {
        ld_preload_str = build_env_string(kLdPreloadName, kLdPreloadValue);
    }
    if (!ld_preload_str) {
        ret = -ENOMEM;
        goto out_release_env_p;
    }

    if (ld_library_path_str) {
        merged = merge_env_value(ld_library_path_str, kLdLibraryPathName, kLdLibraryPathValue);
        kfree(ld_library_path_str);
        ld_library_path_str = merged;
    } else {
        ld_library_path_str = build_env_string(kLdLibraryPathName, kLdLibraryPathValue);
    }
    if (!ld_library_path_str) {
        ret = -ENOMEM;
        goto out_release_ld_preload_str;
    }

    ld_preload_p = stackp = ALIGN_DOWN(stackp - (strlen(ld_preload_str) + 1), 8);
    ret = copy_to_user(ld_preload_p, ld_preload_str, strlen(ld_preload_str) + 1);
    if (ret != 0) {
        pr_warn("write ld_preload when adb_root_handle_execve failed: %ld\n", ret);
        ret = -EFAULT;
        goto out_release_ld_library_path_str;
    }

    ld_library_path_p = stackp = ALIGN_DOWN(stackp - (strlen(ld_library_path_str) + 1), 8);
    ret = copy_to_user(ld_library_path_p, ld_library_path_str, strlen(ld_library_path_str) + 1);
    if (ret != 0) {
        pr_warn("write ld_library_path when adb_root_handle_execve failed: %ld\n", ret);
        ret = -EFAULT;
        goto out_release_ld_library_path_str;
    }

    if (ld_preload_idx >= 0)
        tmp_env_p[ld_preload_idx] = ld_preload_p;
    else
        tmp_env_p[env_count++] = ld_preload_p;

    if (ld_library_path_idx >= 0)
        tmp_env_p[ld_library_path_idx] = ld_library_path_p;
    else
        tmp_env_p[env_count++] = ld_library_path_p;

    tmp_env_p[env_count++] = 0;
    total_size = env_count * kPtrSize;

    stackp -= total_size;
    ret = copy_to_user(stackp, tmp_env_p, total_size);
    if (ret != 0) {
        pr_err("copy new env failed: %ld\n", ret);
        ret = -EFAULT;
        goto out_release_ld_library_path_str;
    }

    *envp_p = stackp;
    ret = 0;

out_release_ld_library_path_str:
    kfree(ld_library_path_str);
out_release_ld_preload_str:
    kfree(ld_preload_str);
out_release_env_p:
    if (tmp_env_p) {
        kfree(tmp_env_p);
    }

    return ret;
}

static long do_ksu_adb_root_handle_execve(struct pt_regs *regs)
{
    if (likely(is_exec_adbd(regs) != 1)) {
        return 0;
    }

    if (unlikely(is_libadbroot_ok() != 1)) {
        return 0;
    }

    long ret = setup_ld_preload(regs);
    if (ret) {
        return ret;
    }

    pr_info("escape to root for adb\n");
    escape_to_root_for_adb_root();
    return 0;
}

long ksu_adb_root_handle_execve(struct pt_regs *regs)
{
    if (static_branch_unlikely(&ksu_adb_root)) {
        return do_ksu_adb_root_handle_execve(regs);
    }
    return 0;
}

static int kernel_adb_root_feature_get(u64 *value)
{
    *value = static_key_enabled(&ksu_adb_root) ? 1 : 0;
    return 0;
}

static int kernel_adb_root_feature_set(u64 value)
{
    bool enable = value != 0;
    if (enable) {
        static_key_enable(&ksu_adb_root.key);
    } else {
        static_key_disable(&ksu_adb_root.key);
    }
    pr_info("adb_root: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler ksu_adb_root_handler = {
    .feature_id = KSU_FEATURE_ADB_ROOT,
    .name = "adb_root",
    .get_handler = kernel_adb_root_feature_get,
    .set_handler = kernel_adb_root_feature_set,
};

void __init ksu_adb_root_init(void)
{
    if (ksu_register_feature_handler(&ksu_adb_root_handler)) {
        pr_err("Failed to register adb_root feature handler\n");
    }
}

void __exit ksu_adb_root_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_ADB_ROOT);
}
