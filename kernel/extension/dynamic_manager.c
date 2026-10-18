// SPDX-License-Identifier: GPL-2.0
/*
 * Dynamic manager subsystem (consolidated from kernel/manager/dynamic_manager.c).
 *
 * Implements ksu_dynamic_manager_{get,set}, ksu_dynamic_manager_match,
 * ksu_dynamic_manager_verify_apk, etc., AND the KSU_EXTENSION_DYNAMIC_MANAGER
 * extension wiring.
 *
 * The two responsibilities share state: getting the sticky-state bit
 * reads dynamic_manager_enabled, and the io op forwards to the same
 * set/get code paths that manager UI used to call via KSU_IOCTL_MANAGER.
 */
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/kernel.h>

#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "extension/dynamic_manager.h"
#include "manager/manager_identity.h"
#include "manager/apk_sign.h"
#include "manager/throne_tracker.h"

#define DYNAMIC_MANAGER_FILE "/data/adb/ksu/.dynamic_managers"
#define DYNAMIC_MANAGER_MAGIC 0x4d534b44
#define DYNAMIC_MANAGER_VERSION 1
#define DYNAMIC_MANAGER_MAX_CERT_SIZE 1024

struct dynamic_manager_state {
    __u32 magic;
    __u32 version;
    __u32 enabled;
    __u32 count;
    struct ksu_manager_entry entries[KSU_MAX_DYNAMIC_MANAGERS];
};

static DEFINE_RWLOCK(dynamic_manager_lock);
static DEFINE_MUTEX(dynamic_manager_update_lock);
bool dynamic_manager_enabled = false;
static struct ksu_manager_entry dynamic_managers[KSU_MAX_DYNAMIC_MANAGERS];
static bool dynamic_manager_verified[KSU_MAX_DYNAMIC_MANAGERS];
static __u32 dynamic_manager_count;

bool ksu_manager_enabled(void)
{
    return READ_ONCE(dynamic_manager_enabled);
}

static bool hash_valid(const char *hash)
{
    int i;

    if (strnlen(hash, KSU_MANAGER_HASH_LENGTH + 1) != KSU_MANAGER_HASH_LENGTH)
        return false;
    for (i = 0; i < KSU_MANAGER_HASH_LENGTH; ++i) {
        if (!isxdigit(hash[i]))
            return false;
    }
    return true;
}

static bool package_valid(const char *package)
{
    size_t len = strnlen(package, KSU_MANAGER_PACKAGE_LENGTH);

    if (!len || len >= KSU_MANAGER_PACKAGE_LENGTH || !isalpha(package[0]))
        return false;
    while (*package) {
        if (!isalnum(*package) && *package != '_' && *package != '.')
            return false;
        ++package;
    }
    return true;
}

static int find_manager_locked(const char *package)
{
    unsigned int i;

    for (i = 0; i < dynamic_manager_count; ++i) {
        if (!strcmp(dynamic_managers[i].package, package))
            return i;
    }
    return -ENOENT;
}

static void clear_managers_locked(void)
{
    memset(dynamic_managers, 0, sizeof(dynamic_managers));
    memset(dynamic_manager_verified, 0, sizeof(dynamic_manager_verified));
    dynamic_manager_count = 0;
}

bool ksu_manager_package_authorized(const char *package, uid_t uid)
{
    int index;
    bool found = false;

    if (ksu_manager_appid != KSU_INVALID_APPID &&
        ksu_manager_appid == uid % KSU_PER_USER_RANGE)
        return true;
    read_lock(&dynamic_manager_lock);
    if (READ_ONCE(dynamic_manager_enabled)) {
        index = find_manager_locked(package);
        found = index >= 0 && dynamic_manager_verified[index] &&
                dynamic_managers[index].uid == uid % KSU_PER_USER_RANGE;
    }
    read_unlock(&dynamic_manager_lock);
    return found;
}

bool ksu_dynamic_manager_uid_registered(uid_t uid)
{
    unsigned int i;
    bool found = false;
    uid_t appid = uid % KSU_PER_USER_RANGE;

    read_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (dynamic_managers[i].uid == appid) {
            found = true;
            break;
        }
    }
    read_unlock(&dynamic_manager_lock);
    return found;
}

bool ksu_manager_uid_authorized(uid_t uid)
{
    uid_t appid = uid % KSU_PER_USER_RANGE;

    if (ksu_manager_appid != KSU_INVALID_APPID && ksu_manager_appid == appid)
        return true;
    return ksu_manager_enabled() && ksu_dynamic_manager_uid_registered(uid);
}

void ksu_dynamic_manager_load(void)
{
    struct dynamic_manager_state *state;
    struct file *fp;
    loff_t pos = 0;
    ssize_t read;
    unsigned int i;

    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state)
        return;
    fp = filp_open(DYNAMIC_MANAGER_FILE, O_RDONLY, 0);
    if (IS_ERR(fp))
        goto out;
    read = kernel_read(fp, state, sizeof(*state), &pos);
    filp_close(fp, NULL);
    if (read != sizeof(*state) || state->magic != DYNAMIC_MANAGER_MAGIC ||
        state->version != DYNAMIC_MANAGER_VERSION ||
        state->count > KSU_MAX_DYNAMIC_MANAGERS || state->enabled > 1)
        goto out;

    for (i = 0; i < state->count; ++i) {
        const struct ksu_manager_entry *entry = &state->entries[i];

        if (!entry->cert_size ||
            entry->cert_size > DYNAMIC_MANAGER_MAX_CERT_SIZE ||
            !package_valid(entry->package) || !hash_valid(entry->hash))
            goto out;
    }
    write_lock(&dynamic_manager_lock);
    WRITE_ONCE(dynamic_manager_enabled, !!state->enabled);
    dynamic_manager_count = state->count;
    memcpy(dynamic_managers, state->entries, sizeof(dynamic_managers));
    memset(dynamic_manager_verified, 0, sizeof(dynamic_manager_verified));
    write_unlock(&dynamic_manager_lock);
    goto free_state;
out:
    write_lock(&dynamic_manager_lock);
    WRITE_ONCE(dynamic_manager_enabled, false);
    dynamic_manager_count = 0;
    clear_managers_locked();
    write_unlock(&dynamic_manager_lock);
free_state:
    kfree(state);
}

int ksu_dynamic_manager_set(struct ksu_manager_cmd *cmd)
{
    struct ksu_manager_entry entry = {};
    int i;
    uid_t package_uid = KSU_INVALID_APPID;
    int ret = 0;

    if (!cmd || cmd->count > KSU_MAX_DYNAMIC_MANAGERS || cmd->enabled > 1)
        return -EINVAL;

    if (cmd->operation == KSU_MANAGER_ADD) {
        if (!cmd->cert_size ||
            cmd->cert_size > DYNAMIC_MANAGER_MAX_CERT_SIZE ||
            strnlen(cmd->package, sizeof(cmd->package)) >=
                sizeof(cmd->package) ||
            strnlen(cmd->hash, sizeof(cmd->hash)) >= sizeof(cmd->hash) ||
            !package_valid(cmd->package) || !hash_valid(cmd->hash) ||
            cmd->uid == KSU_INVALID_APPID)
            return -EINVAL;
        package_uid = cmd->uid % KSU_PER_USER_RANGE;
    }

    mutex_lock(&dynamic_manager_update_lock);
    write_lock(&dynamic_manager_lock);
    switch (cmd->operation) {
    case KSU_MANAGER_SET_ENABLED:
        WRITE_ONCE(dynamic_manager_enabled, !!cmd->enabled);
        break;
    case KSU_MANAGER_ADD:
        entry.cert_size = cmd->cert_size;
        entry.uid = package_uid;
        strscpy(entry.package, cmd->package, sizeof(entry.package));
        strscpy(entry.hash, cmd->hash, sizeof(entry.hash));
        i = find_manager_locked(entry.package);
        if (i >= 0) {
            dynamic_managers[i] = entry;
            dynamic_manager_verified[i] = false;
            break;
        }
        if (dynamic_manager_count == KSU_MAX_DYNAMIC_MANAGERS) {
            ret = -ENOSPC;
            break;
        }
        dynamic_managers[dynamic_manager_count++] = entry;
        dynamic_manager_verified[dynamic_manager_count - 1] = false;
        break;
    case KSU_MANAGER_REMOVE:
        if (strnlen(cmd->package, sizeof(cmd->package)) >=
                sizeof(cmd->package) ||
            !package_valid(cmd->package)) {
            ret = -EINVAL;
            break;
        }
        if (cmd->hash[0] &&
            strnlen(cmd->hash, sizeof(cmd->hash)) >= sizeof(cmd->hash)) {
            ret = -EINVAL;
            break;
        }
        i = find_manager_locked(cmd->package);
        if (i >= 0) {
            --dynamic_manager_count;
            dynamic_managers[i] =
                dynamic_managers[dynamic_manager_count];
            dynamic_manager_verified[i] =
                dynamic_manager_verified[dynamic_manager_count];
            memset(&dynamic_managers[dynamic_manager_count], 0,
                   sizeof(dynamic_managers[0]));
            dynamic_manager_verified[dynamic_manager_count] = false;
        }
        break;
    case KSU_MANAGER_CLEAR:
        clear_managers_locked();
        break;
    default:
        ret = -EINVAL;
        break;
    }
    write_unlock(&dynamic_manager_lock);
    mutex_unlock(&dynamic_manager_update_lock);
    if (!ret)
        track_throne(false);
    return ret;
}

int ksu_dynamic_manager_get(struct ksu_manager_cmd *cmd)
{
    if (!cmd)
        return -EINVAL;
    read_lock(&dynamic_manager_lock);
    cmd->enabled = dynamic_manager_enabled;
    cmd->count = dynamic_manager_count;
    memcpy(cmd->entries, dynamic_managers, sizeof(dynamic_managers));
    read_unlock(&dynamic_manager_lock);
    return 0;
}

bool ksu_dynamic_manager_match(const char *package, unsigned int size,
                               const char *hash)
{
    unsigned int i;
    bool found = false;

    if (!ksu_manager_enabled())
        return false;

    read_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (dynamic_managers[i].cert_size == size &&
            !strcmp(dynamic_managers[i].package, package) &&
            !strncasecmp(dynamic_managers[i].hash, hash,
                         KSU_MANAGER_HASH_LENGTH)) {
            found = true;
            break;
        }
    }
    read_unlock(&dynamic_manager_lock);
    return found;
}

void ksu_dynamic_manager_reset_verification(void)
{
    write_lock(&dynamic_manager_lock);
    memset(dynamic_manager_verified, 0, sizeof(dynamic_manager_verified));
    write_unlock(&dynamic_manager_lock);
}

int ksu_dynamic_manager_uid_for_package(const char *package, uid_t *uid)
{
    int index;

    if (!package || !uid)
        return -EINVAL;

    read_lock(&dynamic_manager_lock);
    index = find_manager_locked(package);
    if (index >= 0)
        *uid = dynamic_managers[index].uid;
    read_unlock(&dynamic_manager_lock);
    return index < 0 ? -ENOENT : 0;
}

bool ksu_dynamic_manager_package_registered(const char *package)
{
    int index;

    if (!package)
        return false;
    read_lock(&dynamic_manager_lock);
    index = find_manager_locked(package);
    read_unlock(&dynamic_manager_lock);
    return index >= 0;
}

bool ksu_dynamic_manager_verify_apk(char *path, const char *package, uid_t uid)
{
    struct ksu_manager_entry entry = {};
    unsigned int i;
    bool found = false;

    read_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (!strcmp(dynamic_managers[i].package, package) &&
            dynamic_managers[i].uid == uid % KSU_PER_USER_RANGE) {
            entry = dynamic_managers[i];
            found = true;
            break;
        }
    }
    read_unlock(&dynamic_manager_lock);
    if (!found ||
        !ksu_check_apk_signature(path, entry.cert_size, entry.hash))
        return false;

    write_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (!memcmp(&dynamic_managers[i], &entry, sizeof(entry))) {
            dynamic_manager_verified[i] = true;
            break;
        }
    }
    write_unlock(&dynamic_manager_lock);
    return true;
}

int ksu_extension_dynamic_manager_get(u32 id, u64 *value)
{
    *value = ksu_manager_enabled() ? 1 : 0;
    return 0;
}

int ksu_extension_dynamic_manager_set(u32 id, u64 value)
{
    struct ksu_manager_cmd *cmd;
    bool want_enabled = value != 0;
    int ret;

    if (want_enabled == ksu_manager_enabled())
        return 0;

    cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
    if (!cmd)
        return -ENOMEM;

    cmd->operation = KSU_MANAGER_SET_ENABLED;
    cmd->enabled = want_enabled ? 1 : 0;
    cmd->count = 0;
    ret = ksu_dynamic_manager_set(cmd);
    kfree(cmd);
    return ret;
}

const struct ksu_extension_handler_ops ksu_extension_dynamic_manager_ops = {
    .get = ksu_extension_dynamic_manager_get,
    .set = ksu_extension_dynamic_manager_set,
};

int ksu_extension_dynamic_manager_io(u32 id, void __user *raw)
{
    struct ksu_manager_cmd *cmd;
    int ret;

#ifdef CONFIG_KSU_DISABLE_MANAGER
    (void)raw;
    return -EOPNOTSUPP;
#else
    cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
    if (!cmd)
        return -ENOMEM;

    if (copy_from_user(cmd, raw, sizeof(*cmd))) {
        ret = -EFAULT;
        goto out;
    }

    if (cmd->operation == KSU_MANAGER_GET) {
        ret = ksu_dynamic_manager_get(cmd);
        if (!ret && copy_to_user(raw, cmd, sizeof(*cmd)))
            ret = -EFAULT;
        goto out;
    }
    ret = ksu_dynamic_manager_set(cmd);

out:
    kfree(cmd);
    return ret;
#endif
}
