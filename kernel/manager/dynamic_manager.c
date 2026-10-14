// SPDX-License-Identifier: GPL-2.0
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "klog.h"
#include "manager/manager_identity.h"
#include "manager/apk_sign.h"
#include "manager/throne_tracker.h"
#include "uapi/supercall.h"

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

static DEFINE_MUTEX(dynamic_manager_lock);
static bool dynamic_manager_enabled = true;
static struct ksu_manager_entry dynamic_managers[KSU_MAX_DYNAMIC_MANAGERS];
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

bool ksu_manager_package_authorized(const char *package, uid_t uid)
{
    unsigned int i;
    bool found = false;

    if (ksu_manager_appid != KSU_INVALID_APPID && ksu_manager_appid == uid % KSU_PER_USER_RANGE)
        return true;
    if (!ksu_manager_enabled())
        return false;

    mutex_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (dynamic_managers[i].uid == uid % KSU_PER_USER_RANGE &&
            !strcmp(dynamic_managers[i].package, package)) {
            found = true;
            break;
        }
    }
    mutex_unlock(&dynamic_manager_lock);
    return found;
}

bool ksu_manager_uid_authorized(uid_t uid)
{
    unsigned int i;
    bool found = false;
    uid_t appid = uid % KSU_PER_USER_RANGE;

    if (ksu_manager_appid != KSU_INVALID_APPID && ksu_manager_appid == appid)
        return true;
    if (!ksu_manager_enabled())
        return false;

    mutex_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (dynamic_managers[i].uid == appid) {
            found = true;
            break;
        }
    }
    mutex_unlock(&dynamic_manager_lock);
    return found;
}

static int save_state_locked(void)
{
    struct dynamic_manager_state *state;
    struct file *fp;
    loff_t pos = 0;
    ssize_t written;
    int ret = 0;

    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state)
        return -ENOMEM;
    state->magic = DYNAMIC_MANAGER_MAGIC;
    state->version = DYNAMIC_MANAGER_VERSION;
    state->enabled = dynamic_manager_enabled;
    state->count = dynamic_manager_count;
    memcpy(state->entries, dynamic_managers, sizeof(dynamic_managers));

    fp = filp_open(DYNAMIC_MANAGER_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(fp)) {
        ret = PTR_ERR(fp);
        goto out;
    }
    written = kernel_write(fp, state, sizeof(*state), &pos);
    if (written != sizeof(*state))
        ret = written < 0 ? written : -EIO;
    filp_close(fp, NULL);
out:
    kfree(state);
    return ret;
}

void ksu_dynamic_manager_sync_uid(const char *package, uid_t uid)
{
    unsigned int i;
    bool changed = false;

    mutex_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (!strcmp(dynamic_managers[i].package, package) && dynamic_managers[i].uid != uid % KSU_PER_USER_RANGE) {
            dynamic_managers[i].uid = uid % KSU_PER_USER_RANGE;
            changed = true;
        }
    }
    if (changed)
        save_state_locked();
    mutex_unlock(&dynamic_manager_lock);
}

void ksu_dynamic_manager_load(void)
{
    struct dynamic_manager_state *state;
    struct file *fp;
    loff_t pos = 0;
    ssize_t read;

    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state)
        return;
    fp = filp_open(DYNAMIC_MANAGER_FILE, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        kfree(state);
        return;
    }
    read = kernel_read(fp, state, sizeof(*state), &pos);
    filp_close(fp, NULL);
    if (read == sizeof(*state) && state->magic == DYNAMIC_MANAGER_MAGIC &&
        state->version == DYNAMIC_MANAGER_VERSION && state->count <= KSU_MAX_DYNAMIC_MANAGERS) {
        unsigned int i;
        bool valid = true;

        for (i = 0; i < state->count; ++i) {
            if (!state->entries[i].cert_size || state->entries[i].cert_size > DYNAMIC_MANAGER_MAX_CERT_SIZE ||
                !package_valid(state->entries[i].package) ||
                !hash_valid(state->entries[i].hash)) {
                valid = false;
                break;
            }
        }
        if (valid) {
            mutex_lock(&dynamic_manager_lock);
            dynamic_manager_enabled = !!state->enabled;
            dynamic_manager_count = state->count;
            memcpy(dynamic_managers, state->entries, sizeof(dynamic_managers));
            mutex_unlock(&dynamic_manager_lock);
        }
    }
    kfree(state);
}

int ksu_dynamic_manager_set(struct ksu_manager_cmd *cmd)
{
    struct ksu_manager_entry entry = {};
    unsigned int i;
    int ret = 0;

    if (!cmd || cmd->count > KSU_MAX_DYNAMIC_MANAGERS || cmd->enabled > 1)
        return -EINVAL;

    mutex_lock(&dynamic_manager_lock);
    switch (cmd->operation) {
    case KSU_MANAGER_SET_ENABLED:
        dynamic_manager_enabled = !!cmd->enabled;
        break;
    case KSU_MANAGER_ADD:
        if (!cmd->cert_size || cmd->cert_size > DYNAMIC_MANAGER_MAX_CERT_SIZE ||
            strnlen(cmd->package, sizeof(cmd->package)) >= sizeof(cmd->package) ||
            strnlen(cmd->hash, sizeof(cmd->hash)) >= sizeof(cmd->hash)) {
            ret = -EINVAL;
            break;
        }
        entry.cert_size = cmd->cert_size;
        entry.uid = cmd->uid % KSU_PER_USER_RANGE;
        strscpy(entry.package, cmd->package, sizeof(entry.package));
        strscpy(entry.hash, cmd->hash, sizeof(entry.hash));
        if (!package_valid(entry.package) || !hash_valid(entry.hash)) {
            ret = -EINVAL;
            break;
        }
        for (i = 0; i < dynamic_manager_count; ++i) {
            if (!strcmp(dynamic_managers[i].package, entry.package)) {
                entry.uid = dynamic_managers[i].uid;
                dynamic_managers[i] = entry;
                goto save;
            }
        }
        if (dynamic_manager_count == KSU_MAX_DYNAMIC_MANAGERS) {
            ret = -ENOSPC;
            break;
        }
        dynamic_managers[dynamic_manager_count++] = entry;
        break;
    case KSU_MANAGER_REMOVE:
        if (strnlen(cmd->package, sizeof(cmd->package)) >= sizeof(cmd->package) || !package_valid(cmd->package)) {
            ret = -EINVAL;
            break;
        }
        for (i = 0; i < dynamic_manager_count; ++i) {
            if (!strcmp(dynamic_managers[i].package, cmd->package)) {
                --dynamic_manager_count;
                dynamic_managers[i] = dynamic_managers[dynamic_manager_count];
                memset(&dynamic_managers[dynamic_manager_count], 0, sizeof(dynamic_managers[0]));
                break;
            }
        }
        break;
    case KSU_MANAGER_CLEAR:
        memset(dynamic_managers, 0, sizeof(dynamic_managers));
        dynamic_manager_count = 0;
        break;
    default:
        ret = -EINVAL;
        break;
    }
    if (!ret) {
save:
        ret = save_state_locked();
    }
    mutex_unlock(&dynamic_manager_lock);
    if (!ret)
        track_throne(false);
    return ret;
}

int ksu_dynamic_manager_get(struct ksu_manager_cmd *cmd)
{
    if (!cmd)
        return -EINVAL;
    mutex_lock(&dynamic_manager_lock);
    cmd->enabled = dynamic_manager_enabled;
    cmd->count = dynamic_manager_count;
    memcpy(cmd->entries, dynamic_managers, sizeof(dynamic_managers));
    mutex_unlock(&dynamic_manager_lock);
    return 0;
}

bool ksu_dynamic_manager_match(const char *package, unsigned int size, const char *hash)
{
    unsigned int i;
    bool found = false;

    if (!ksu_manager_enabled())
        return false;

    mutex_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (dynamic_managers[i].cert_size == size && !strcmp(dynamic_managers[i].package, package) &&
            !strncasecmp(dynamic_managers[i].hash, hash, KSU_MANAGER_HASH_LENGTH)) {
            found = true;
            break;
        }
    }
    mutex_unlock(&dynamic_manager_lock);
    return found;
}

bool ksu_dynamic_manager_check_apk(char *path, const char *package, uid_t uid)
{
    struct ksu_manager_entry entry = {};
    unsigned int i;
    unsigned int appid = uid % KSU_PER_USER_RANGE;
    bool found = false;

    if (!ksu_manager_enabled())
        return false;

    mutex_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (!strcmp(dynamic_managers[i].package, package) && dynamic_managers[i].uid == appid) {
            entry = dynamic_managers[i];
            found = true;
            break;
        }
    }
    mutex_unlock(&dynamic_manager_lock);

    return found && ksu_check_apk_signature(path, entry.cert_size, entry.hash);
}
