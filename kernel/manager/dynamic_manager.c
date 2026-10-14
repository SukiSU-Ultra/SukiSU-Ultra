// SPDX-License-Identifier: GPL-2.0
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "klog.h"
#include "ksu.h"
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

static int lookup_package_uid(const char *package, uid_t *uid)
{
    struct file *fp;
    char line[KSU_MAX_PACKAGE_NAME + 32];
    size_t length = 0;
    loff_t pos = 0;
    char ch;
    ssize_t read;
    int ret = -ENOENT;
    const struct cred *saved;

    if (!package || !uid)
        return -EINVAL;

    saved = override_creds(ksu_cred);
    fp = filp_open("/data/system/packages.list", O_RDONLY, 0);
    if (IS_ERR(fp)) {
        ret = PTR_ERR(fp);
        goto restore;
    }
    for (;;) {
        read = kernel_read(fp, &ch, sizeof(ch), &pos);
        if (read != sizeof(ch))
            break;
        if (ch != '\n') {
            if (length + 1 < sizeof(line))
                line[length++] = ch;
            continue;
        }
        if (length > 0) {
            char *cursor = line;
            char *name = strsep(&cursor, " ");
            char *uid_string = strsep(&cursor, " ");
            u32 parsed_uid;
            line[length] = '\0';
            if (name && uid_string && !strcmp(name, package) && !kstrtou32(uid_string, 10, &parsed_uid)) {
                *uid = parsed_uid % KSU_PER_USER_RANGE;
                ret = 0;
                break;
            }
        }
        length = 0;
    }
    filp_close(fp, NULL);
restore:
    revert_creds(saved);
    return ret;
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
    read_lock(&dynamic_manager_lock);
    if (!READ_ONCE(dynamic_manager_enabled)) {
        read_unlock(&dynamic_manager_lock);
        return false;
    }
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (dynamic_manager_verified[i] && dynamic_managers[i].uid == uid % KSU_PER_USER_RANGE &&
            !strcmp(dynamic_managers[i].package, package)) {
            found = true;
            break;
        }
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

static int save_state(void)
{
    struct dynamic_manager_state *state;
    struct file *fp;
    loff_t pos = 0;
    ssize_t written;
    int ret = 0;
    const struct cred *saved;

    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state)
        return -ENOMEM;
    read_lock(&dynamic_manager_lock);
    state->magic = DYNAMIC_MANAGER_MAGIC;
    state->version = DYNAMIC_MANAGER_VERSION;
    state->enabled = READ_ONCE(dynamic_manager_enabled);
    state->count = dynamic_manager_count;
    memcpy(state->entries, dynamic_managers, sizeof(dynamic_managers));
    read_unlock(&dynamic_manager_lock);

    saved = override_creds(ksu_cred);
    fp = filp_open(DYNAMIC_MANAGER_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(fp)) {
        ret = PTR_ERR(fp);
        goto restore;
    }
    written = kernel_write(fp, state, sizeof(*state), &pos);
    if (written != sizeof(*state))
        ret = written < 0 ? written : -EIO;
    filp_close(fp, NULL);
restore:
    revert_creds(saved);
    kfree(state);
    return ret;
}

void ksu_dynamic_manager_load(void)
{
    struct dynamic_manager_state *state;
    struct ksu_manager_entry *kept_entries;
    struct file *fp;
    loff_t pos = 0;
    ssize_t read;
    unsigned int i, kept = 0;
    bool enabled = false;

    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state)
        return;
    kept_entries = kzalloc(sizeof(*kept_entries) * KSU_MAX_DYNAMIC_MANAGERS, GFP_KERNEL);
    if (!kept_entries) {
        kfree(state);
        return;
    }
    fp = filp_open(DYNAMIC_MANAGER_FILE, O_RDONLY, 0);
    if (IS_ERR(fp))
        goto out;
    read = kernel_read(fp, state, sizeof(*state), &pos);
    filp_close(fp, NULL);
    if (read == sizeof(*state) && state->magic == DYNAMIC_MANAGER_MAGIC &&
        state->version == DYNAMIC_MANAGER_VERSION && state->count <= KSU_MAX_DYNAMIC_MANAGERS &&
        state->enabled <= 1) {
        enabled = !!state->enabled;
        for (i = 0; i < state->count; ++i) {
            uid_t current_uid;
            const struct ksu_manager_entry *entry = &state->entries[i];

            if (!entry->cert_size || entry->cert_size > DYNAMIC_MANAGER_MAX_CERT_SIZE ||
                !package_valid(entry->package) || !hash_valid(entry->hash))
                continue;
            /*
             * Persisted entries are only a hint: require the current
             * package installation to agree on the package name and UID
             * before we re-accept the entry. The runtime scan will still
             * re-verify the signing certificate.
             */
            if (lookup_package_uid(entry->package, &current_uid))
                continue;
            if (current_uid != entry->uid % KSU_PER_USER_RANGE)
                continue;
            if (kept < KSU_MAX_DYNAMIC_MANAGERS)
                kept_entries[kept++] = *entry;
        }
    }
out:
    write_lock(&dynamic_manager_lock);
    WRITE_ONCE(dynamic_manager_enabled, kept ? enabled : false);
    dynamic_manager_count = kept;
    if (kept)
        memcpy(dynamic_managers, kept_entries, sizeof(*kept_entries) * kept);
    else
        memset(dynamic_managers, 0, sizeof(dynamic_managers));
    memset(dynamic_manager_verified, 0, sizeof(dynamic_manager_verified));
    write_unlock(&dynamic_manager_lock);
    kfree(kept_entries);
    kfree(state);
}

int ksu_dynamic_manager_set(struct ksu_manager_cmd *cmd)
{
    struct ksu_manager_entry entry = {};
    struct ksu_manager_entry *previous_managers;
    bool *previous_verified;
    __u32 previous_count;
    bool previous_enabled;
    unsigned int i;
    uid_t package_uid = KSU_INVALID_APPID;
    bool updated = false;
    int ret = 0;

    if (!cmd || cmd->count > KSU_MAX_DYNAMIC_MANAGERS || cmd->enabled > 1)
        return -EINVAL;

    if (cmd->operation == KSU_MANAGER_ADD) {
        if (!cmd->cert_size || cmd->cert_size > DYNAMIC_MANAGER_MAX_CERT_SIZE ||
            strnlen(cmd->package, sizeof(cmd->package)) >= sizeof(cmd->package) ||
            strnlen(cmd->hash, sizeof(cmd->hash)) >= sizeof(cmd->hash) ||
            !package_valid(cmd->package) || !hash_valid(cmd->hash) ||
            lookup_package_uid(cmd->package, &package_uid))
            return -EINVAL;
    }

    previous_managers = kzalloc(sizeof(dynamic_managers), GFP_KERNEL);
    previous_verified = kzalloc(sizeof(dynamic_manager_verified), GFP_KERNEL);
    if (!previous_managers || !previous_verified) {
        kfree(previous_managers);
        kfree(previous_verified);
        return -ENOMEM;
    }

    mutex_lock(&dynamic_manager_update_lock);
    write_lock(&dynamic_manager_lock);
    previous_enabled = READ_ONCE(dynamic_manager_enabled);
    previous_count = dynamic_manager_count;
    memcpy(previous_managers, dynamic_managers, sizeof(dynamic_managers));
    memcpy(previous_verified, dynamic_manager_verified, sizeof(dynamic_manager_verified));
    switch (cmd->operation) {
    case KSU_MANAGER_SET_ENABLED:
        WRITE_ONCE(dynamic_manager_enabled, !!cmd->enabled);
        break;
    case KSU_MANAGER_ADD:
        entry.cert_size = cmd->cert_size;
        entry.uid = package_uid;
        strscpy(entry.package, cmd->package, sizeof(entry.package));
        strscpy(entry.hash, cmd->hash, sizeof(entry.hash));
        for (i = 0; i < dynamic_manager_count; ++i) {
            if (!strcmp(dynamic_managers[i].package, entry.package)) {
                dynamic_managers[i] = entry;
                dynamic_manager_verified[i] = false;
                updated = true;
                break;
            }
        }
        if (updated)
            break;
        if (dynamic_manager_count == KSU_MAX_DYNAMIC_MANAGERS) {
            ret = -ENOSPC;
            break;
        }
        dynamic_managers[dynamic_manager_count++] = entry;
        dynamic_manager_verified[dynamic_manager_count - 1] = false;
        break;
    case KSU_MANAGER_REMOVE:
        if (strnlen(cmd->package, sizeof(cmd->package)) >= sizeof(cmd->package) || !package_valid(cmd->package)) {
            ret = -EINVAL;
            break;
        }
        if (cmd->hash[0] && strnlen(cmd->hash, sizeof(cmd->hash)) >= sizeof(cmd->hash)) {
            ret = -EINVAL;
            break;
        }
        for (i = 0; i < dynamic_manager_count; ++i) {
            if (!strcmp(dynamic_managers[i].package, cmd->package)) {
                --dynamic_manager_count;
                dynamic_managers[i] = dynamic_managers[dynamic_manager_count];
                dynamic_manager_verified[i] = dynamic_manager_verified[dynamic_manager_count];
                memset(&dynamic_managers[dynamic_manager_count], 0, sizeof(dynamic_managers[0]));
                dynamic_manager_verified[dynamic_manager_count] = false;
                break;
            }
        }
        break;
    case KSU_MANAGER_CLEAR:
        memset(dynamic_managers, 0, sizeof(dynamic_managers));
        memset(dynamic_manager_verified, 0, sizeof(dynamic_manager_verified));
        dynamic_manager_count = 0;
        break;
    default:
        ret = -EINVAL;
        break;
    }
    if (ret) {
        write_unlock(&dynamic_manager_lock);
        mutex_unlock(&dynamic_manager_update_lock);
        kfree(previous_managers);
        kfree(previous_verified);
        return ret;
    }
    write_unlock(&dynamic_manager_lock);
    ret = save_state();
    if (ret) {
        write_lock(&dynamic_manager_lock);
        WRITE_ONCE(dynamic_manager_enabled, previous_enabled);
        dynamic_manager_count = previous_count;
        memcpy(dynamic_managers, previous_managers, sizeof(dynamic_managers));
        memcpy(dynamic_manager_verified, previous_verified, sizeof(dynamic_manager_verified));
        write_unlock(&dynamic_manager_lock);
    }
    mutex_unlock(&dynamic_manager_update_lock);
    kfree(previous_managers);
    kfree(previous_verified);
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

bool ksu_dynamic_manager_match(const char *package, unsigned int size, const char *hash)
{
    unsigned int i;
    bool found = false;

    if (!ksu_manager_enabled())
        return false;

    read_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (dynamic_managers[i].cert_size == size && !strcmp(dynamic_managers[i].package, package) &&
            !strncasecmp(dynamic_managers[i].hash, hash, KSU_MANAGER_HASH_LENGTH)) {
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
    unsigned int i;
    int ret = -ENOENT;

    if (!package || !uid)
        return -EINVAL;

    read_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (!strcmp(dynamic_managers[i].package, package)) {
            *uid = dynamic_managers[i].uid;
            ret = 0;
            break;
        }
    }
    read_unlock(&dynamic_manager_lock);
    return ret;
}

bool ksu_dynamic_manager_package_registered(const char *package)
{
    unsigned int i;
    bool found = false;

    read_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (!strcmp(dynamic_managers[i].package, package)) {
            found = true;
            break;
        }
    }
    read_unlock(&dynamic_manager_lock);
    return found;
}

bool ksu_dynamic_manager_verify_apk(char *path, const char *package, uid_t uid)
{
    struct ksu_manager_entry entry = {};
    unsigned int i;
    bool found = false;

    read_lock(&dynamic_manager_lock);
    for (i = 0; i < dynamic_manager_count; ++i) {
        if (!strcmp(dynamic_managers[i].package, package) && dynamic_managers[i].uid == uid % KSU_PER_USER_RANGE) {
            entry = dynamic_managers[i];
            found = true;
            break;
        }
    }
    read_unlock(&dynamic_manager_lock);
    if (!found || !ksu_check_apk_signature(path, entry.cert_size, entry.hash))
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
