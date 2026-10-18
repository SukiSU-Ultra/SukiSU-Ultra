// SPDX-License-Identifier: GPL-2.0
/*
 * Extension subsystem dispatcher.
 *
 * Owns the handler table indexed by ksu_extension_id. Provides:
 *   - value-flavored get/set through ksu_extension_get/set()
 *   - io-flavoured passthrough via ksu_extension_ioctl()
 *   - force_feature integration (parallel to kernel/policy/feature.c)
 *
 * See kernel/extension/extension.h for the broader design.
 */
#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/string.h>

#include "extension.h"
#include "kpm.h"
#include "cpu_spoof.h"
#include "umount_paths.h"
#include "dynamic_manager.h"
#include "klog.h" // IWYU pragma: keep

static const struct ksu_extension_handler *extension_handlers[KSU_EXTENSION_MAX];

static DEFINE_MUTEX(extension_mutex);

static const char *const extension_names[KSU_EXTENSION_MAX] = {
    [KSU_EXTENSION_KPM] = "kpm",
    [KSU_EXTENSION_CPU_SPOOF] = "cpu_spoof",
    [KSU_EXTENSION_UMOUNT_PATHS] = "umount_paths",
    [KSU_EXTENSION_DYNAMIC_MANAGER] = "dynamic_manager",
};

/*
 * Force-feature bitmap (parallel to policy/feature.c).
 * Each set bit means "userspace cannot change this extension anymore,
 * init must call io_handler / set with the saved value".
 */
static u64 forced_values[KSU_EXTENSION_MAX];
static DECLARE_BITMAP(forced_mask, KSU_EXTENSION_MAX);
static DECLARE_BITMAP(forced_pending, KSU_EXTENSION_MAX);

static int parse_extension_id(const char *name, u32 *id)
{
    u32 i;

    if (!kstrtou32(name, 10, id)) {
        return *id < KSU_EXTENSION_MAX ? 0 : -EINVAL;
    }

    for (i = 0; i < KSU_EXTENSION_MAX; i++) {
        if (extension_names[i] && !strcmp(name, extension_names[i])) {
            *id = i;
            return 0;
        }
    }

    return -EINVAL;
}

/*
 * force_extension=<name|id>:<value>[,<name|id>:<value>...]
 *
 * May be specified multiple times. Invalid entries are skipped instead of
 * failing, as a param error would prevent KernelSU from loading at all.
 * This may run before the slab allocator is up (built-in), so don't allocate.
 */
static int force_extension_param_set(const char *val,
                                     const struct kernel_param *kp)
{
    char name[32], num[24];
    const char *p = val, *end, *sep;
    size_t name_len, num_len;
    u32 id;
    u64 value;

    if (!val)
        return 0;

    for (; *p; p = *end ? end + 1 : end) {
        end = strchrnul(p, ',');
        if (end == p)
            continue;

        sep = memchr(p, ':', end - p);
        name_len = sep ? sep - p : 0;
        num_len = sep ? end - sep - 1 : 0;
        if (!name_len || name_len >= sizeof(name) || !num_len ||
            num_len >= sizeof(num)) {
            pr_err("extension: invalid force_extension entry '%.*s'\n",
                   (int)(end - p), p);
            continue;
        }

        memcpy(name, p, name_len);
        name[name_len] = '\0';
        memcpy(num, sep + 1, num_len);
        num[num_len] = '\0';

        if (parse_extension_id(name, &id) || kstrtou64(num, 0, &value)) {
            pr_err("extension: invalid force_extension entry '%s:%s'\n",
                   name, num);
            continue;
        }

        forced_values[id] = value;
        set_bit(id, forced_mask);
        set_bit(id, forced_pending);
        pr_info("extension: %s (id=%u) forced to %llu\n",
                extension_names[id], id, value);
    }
    return 0;
}

static const struct kernel_param_ops force_extension_param_ops = {
    /* A bare `force_extension` would otherwise fail parse_args() and
     * the whole module load: keep it no-arg-friendly. */
    .flags = KERNEL_PARAM_OPS_FL_NOARG,
    .set = force_extension_param_set,
};
module_param_cb(force_extension, &force_extension_param_ops, NULL, 0);

int ksu_register_extension_handler(const struct ksu_extension_handler *handler)
{
    if (!handler)
        return -EINVAL;

    if (handler->extension_id >= KSU_EXTENSION_MAX)
        return -EINVAL;

    if (!handler->ops && !handler->io_handler)
        return -EINVAL;

    mutex_lock(&extension_mutex);

    if (extension_handlers[handler->extension_id])
        pr_warn("extension: handler for %u already registered, overwriting\n",
                handler->extension_id);

    extension_handlers[handler->extension_id] = handler;

    pr_info("extension: registered handler for %s (id=%u)\n",
            handler->name ? handler->name : "unknown",
            handler->extension_id);

    mutex_unlock(&extension_mutex);
    return 0;
}

int ksu_unregister_extension_handler(u32 extension_id)
{
    int ret = 0;

    if (extension_id >= KSU_EXTENSION_MAX)
        return -EINVAL;

    mutex_lock(&extension_mutex);
    if (!extension_handlers[extension_id]) {
        ret = -ENOENT;
        goto out;
    }

    extension_handlers[extension_id] = NULL;
    pr_info("extension: unregistered handler for id=%u\n", extension_id);
out:
    mutex_unlock(&extension_mutex);
    return ret;
}

int ksu_extension_get(u32 extension_id, u64 *value, bool *supported)
{
    int ret = 0;
    const struct ksu_extension_handler *handler;

    if (extension_id >= KSU_EXTENSION_MAX)
        return -EINVAL;
    if (!value || !supported)
        return -EINVAL;

    mutex_lock(&extension_mutex);
    handler = extension_handlers[extension_id];
    if (!handler || !handler->ops || !handler->ops->get) {
        *supported = false;
        *value = 0;
        goto out;
    }
    *supported = true;
    ret = handler->ops->get(extension_id, value);
    if (ret)
        pr_err("extension: get for %u failed: %d\n", extension_id, ret);
out:
    mutex_unlock(&extension_mutex);
    return ret;
}

int ksu_extension_set(u32 extension_id, u64 value)
{
    int ret = 0;
    const struct ksu_extension_handler *handler;

    if (extension_id >= KSU_EXTENSION_MAX)
        return -EINVAL;

    if (test_bit(extension_id, forced_mask)) {
        pr_warn("extension: extension %u is forced by boot config\n",
                extension_id);
        return -EPERM;
    }

    mutex_lock(&extension_mutex);
    handler = extension_handlers[extension_id];
    if (!handler || !handler->ops || !handler->ops->set) {
        ret = -EOPNOTSUPP;
        goto out;
    }
    ret = handler->ops->set(extension_id, value);
    if (ret)
        pr_err("extension: set for %u failed: %d\n", extension_id, ret);
out:
    mutex_unlock(&extension_mutex);
    return ret;
}

bool ksu_extension_is_forced(u32 extension_id)
{
    return extension_id < KSU_EXTENSION_MAX &&
           test_bit(extension_id, forced_mask);
}

int ksu_extension_ioctl(u32 extension_id, void __user *raw)
{
    int ret;
    const struct ksu_extension_handler *handler;

    if (extension_id >= KSU_EXTENSION_MAX)
        return -EINVAL;

    mutex_lock(&extension_mutex);
    handler = extension_handlers[extension_id];
    if (!handler || !handler->io_handler) {
        ret = -EOPNOTSUPP;
        goto out;
    }
    ret = handler->io_handler(extension_id, raw);
out:
    mutex_unlock(&extension_mutex);
    return ret;
}

int ksu_extension_wipe(u32 extension_id)
{
    int ret = 0;
    const struct ksu_extension_handler *handler;

    if (extension_id >= KSU_EXTENSION_MAX)
        return -EINVAL;

    mutex_lock(&extension_mutex);
    handler = extension_handlers[extension_id];
    if (!handler || !handler->io_handler) {
        ret = -EOPNOTSUPP;
        goto out;
    }
    /*
     * Re-use the io_handler with a NULL user pointer. Subsystems that
     * support a "wipe" semantics interpret the NULL pointer as "drop
     * all entries" (umount paths), while others return -EOPNOTSUPP.
     */
    ret = handler->io_handler(extension_id, NULL);
out:
    mutex_unlock(&extension_mutex);
    return ret;
}

void ksu_extension_apply_forced(void)
{
    const struct ksu_extension_handler *handler;
    unsigned int id;
    int ret;

    mutex_lock(&extension_mutex);

    for_each_set_bit (id, forced_pending, KSU_EXTENSION_MAX) {
        handler = extension_handlers[id];
        if (!handler)
            continue;

        /*
         * Forced-by-config takes precedence: prefer the set op when
         * present (value-flavoured), otherwise pass-through to the
         * io_handler with the saved bit as a u64.
         */
        if (handler->ops && handler->ops->set) {
            ret = handler->ops->set(id, forced_values[id]);
        } else if (handler->io_handler) {
            ret = handler->io_handler(id, (void __user *)(uintptr_t)0);
            /* io-flavored extensions don't always accept a value-set;
             * any sentinel or EOPNOTSUPP is acceptable here. */
            if (ret == -EOPNOTSUPP)
                ret = 0;
        } else {
            continue;
        }

        if (ret) {
            pr_warn("extension: apply forced %s=%llu failed: %d\n",
                    extension_names[id], forced_values[id], ret);
            continue;
        }
        clear_bit(id, forced_pending);
        pr_info("extension: applied forced %s=%llu\n", extension_names[id],
                forced_values[id]);
    }

    mutex_unlock(&extension_mutex);
}

void __init ksu_extension_init(void)
{
    int i;

    for (i = 0; i < KSU_EXTENSION_MAX; i++)
        extension_handlers[i] = NULL;

    pr_info("extension: subsystem initialized\n");
}

/*
 * Convenience: register all built-in extensions in one call. Keeping it
 * in extension.c (rather than core/init.c) means feature authors don't
 * have to know the inner table layout.
 */
void __init ksu_extension_register_all(void)
{
    static const struct ksu_extension_handler kpm_handler = {
        .extension_id = KSU_EXTENSION_KPM,
        .name = "kpm",
        .ops = &ksu_extension_kpm_ops,
        .io_handler = ksu_extension_kpm_io,
    };
    static const struct ksu_extension_handler cpu_spoof_handler = {
        .extension_id = KSU_EXTENSION_CPU_SPOOF,
        .name = "cpu_spoof",
        .ops = &ksu_extension_cpu_spoof_ops,
        .io_handler = ksu_extension_cpu_spoof_io,
    };
    static const struct ksu_extension_handler umount_paths_handler = {
        .extension_id = KSU_EXTENSION_UMOUNT_PATHS,
        .name = "umount_paths",
        .ops = &ksu_extension_umount_paths_ops,
        .io_handler = ksu_extension_umount_paths_io,
    };
    static const struct ksu_extension_handler dynamic_manager_handler = {
        .extension_id = KSU_EXTENSION_DYNAMIC_MANAGER,
        .name = "dynamic_manager",
        .ops = &ksu_extension_dynamic_manager_ops,
        .io_handler = ksu_extension_dynamic_manager_io,
    };

    if (ksu_register_extension_handler(&kpm_handler))
        pr_err("extension: failed to register kpm\n");
    if (ksu_register_extension_handler(&cpu_spoof_handler))
        pr_err("extension: failed to register cpu_spoof\n");
    if (ksu_register_extension_handler(&umount_paths_handler))
        pr_err("extension: failed to register umount_paths\n");
    if (ksu_register_extension_handler(&dynamic_manager_handler))
        pr_err("extension: failed to register dynamic_manager\n");
}

void __exit ksu_extension_exit(void)
{
    mutex_lock(&extension_mutex);
    memset(extension_handlers, 0, sizeof(extension_handlers));
    mutex_unlock(&extension_mutex);
    pr_info("extension: subsystem cleaned up\n");
}
