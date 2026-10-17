// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * Per-KPM module manager. The KP project stores loaded KPMs on a linked
 * list; here we store them on a list_head rooted at kp_kpm_list with a
 * single mutex to coordinate load/unload.
 */
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <asm/uaccess.h>

#include "kp/include/ktypes.h"
#include "kp/include/log.h"
#include "kp/include/kpmodule.h"
#include "kpm.h"

int kpm_relocate_image(struct kpm_module *mod, const void *image, size_t image_size);
int kp_module_verify(const void *data, size_t size, struct kp_version_info *info);

struct kp_kpm_entry {
    struct list_head list;
    struct kpm_module mod;
    char *path;
    int id;
};

static LIST_HEAD(kp_kpm_list);
static DEFINE_MUTEX(kp_kpm_lock);
static int kp_kpm_id;

static int kp_kpm_invoke(struct kpm_module *mod, int which, void *arg)
{
    kpm_entry_t fn = NULL;
    if (which == 0) fn = mod->info.init;
    else if (which == 1) fn = mod->info.exit;
    if (!fn) return 0;
    return fn(arg, mod);
}

static void kp_kpm_unload(struct kp_kpm_entry *entry)
{
    kp_kpm_invoke(&entry->mod, 1, NULL);
    if (entry->mod.text) vfree(entry->mod.text);
    if (entry->mod.data) vfree(entry->mod.data);
    if (entry->mod.syms) kfree(entry->mod.syms);
    kfree(entry->path);
    kfree(entry);
}

struct kpm_module *kp_kpm_load(const void *data, size_t size, const char *path)
{
    struct kp_version_info info;
    if (kp_module_verify(data, size, &info) < 0)
        return ERR_PTR(-EINVAL);

    int err;
    struct kp_kpm_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) return ERR_PTR(-ENOMEM);

    entry->id = ++kp_kpm_id;
    entry->path = kstrdup(path, GFP_KERNEL);
    if (!entry->path) { kfree(entry); return ERR_PTR(-ENOMEM); }

    entry->mod.image = (void *)data;
    entry->mod.image_size = size;
    snprintf(entry->mod.info.name, sizeof(entry->mod.info.name), "kpm-%d", entry->id);
    snprintf(entry->mod.info.author, sizeof(entry->mod.info.author), "sukisu-lkm");
    snprintf(entry->mod.info.description, sizeof(entry->mod.info.description), "Loaded via sukisu lkm supercall");

    entry->mod.text = vmalloc(0x4000);
    entry->mod.text_size = 0x4000;
    entry->mod.data = vmalloc(0x4000);
    entry->mod.data_size = 0x4000;

    err = kpm_relocate_image(&entry->mod, data, size);
    if (err) { kp_kpm_unload(entry); return ERR_PTR(err); }

    err = kp_kpm_invoke(&entry->mod, 0, NULL);
    if (err) {
        logke("kpm init failed for %s: %d\n", path, err);
        kp_kpm_unload(entry);
        return ERR_PTR(err);
    }

    mutex_lock(&kp_kpm_lock);
    list_add_tail(&entry->list, &kp_kpm_list);
    mutex_unlock(&kp_kpm_lock);
    logki("loaded kpm %d (%s)\n", entry->id, path);
    return &entry->mod;
}
EXPORT_SYMBOL(kp_kpm_load);

int kp_kpm_unload_by_name(const char *name)
{
    struct kp_kpm_entry *entry, *tmp;
    int ret = -ENOENT;
    mutex_lock(&kp_kpm_lock);
    list_for_each_entry_safe(entry, tmp, &kp_kpm_list, list) {
        if (!strcmp(entry->path, name) || !strcmp(entry->mod.info.name, name)) {
            list_del(&entry->list);
            mutex_unlock(&kp_kpm_lock);
            kp_kpm_unload(entry);
            return 0;
        }
    }
    mutex_unlock(&kp_kpm_lock);
    return ret;
}
EXPORT_SYMBOL(kp_kpm_unload_by_name);

void kp_kpm_unload_all(void)
{
    struct kp_kpm_entry *entry, *tmp;
    mutex_lock(&kp_kpm_lock);
    list_for_each_entry_safe(entry, tmp, &kp_kpm_list, list) {
        list_del(&entry->list);
        kp_kpm_unload(entry);
    }
    mutex_unlock(&kp_kpm_lock);
}
EXPORT_SYMBOL(kp_kpm_unload_all);

int kp_kpm_control(const char *name, int cmd, void *arg)
{
    struct kp_kpm_entry *entry;
    mutex_lock(&kp_kpm_lock);
    list_for_each_entry(entry, &kp_kpm_list, list) {
        if (!strcmp(entry->path, name) || !strcmp(entry->mod.info.name, name)) {
            kpm_entry_t fn = cmd == 0 ? entry->mod.info.ctl0 : entry->mod.info.ctl1;
            int r = fn ? fn(arg, &entry->mod) : -ENOTTY;
            mutex_unlock(&kp_kpm_lock);
            return r;
        }
    }
    mutex_unlock(&kp_kpm_lock);
    return -ENOENT;
}
EXPORT_SYMBOL(kp_kpm_control);

int kp_kpm_event(const char *name, int code, void *arg)
{
    struct kp_kpm_entry *entry;
    mutex_lock(&kp_kpm_lock);
    list_for_each_entry(entry, &kp_kpm_list, list) {
        if (!strcmp(entry->path, name) || !strcmp(entry->mod.info.name, name)) {
            kpm_entry_t fn = entry->mod.info.event;
            int r = fn ? fn(arg, &entry->mod) : 0;
            mutex_unlock(&kp_kpm_lock);
            return r;
        }
    }
    mutex_unlock(&kp_kpm_lock);
    return 0;
}
EXPORT_SYMBOL(kp_kpm_event);

void kp_kpm_list_modules(struct kpm_module **mods, int *count)
{
    struct kp_kpm_entry *entry;
    int n = 0;
    mutex_lock(&kp_kpm_lock);
    list_for_each_entry(entry, &kp_kpm_list, list) {
        if (mods && n < *count)
            mods[n] = &entry->mod;
        n++;
    }
    mutex_unlock(&kp_kpm_lock);
    *count = n;
}
EXPORT_SYMBOL(kp_kpm_list_modules);