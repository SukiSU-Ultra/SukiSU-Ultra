#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#include "kstorage.h"

#define KPM_KSTORAGE_HASH_BITS 8
#define KPM_KSTORAGE_BUCKETS (1U << KPM_KSTORAGE_HASH_BITS)

static struct hlist_head kpm_storage[KPM_KSTORAGE_MAX_GROUPS][KPM_KSTORAGE_BUCKETS];
static spinlock_t kpm_storage_locks[KPM_KSTORAGE_MAX_GROUPS];
static spinlock_t kpm_group_lock;
static int kpm_used_groups = -1;
static int kpm_group_sizes[KPM_KSTORAGE_MAX_GROUPS];
static atomic_t kpm_storage_generation = ATOMIC_INIT(1);

static struct hlist_head *kpm_storage_bucket(int group, long id)
{
    u64 hash = (u64)id * 0x9e3779b97f4a7c15ULL;
    return &kpm_storage[group][hash >> (64 - KPM_KSTORAGE_HASH_BITS)];
}

static void kpm_storage_free(struct rcu_head *rcu)
{
    struct kpm_kstorage *item = container_of(rcu, struct kpm_kstorage, rcu);
    kvfree(item);
}

int kpm_kstorage_alloc_group(void)
{
    unsigned long flags;
    int group;

    spin_lock_irqsave(&kpm_group_lock, flags);
    group = ++kpm_used_groups;
    spin_unlock_irqrestore(&kpm_group_lock, flags);
    return group < KPM_KSTORAGE_MAX_GROUPS ? group : -ENOSPC;
}
EXPORT_SYMBOL(kpm_kstorage_alloc_group);

int kpm_kstorage_group_size(int group)
{
    return group >= 0 && group < KPM_KSTORAGE_MAX_GROUPS ? READ_ONCE(kpm_group_sizes[group]) : -EINVAL;
}
EXPORT_SYMBOL(kpm_kstorage_group_size);

u32 kpm_kstorage_generation(void)
{
    return (u32)atomic_read(&kpm_storage_generation);
}
EXPORT_SYMBOL(kpm_kstorage_generation);

int kpm_kstorage_write(int group, long id, const void *data, int offset, int length)
{
    struct hlist_head *bucket;
    struct kpm_kstorage *item, *old = NULL;
    unsigned long flags;

    if (group < 0 || group >= KPM_KSTORAGE_MAX_GROUPS || !data || offset < 0 || length < 0)
        return -EINVAL;
    item = kvmalloc(struct_size(item, data, length), GFP_KERNEL);
    if (!item)
        return -ENOMEM;
    item->group = group;
    item->id = id;
    item->length = length;
    memcpy(item->data, (const u8 *)data + offset, length);
    bucket = kpm_storage_bucket(group, id);

    spin_lock_irqsave(&kpm_storage_locks[group], flags);
    hlist_for_each_entry(old, bucket, node) {
        if (old->id == id)
            break;
        old = NULL;
    }
    if (old) {
        hlist_replace_rcu(&old->node, &item->node);
    } else {
        hlist_add_head_rcu(&item->node, bucket);
        kpm_group_sizes[group]++;
    }
    spin_unlock_irqrestore(&kpm_storage_locks[group], flags);
    if (old)
        call_rcu(&old->rcu, kpm_storage_free);
    atomic_inc(&kpm_storage_generation);
    return 0;
}
EXPORT_SYMBOL(kpm_kstorage_write);

const struct kpm_kstorage *kpm_kstorage_get(int group, long id)
{
    struct kpm_kstorage *item;

    if (group < 0 || group >= KPM_KSTORAGE_MAX_GROUPS)
        return ERR_PTR(-EINVAL);
    hlist_for_each_entry_rcu(item, kpm_storage_bucket(group, id), node)
        if (item->id == id)
            return item;
    return ERR_PTR(-ENOENT);
}
EXPORT_SYMBOL(kpm_kstorage_get);

int kpm_kstorage_for_each(int group, kpm_kstorage_iter_fn callback, void *data)
{
    struct kpm_kstorage *item;
    int bucket, result = 0;

    if (group < 0 || group >= KPM_KSTORAGE_MAX_GROUPS || !callback)
        return -EINVAL;
    rcu_read_lock();
    for (bucket = 0; bucket < KPM_KSTORAGE_BUCKETS && !result; ++bucket)
        hlist_for_each_entry_rcu(item, &kpm_storage[group][bucket], node) {
            result = callback(item, data);
            if (result)
                break;
        }
    rcu_read_unlock();
    return result;
}
EXPORT_SYMBOL(kpm_kstorage_for_each);

int kpm_kstorage_read(int group, long id, void *data, int offset, int length)
{
    const struct kpm_kstorage *item;
    int copy_length;

    if (!data || offset < 0 || length < 0)
        return -EINVAL;
    rcu_read_lock();
    item = kpm_kstorage_get(group, id);
    if (IS_ERR(item)) {
        rcu_read_unlock();
        return PTR_ERR(item);
    }
    if (offset >= item->length) {
        rcu_read_unlock();
        return 0;
    }
    copy_length = min(length, item->length - offset);
    memcpy(data, item->data + offset, copy_length);
    rcu_read_unlock();
    return copy_length;
}
EXPORT_SYMBOL(kpm_kstorage_read);

int kpm_kstorage_list_ids(int group, long *ids, int length)
{
    struct kpm_kstorage *item;
    int bucket, count = 0;

    if (group < 0 || group >= KPM_KSTORAGE_MAX_GROUPS || !ids || length < 0)
        return -EINVAL;
    rcu_read_lock();
    for (bucket = 0; bucket < KPM_KSTORAGE_BUCKETS && count < length; ++bucket)
        hlist_for_each_entry_rcu(item, &kpm_storage[group][bucket], node) {
            if (count == length)
                break;
            ids[count++] = item->id;
        }
    rcu_read_unlock();
    return count;
}
EXPORT_SYMBOL(kpm_kstorage_list_ids);

int kpm_kstorage_remove(int group, long id)
{
    struct kpm_kstorage *item;
    unsigned long flags;

    if (group < 0 || group >= KPM_KSTORAGE_MAX_GROUPS)
        return -EINVAL;
    spin_lock_irqsave(&kpm_storage_locks[group], flags);
    hlist_for_each_entry(item, kpm_storage_bucket(group, id), node)
        if (item->id == id) {
            hlist_del_rcu(&item->node);
            kpm_group_sizes[group]--;
            spin_unlock_irqrestore(&kpm_storage_locks[group], flags);
            call_rcu(&item->rcu, kpm_storage_free);
            atomic_inc(&kpm_storage_generation);
            return 0;
        }
    spin_unlock_irqrestore(&kpm_storage_locks[group], flags);
    return -ENOENT;
}
EXPORT_SYMBOL(kpm_kstorage_remove);

void kpm_kstorage_init(void)
{
    int group, bucket;

    for (group = 0; group < KPM_KSTORAGE_MAX_GROUPS; ++group) {
        for (bucket = 0; bucket < KPM_KSTORAGE_BUCKETS; ++bucket)
            INIT_HLIST_HEAD(&kpm_storage[group][bucket]);
        spin_lock_init(&kpm_storage_locks[group]);
    }
    spin_lock_init(&kpm_group_lock);
}

MODULE_LICENSE("GPL");
