#ifndef __SUKISU_KPM_KSTORAGE_H
#define __SUKISU_KPM_KSTORAGE_H

#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

#define KPM_KSTORAGE_MAX_GROUPS 4

struct kpm_kstorage {
    struct hlist_node node;
    struct rcu_head rcu;
    int group;
    long id;
    int length;
    u8 data[];
};

typedef int (*kpm_kstorage_iter_fn)(struct kpm_kstorage *item, void *data);

int kpm_kstorage_alloc_group(void);
int kpm_kstorage_group_size(int group);
u32 kpm_kstorage_generation(void);
int kpm_kstorage_write(int group, long id, const void *data, int offset, int length);
const struct kpm_kstorage *kpm_kstorage_get(int group, long id);
int kpm_kstorage_for_each(int group, kpm_kstorage_iter_fn callback, void *data);
int kpm_kstorage_read(int group, long id, void *data, int offset, int length);
int kpm_kstorage_list_ids(int group, long *ids, int length);
int kpm_kstorage_remove(int group, long id);
void kpm_kstorage_init(void);

#endif
