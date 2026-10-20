#ifndef __KSU_H_UID_OBSERVER
#define __KSU_H_UID_OBSERVER

#include <linux/list.h>
#include <linux/types.h>

struct uid_data {
    struct list_head list;
    u32 uid;
    char package[256];
};

#ifdef CONFIG_KSU_DISABLE_MANAGER
static inline void ksu_throne_tracker_init()
{
}

static inline void ksu_throne_tracker_exit()
{
}

static inline void track_throne(bool prune_only)
{
    (void)prune_only;
}
#else
void ksu_throne_tracker_init();

void ksu_throne_tracker_exit();

void track_throne(bool prune_only);
#endif

#endif
