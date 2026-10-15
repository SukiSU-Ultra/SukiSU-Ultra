#include <linux/errno.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

#include "../hook/syscall_hook.h"
#include "syscall_api.h"

struct kpm_syscall_slot {
    kpm_syscall_before_t before;
    kpm_syscall_after_t after;
    void *data;
};

static DEFINE_MUTEX(kpm_syscall_lock);
static struct kpm_syscall_slot kpm_syscall_slots[__NR_syscalls];

static long kpm_syscall_dispatch(int nr, const struct pt_regs *regs)
{
    struct kpm_syscall_slot slot;
    long result;

    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;
    mutex_lock(&kpm_syscall_lock);
    slot = kpm_syscall_slots[nr];
    mutex_unlock(&kpm_syscall_lock);
    if (!slot.before)
        return ksu_syscall_table[nr](regs);

    result = slot.before(nr, regs, slot.data);
    if (result == KPM_SYSCALL_CONTINUE)
        result = ksu_syscall_table[nr](regs);
    if (slot.after)
        slot.after(nr, regs, result, slot.data);
    return result;
}

int kpm_hook_syscall(int nr, kpm_syscall_before_t before,
                     kpm_syscall_after_t after, void *data)
{
    int result;

    if (nr < 0 || nr >= __NR_syscalls || !before)
        return -EINVAL;
    mutex_lock(&kpm_syscall_lock);
    if (kpm_syscall_slots[nr].before) {
        result = -EEXIST;
    } else {
        kpm_syscall_slots[nr] = (struct kpm_syscall_slot){
            .before = before,
            .after = after,
            .data = data,
        };
        result = ksu_register_syscall_hook(nr, kpm_syscall_dispatch);
    }
    if (result)
        kpm_syscall_slots[nr] = (struct kpm_syscall_slot){};
    mutex_unlock(&kpm_syscall_lock);
    return result;
}
EXPORT_SYMBOL(kpm_hook_syscall);

int kpm_unhook_syscall(int nr, kpm_syscall_before_t before,
                       kpm_syscall_after_t after)
{
    int result = -ENOENT;

    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;
    mutex_lock(&kpm_syscall_lock);
    if (kpm_syscall_slots[nr].before == before &&
        kpm_syscall_slots[nr].after == after) {
        ksu_unregister_syscall_hook(nr);
        kpm_syscall_slots[nr] = (struct kpm_syscall_slot){};
        result = 0;
    }
    mutex_unlock(&kpm_syscall_lock);
    return result;
}
EXPORT_SYMBOL(kpm_unhook_syscall);

MODULE_LICENSE("GPL");
