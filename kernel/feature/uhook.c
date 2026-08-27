// SPDX-License-Identifier: GPL-2.0
/*
 * uhook - general kernel-mediated userspace instrumentation via uprobes,
 * exposed through KSU_IOCTL_UHOOK (see uapi/supercall.h).
 *
 * A hook is keyed by (file inode, file-offset), so it applies to every thread
 * and process that maps the file, is immune to ASLR, and is invisible to the
 * target: no ptrace, no injected code, no modified instruction bytes. This is
 * the persistent/automatic counterpart to the interactive HWBP-hold in ptctl.
 *
 * A hook = where (entry or uretprobe return) + when (condition) + what (action),
 * with an optional register capture drained via KSU_UHOOK_READ.
 *
 * Reliable verbs on arm64: OBSERVE, POKE, and SETREG. SETREG at a RETURN site
 * forges the function's return value (x0) -- the canonical "make a check report
 * success" bypass. The control-flow verbs (FORCE_RET/JUMP/SKIP) rewrite pc, but
 * arm64's uprobe single-steps a non-simulated probed instruction after the
 * handler and thereby overwrites a handler-set pc (see handle_swbp() and
 * arch_uprobe_skip_sstep()); they are only honoured at simulated branch sites.
 * To fully skip a void method, patch its first instruction to `ret` via a ptctl
 * poke instead.
 *
 * Portability. Register access is implemented for arm64 and x86_64 (the module
 * is built for both); other arches fall back to no-ops so it still links. The
 * uprobe register/unregister ABI changed in v6.12 (uprobe_register() gained a
 * ref_ctr_offset argument and returns a struct uprobe *; uprobe_unregister()
 * split into _nosync/_sync); both eras are handled below, and the consumer
 * handler signatures are identical across them. All ops are root-gated by the
 * supercall perm check; kernel entry points are resolved via kallsyms so this
 * links whether built in or as an LKM.
 */
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/uprobes.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <asm/ptrace.h>

#include "uapi/supercall.h"
#include "feature/uhook.h"
#include "infra/symbol_resolver.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define UHOOK_NEW_UPROBE 1
#else
#define UHOOK_NEW_UPROBE 0
#endif

#define UHOOK_MAX 32 /* max simultaneous hooks */
#define UHOOK_RING 512 /* capture ring depth (records) */
#define UHOOK_POKE_MAX 256 /* max POKE payload bytes */
#define UHOOK_NREG 34 /* x0..x30, sp, pc, pstate */

/* --- resolved kernel symbols (the uprobe ABI differs across versions) --- */
#if UHOOK_NEW_UPROBE
typedef struct uprobe *(*uprobe_register_t)(struct inode *inode, loff_t offset, loff_t ref_ctr_offset,
                                            struct uprobe_consumer *uc);
typedef void (*uprobe_unregister_nosync_t)(struct uprobe *uprobe, struct uprobe_consumer *uc);
typedef void (*uprobe_unregister_sync_t)(void);
static uprobe_register_t p_uprobe_register;
static uprobe_unregister_nosync_t p_uprobe_unregister_nosync;
static uprobe_unregister_sync_t p_uprobe_unregister_sync;
#else
typedef int (*uprobe_register_t)(struct inode *inode, loff_t offset, struct uprobe_consumer *uc);
typedef void (*uprobe_unregister_t)(struct inode *inode, loff_t offset, struct uprobe_consumer *uc);
static uprobe_register_t p_uprobe_register;
static uprobe_unregister_t p_uprobe_unregister;
#endif

/* --- one installed hook --- */
struct uhook {
    struct uprobe_consumer uc; /* recovered via container_of() in the handlers */
    bool active;
    u32 id;
    struct inode *inode; /* igrab'd ref, iput on removal */
    loff_t offset;
#if UHOOK_NEW_UPROBE
    struct uprobe *uprobe; /* handle needed to unregister on 6.12+ */
#endif
    u32 site; /* enum ksu_uhook_site */
    /* condition */
    u32 cond, cond_reg, cond_cmp, cond_len;
    s64 cond_off;
    u64 cond_val;
    /* action */
    u32 action, act_reg;
    s64 act_off;
    u64 act_val;
    void *poke_data;
    u32 poke_len;
    /* capture */
    u32 cap_regs;
    u64 hits;
};

static struct uhook hooks[UHOOK_MAX];
static DEFINE_MUTEX(hooks_lock);
static u32 next_id = 1;

/* --- capture ring (producer: handlers; consumer: KSU_UHOOK_READ) --- */
static struct ksu_uhook_record *ring;
static u32 ring_head; /* index of oldest record */
static u32 ring_count;
static DEFINE_SPINLOCK(ring_lock);

/* --- register access by index. arm64: 0..30 = x0..x30, 31 = sp, 32 = pc,
 * 33 = pstate. x86_64: 0 = ax (return value, so SETREG index 0 forges a return
 * on both arches), 1..14 = bx,cx,dx,si,di,bp,r8..r15, 31 = sp, 32 = ip,
 * 33 = flags. Other arches return 0 so the module still links. --- */
static u64 uh_get_reg(struct pt_regs *regs, u32 i)
{
#if defined(CONFIG_ARM64) || defined(__aarch64__)
    if (i < 31)
        return regs->regs[i];
    if (i == 31)
        return regs->sp;
    if (i == 32)
        return regs->pc;
    return regs->pstate;
#elif defined(CONFIG_X86_64) || defined(__x86_64__)
    switch (i) {
    case 0:
        return regs->ax;
    case 1:
        return regs->bx;
    case 2:
        return regs->cx;
    case 3:
        return regs->dx;
    case 4:
        return regs->si;
    case 5:
        return regs->di;
    case 6:
        return regs->bp;
    case 7:
        return regs->r8;
    case 8:
        return regs->r9;
    case 9:
        return regs->r10;
    case 10:
        return regs->r11;
    case 11:
        return regs->r12;
    case 12:
        return regs->r13;
    case 13:
        return regs->r14;
    case 14:
        return regs->r15;
    case 31:
        return regs->sp;
    case 32:
        return regs->ip;
    case 33:
        return regs->flags;
    default:
        return 0;
    }
#else
    (void)regs;
    (void)i;
    return 0;
#endif
}

static void uh_set_reg(struct pt_regs *regs, u32 i, u64 v)
{
#if defined(CONFIG_ARM64) || defined(__aarch64__)
    if (i < 31)
        regs->regs[i] = v;
    else if (i == 31)
        regs->sp = v;
    else if (i == 32)
        regs->pc = v;
    else
        regs->pstate = v;
#elif defined(CONFIG_X86_64) || defined(__x86_64__)
    switch (i) {
    case 0:
        regs->ax = v;
        break;
    case 1:
        regs->bx = v;
        break;
    case 2:
        regs->cx = v;
        break;
    case 3:
        regs->dx = v;
        break;
    case 4:
        regs->si = v;
        break;
    case 5:
        regs->di = v;
        break;
    case 6:
        regs->bp = v;
        break;
    case 7:
        regs->r8 = v;
        break;
    case 8:
        regs->r9 = v;
        break;
    case 9:
        regs->r10 = v;
        break;
    case 10:
        regs->r11 = v;
        break;
    case 11:
        regs->r12 = v;
        break;
    case 12:
        regs->r13 = v;
        break;
    case 13:
        regs->r14 = v;
        break;
    case 14:
        regs->r15 = v;
        break;
    case 31:
        regs->sp = v;
        break;
    case 32:
        regs->ip = v;
        break;
    case 33:
        regs->flags = v;
        break;
    default:
        break;
    }
#else
    (void)regs;
    (void)i;
    (void)v;
#endif
}

static bool uh_cmp(u64 a, u32 op, u64 b)
{
    switch (op) {
    case KSU_UHOOK_EQ:
        return a == b;
    case KSU_UHOOK_NE:
        return a != b;
    case KSU_UHOOK_LT:
        return a < b;
    case KSU_UHOOK_GT:
        return a > b;
    case KSU_UHOOK_AND:
        return (a & b) != 0;
    }
    return false;
}

/* Handlers run in the context of the hitting thread, so its userspace is
 * addressable directly via copy_from_user()/copy_to_user(). */
static bool uh_cond_ok(struct uhook *h, struct pt_regs *regs)
{
    u64 v = 0;

    switch (h->cond) {
    case KSU_UHOOK_COND_NONE:
        return true;
    case KSU_UHOOK_COND_REG:
        if (h->cond_reg >= UHOOK_NREG)
            return false;
        return uh_cmp(uh_get_reg(regs, h->cond_reg), h->cond_cmp, h->cond_val);
    case KSU_UHOOK_COND_MEM: {
        unsigned long addr;
        u32 len = h->cond_len ? min_t(u32, h->cond_len, 8u) : 8u;

        if (h->cond_reg >= UHOOK_NREG)
            return false;
        addr = (unsigned long)(uh_get_reg(regs, h->cond_reg) + h->cond_off);
        if (copy_from_user(&v, (void __user *)addr, len))
            return false; /* unreadable -> do not fire */
        return uh_cmp(v, h->cond_cmp, h->cond_val);
    }
    }
    return false;
}

static void uh_capture(struct uhook *h, struct pt_regs *regs)
{
    struct ksu_uhook_record *rec;
    unsigned long flags;
    u32 idx, i, n;

    if (!ring)
        return;
    spin_lock_irqsave(&ring_lock, flags);
    if (ring_count >= UHOOK_RING) {
        /* full: drop the oldest to make room */
        ring_head = (ring_head + 1) % UHOOK_RING;
        ring_count--;
    }
    idx = (ring_head + ring_count) % UHOOK_RING;
    rec = &ring[idx];
    rec->id = h->id;
    rec->tid = task_pid_nr(current);
    rec->ts_ns = ktime_get_ns();
    n = h->cap_regs ? min_t(u32, h->cap_regs, (u32)UHOOK_NREG) : (u32)UHOOK_NREG;
    for (i = 0; i < UHOOK_NREG; i++)
        rec->regs[i] = i < n ? uh_get_reg(regs, i) : 0;
    ring_count++;
    spin_unlock_irqrestore(&ring_lock, flags);
}

static void uh_apply(struct uhook *h, struct pt_regs *regs)
{
    if (!uh_cond_ok(h, regs))
        return;
    h->hits++;

    switch (h->action) {
    case KSU_UHOOK_OBSERVE:
        uh_capture(h, regs);
        break;
    case KSU_UHOOK_SETREG:
        if (h->act_reg < UHOOK_NREG)
            uh_set_reg(regs, h->act_reg, h->act_val);
        break;
    case KSU_UHOOK_FORCE_RET:
#if defined(CONFIG_ARM64) || defined(__aarch64__)
        /* pc = lr (x30); see file header re: the single-step overwrite */
        instruction_pointer_set(regs, regs->regs[30]);
#elif defined(CONFIG_X86_64) || defined(__x86_64__)
    {
        /* at entry the return address sits at *rsp; pop it into rip */
        unsigned long ret_addr = 0;

        if (!copy_from_user(&ret_addr, (void __user *)regs->sp, sizeof(ret_addr))) {
            instruction_pointer_set(regs, ret_addr);
            regs->sp += sizeof(ret_addr);
        }
    }
#endif
        break;
    case KSU_UHOOK_JUMP:
        instruction_pointer_set(regs, h->act_val);
        break;
    case KSU_UHOOK_SKIP:
        instruction_pointer_set(regs, instruction_pointer(regs) + h->act_val);
        break;
    case KSU_UHOOK_POKE:
        if (h->poke_data && h->act_reg < UHOOK_NREG) {
            unsigned long addr = (unsigned long)(uh_get_reg(regs, h->act_reg) + h->act_off);

            (void)copy_to_user((void __user *)addr, h->poke_data, h->poke_len);
        }
        break;
    }
}

static int uh_entry_handler(struct uprobe_consumer *uc, struct pt_regs *regs)
{
    uh_apply(container_of(uc, struct uhook, uc), regs);
    return 0;
}

static int uh_ret_handler(struct uprobe_consumer *uc, unsigned long func, struct pt_regs *regs)
{
    (void)func;
    uh_apply(container_of(uc, struct uhook, uc), regs);
    return 0;
}

/* --- register/unregister across the two uprobe ABIs --- */
static int uh_uprobe_register(struct uhook *h)
{
#if UHOOK_NEW_UPROBE
    h->uprobe = p_uprobe_register(h->inode, h->offset, 0, &h->uc);
    if (IS_ERR_OR_NULL(h->uprobe)) {
        int ret = IS_ERR(h->uprobe) ? PTR_ERR(h->uprobe) : -ENODEV;

        h->uprobe = NULL;
        return ret;
    }
    return 0;
#else
    return p_uprobe_register(h->inode, h->offset, &h->uc);
#endif
}

static void uh_uprobe_unregister(struct uhook *h)
{
#if UHOOK_NEW_UPROBE
    if (h->uprobe && p_uprobe_unregister_nosync) {
        p_uprobe_unregister_nosync(h->uprobe, &h->uc);
        if (p_uprobe_unregister_sync)
            p_uprobe_unregister_sync();
        h->uprobe = NULL;
    }
#else
    if (p_uprobe_unregister)
        p_uprobe_unregister(h->inode, h->offset, &h->uc);
#endif
}

/* --- hook table helpers (hold hooks_lock) --- */
static struct uhook *uh_find(u32 id)
{
    int i;

    for (i = 0; i < UHOOK_MAX; i++)
        if (hooks[i].active && hooks[i].id == id)
            return &hooks[i];
    return NULL;
}

static void uh_free(struct uhook *h)
{
    if (h->inode) {
        uh_uprobe_unregister(h);
        iput(h->inode);
    }
    kfree(h->poke_data);
    memset(h, 0, sizeof(*h));
}

static int uh_add(struct ksu_uhook_cmd *cmd)
{
    struct uhook *h = NULL;
    struct path path;
    char *kpath;
    int i, ret;

    if (!p_uprobe_register)
        return -ENOSYS;

    for (i = 0; i < UHOOK_MAX; i++)
        if (!hooks[i].active) {
            h = &hooks[i];
            break;
        }
    if (!h)
        return -ENOSPC;

    kpath = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!kpath)
        return -ENOMEM;
    if (strncpy_from_user(kpath, (const char __user *)(uintptr_t)cmd->path, PATH_MAX) < 0) {
        kfree(kpath);
        return -EFAULT;
    }
    ret = kern_path(kpath, LOOKUP_FOLLOW, &path);
    kfree(kpath);
    if (ret)
        return ret;

    memset(h, 0, sizeof(*h));
    h->inode = igrab(d_inode(path.dentry));
    path_put(&path);
    if (!h->inode)
        return -ENOENT;

    h->offset = cmd->offset;
    h->site = cmd->site;
    h->cond = cmd->cond;
    h->cond_reg = cmd->cond_reg;
    h->cond_cmp = cmd->cond_cmp;
    h->cond_len = cmd->cond_len;
    h->cond_off = cmd->cond_off;
    h->cond_val = cmd->cond_val;
    h->action = cmd->action;
    h->act_reg = cmd->act_reg;
    h->act_off = cmd->act_off;
    h->act_val = cmd->act_val;
    h->cap_regs = cmd->cap_regs;

    if (h->action == KSU_UHOOK_POKE && cmd->len) {
        u32 n = min_t(u32, (u32)cmd->len, (u32)UHOOK_POKE_MAX);

        h->poke_data = kmalloc(n, GFP_KERNEL);
        if (!h->poke_data) {
            iput(h->inode);
            h->inode = NULL;
            return -ENOMEM;
        }
        if (copy_from_user(h->poke_data, (void __user *)(uintptr_t)cmd->uptr, n)) {
            kfree(h->poke_data);
            iput(h->inode);
            h->inode = NULL;
            return -EFAULT;
        }
        h->poke_len = n;
    }

    if (h->site == KSU_UHOOK_ON_RET)
        h->uc.ret_handler = uh_ret_handler;
    else
        h->uc.handler = uh_entry_handler;

    ret = uh_uprobe_register(h);
    if (ret) {
        kfree(h->poke_data);
        iput(h->inode);
        memset(h, 0, sizeof(*h));
        return ret;
    }

    h->id = next_id++;
    h->active = true;
    cmd->ret = h->id;
    pr_info("uhook: add id=%u off=0x%llx site=%u action=%u\n", h->id, (u64)h->offset, h->site, h->action);
    return 0;
}

static int uh_read(struct ksu_uhook_cmd *cmd)
{
    void __user *ubuf = (void __user *)(uintptr_t)cmd->uptr;
    u32 want = cmd->len / sizeof(struct ksu_uhook_record);
    u32 done = 0;
    unsigned long flags;

    if (!ring || !want)
        return -EINVAL;
    while (done < want) {
        struct ksu_uhook_record rec;

        spin_lock_irqsave(&ring_lock, flags);
        if (!ring_count) {
            spin_unlock_irqrestore(&ring_lock, flags);
            break;
        }
        rec = ring[ring_head];
        ring_head = (ring_head + 1) % UHOOK_RING;
        ring_count--;
        spin_unlock_irqrestore(&ring_lock, flags);

        if (copy_to_user(ubuf + done * sizeof(rec), &rec, sizeof(rec)))
            return -EFAULT;
        done++;
    }
    cmd->arg1 = done;
    cmd->ret = (s64)done * sizeof(struct ksu_uhook_record);
    return 0;
}

int ksu_uhook(struct ksu_uhook_cmd *cmd)
{
    int ret = 0, i;
    struct uhook *h;

    switch (cmd->op) {
    case KSU_UHOOK_ADD:
        mutex_lock(&hooks_lock);
        ret = uh_add(cmd);
        mutex_unlock(&hooks_lock);
        break;
    case KSU_UHOOK_DEL:
        mutex_lock(&hooks_lock);
        h = uh_find(cmd->id);
        if (h)
            uh_free(h);
        else
            ret = -ENOENT;
        mutex_unlock(&hooks_lock);
        break;
    case KSU_UHOOK_CLEAR:
        mutex_lock(&hooks_lock);
        for (i = 0; i < UHOOK_MAX; i++)
            if (hooks[i].active)
                uh_free(&hooks[i]);
        mutex_unlock(&hooks_lock);
        break;
    case KSU_UHOOK_LIST:
        mutex_lock(&hooks_lock);
        cmd->ret = 0;
        for (i = 0; i < UHOOK_MAX; i++)
            if (hooks[i].active)
                cmd->ret++;
        mutex_unlock(&hooks_lock);
        break;
    case KSU_UHOOK_READ:
        ret = uh_read(cmd);
        break;
    default:
        ret = -EINVAL;
    }
    return ret;
}

void ksu_uhook_init(void)
{
    p_uprobe_register = (uprobe_register_t)find_kernel_symbol_exact("uprobe_register");
#if UHOOK_NEW_UPROBE
    p_uprobe_unregister_nosync = (uprobe_unregister_nosync_t)find_kernel_symbol_exact("uprobe_unregister_nosync");
    p_uprobe_unregister_sync = (uprobe_unregister_sync_t)find_kernel_symbol_exact("uprobe_unregister_sync");
#else
    p_uprobe_unregister = (uprobe_unregister_t)find_kernel_symbol_exact("uprobe_unregister");
#endif
    ring = kvzalloc(sizeof(struct ksu_uhook_record) * UHOOK_RING, GFP_KERNEL);
    pr_info("uhook: init (uprobe_register=%d ring=%d)\n", !!p_uprobe_register, !!ring);
}

void ksu_uhook_exit(void)
{
    int i;

    mutex_lock(&hooks_lock);
    for (i = 0; i < UHOOK_MAX; i++)
        if (hooks[i].active)
            uh_free(&hooks[i]);
    mutex_unlock(&hooks_lock);
    kvfree(ring);
    ring = NULL;
}
