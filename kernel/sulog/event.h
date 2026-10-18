#ifndef __KSU_H_SULOG_EVENT
#define __KSU_H_SULOG_EVENT

struct ksu_event_queue;
struct ksu_sulog_pending_event;

int ksu_sulog_events_init(void);
void ksu_sulog_events_exit(void);

void ksu_sulog_emit_pending(struct ksu_sulog_pending_event *pending, int retval, gfp_t gfp);

static int ksu_sulog_emit_grant_root(int retval, __u32 uid, __u32 euid, gfp_t gfp);
static int ksu_sulog_emit(__u16 event_type, const char *bprm_argv, size_t bprm_argv_len, gfp_t gfp);
static noinline void do_ksu_sulog_emit_bprm(const char *filename);

#ifdef KSU_CAN_USE_JUMP_LABEL // see kernel_compat.h

DEFINE_STATIC_KEY_FALSE(ksu_sulog_key);
static __always_inline void ksu_sulog_emit_bprm(const char *filename)
{
	if (static_branch_unlikely(&ksu_sulog_key))
		do_ksu_sulog_emit_bprm(filename);
}

static inline void ksu_sulog_branch_enable() { static_branch_enable(&ksu_sulog_key); smp_mb(); }
static inline void ksu_sulog_branch_disable() { static_branch_disable(&ksu_sulog_key); smp_mb(); }

#else /* !KSU_CAN_USE_JUMP_LABEL */
static bool ksu_sulog_enabled __read_mostly;
static __always_inline void ksu_sulog_emit_bprm(const char *filename)
{
	if (unlikely(ksu_sulog_enabled))
		do_ksu_sulog_emit_bprm(filename);
}
static inline void ksu_sulog_branch_enable() { } // no-op
static inline void ksu_sulog_branch_disable() { } // no-op

#endif  /* !KSU_CAN_USE_JUMP_LABEL */

struct ksu_event_queue *ksu_sulog_get_queue(void);

#endif
