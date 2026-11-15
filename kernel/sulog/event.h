#ifndef __KSU_H_SULOG_EVENT
#define __KSU_H_SULOG_EVENT

struct ksu_event_queue;
struct ksu_sulog_pending_event;

int ksu_sulog_events_init(void);
void ksu_sulog_events_exit(void);

struct ksu_sulog_pending_event *ksu_sulog_capture_root_execve(const char *filename_kernel, const char __user *filename_user, const char __user *const __user *argv_user, gfp_t gfp);
struct ksu_sulog_pending_event *ksu_sulog_capture_sucompat(const char *filename_kernel, const char __user *filename_user, const char __user *const __user *argv_user, gfp_t gfp);
void ksu_sulog_emit_pending(struct ksu_sulog_pending_event *pending, int retval, gfp_t gfp);
int ksu_sulog_emit_grant_root(int retval, __u32 uid, __u32 euid, gfp_t gfp);

struct ksu_event_queue *ksu_sulog_get_queue(void);

static noinline void do_ksu_sulog_emit_sucompat_pre(const char *filename_kernel, const char __user *filename_user, void ***argv)
{
	const char __user *const __user *argv_user = (const char __user *const __user *)*argv;
	struct ksu_sulog_pending_event *pending_root_execve = ksu_sulog_capture_root_execve(filename_kernel, filename_user, argv_user, GFP_KERNEL);
	ksu_sulog_emit_pending(pending_root_execve, 0, GFP_KERNEL);
}

static noinline void do_ksu_sulog_emit_sucompat_post(const char *filename_kernel, const char __user *filename_user, void ***argv)
{
	const char __user *const __user *argv_user = (const char __user *const __user *)*argv;
	struct ksu_sulog_pending_event *pending_sucompat = ksu_sulog_capture_sucompat(filename_kernel, filename_user, argv_user, GFP_KERNEL);
	ksu_sulog_emit_pending(pending_sucompat, 0, GFP_KERNEL);
}

#ifdef KSU_CAN_USE_JUMP_LABEL // see kernel_compat.h
DEFINE_STATIC_KEY_FALSE(ksu_sulog_key);
static __always_inline void ksu_sulog_emit_sucompat_pre(const char *filename_kernel, const char __user *filename_user, void ***argv)
{
	if (static_branch_unlikely(&ksu_sulog_key))
		do_ksu_sulog_emit_sucompat_pre(filename_kernel, filename_user, argv);
}

static __always_inline void ksu_sulog_emit_sucompat_post(const char *filename_kernel, const char __user *filename_user, void ***argv)
{
	if (static_branch_unlikely(&ksu_sulog_key))
		do_ksu_sulog_emit_sucompat_post(filename_kernel, filename_user, argv);
}

static inline void ksu_sulog_branch_enable() { static_branch_enable(&ksu_sulog_key); smp_mb(); }
static inline void ksu_sulog_branch_disable() { static_branch_disable(&ksu_sulog_key); smp_mb(); }

#else /* !KSU_CAN_USE_JUMP_LABEL */
static bool ksu_sulog_enabled __read_mostly;

static __always_inline void ksu_sulog_emit_sucompat_pre(const char *filename_kernel, const char __user *filename_user, void ***argv)
{
	if (unlikely(ksu_sulog_enabled))
		do_ksu_sulog_emit_sucompat_pre(filename_kernel, filename_user, argv);
}

static __always_inline void ksu_sulog_emit_sucompat_post(const char *filename_kernel, const char __user *filename_user, void ***argv)
{
	if (unlikely(ksu_sulog_enabled))
		do_ksu_sulog_emit_sucompat_post(filename_kernel, filename_user, argv);
}

static inline void ksu_sulog_branch_enable() { } // no-op
static inline void ksu_sulog_branch_disable() { } // no-op

#endif  /* !KSU_CAN_USE_JUMP_LABEL */

#endif
