#define KSU_SULOG_MAX_QUEUED 256U
#define KSU_SULOG_MAX_PAYLOAD_LEN 2048U
#define KSU_SULOG_MAX_ARG_STRINGS 0x7FFFFFFF
#define KSU_SULOG_MAX_ARG_CHUNK 256U
#define KSU_SULOG_MAX_FILENAME_LEN 256U

static struct ksu_event_queue sulog_queue;

struct ksu_sulog_pending_event {
	__u16 event_type;
	void *payload;
	__u32 payload_len;
};

struct ksu_sulog_identity {
	__u32 uid;
	__u32 euid;
};

static void ksu_sulog_fill_task_info(struct ksu_sulog_event *event, __u16 event_type, int retval)
{
	event->version = KSU_SULOG_EVENT_VERSION;
	event->event_type = event_type;
	event->retval = retval;
	event->pid = task_pid_nr(current);
	event->tgid = task_tgid_nr(current);
	event->ppid = task_ppid_nr(current);
	event->uid = current_uid().val;
	event->euid = current_euid().val;
	get_task_comm(event->comm, current);
}

static void ksu_sulog_set_identity(struct ksu_sulog_event *event, const struct ksu_sulog_identity *identity)
{
	if (!identity)
		return;

	event->uid = identity->uid;
	event->euid = identity->euid;
}

static struct ksu_sulog_pending_event *ksu_sulog_capture(__u16 event_type, const char *bprm_argv, size_t bprm_argv_len, gfp_t gfp)
{
	struct ksu_sulog_pending_event *pending = NULL;
	struct ksu_sulog_event *event;
	void *payload = NULL;
	__u32 payload_len;
	__u32 filename_len;
	__u32 argv_len;
	__u32 remaining;
	char *filename_buf;
	bool should_skip_copy = false;

	if (!ksu_sulog_is_enabled())
		return NULL;
	
	if (event_type == KSU_SULOG_EVENT_IOCTL_GRANT_ROOT || event_type == KSU_SULOG_EVENT_SUCOMPAT) {
		filename_len = 0;
		argv_len = 0;
		should_skip_copy = true;
		goto alloc;
	}

	if (!bprm_argv)
		return NULL;

	if (!bprm_argv_len)
		return NULL;

	if (bprm_argv_len <= 0)
		return NULL;

alloc:
	pending = kzalloc(sizeof(*pending), gfp);
	if (!pending)
		goto out_drop;

	payload = kzalloc(KSU_SULOG_MAX_PAYLOAD_LEN, gfp);
	if (!payload)
		goto out_free_pending;

	event = payload;
	ksu_sulog_fill_task_info(event, event_type, 0);

	if (should_skip_copy)
		goto skip_copy;

	remaining = KSU_SULOG_MAX_PAYLOAD_LEN - sizeof(*event);
	filename_buf = (char *)payload + sizeof(*event);

	size_t actual_copy_len = bprm_argv_len;
	
	if (bprm_argv_len > remaining - 1)
		actual_copy_len = remaining - 1 ;

	memcpy(filename_buf, bprm_argv, actual_copy_len);
	filename_buf[actual_copy_len] = '\0';

	filename_len = strlen(filename_buf) + 1 ; // argv0 + null terminator

	if (actual_copy_len > filename_len)
		argv_len = actual_copy_len - (filename_len);
	else
		argv_len = 0;

skip_copy:
	event->filename_len = filename_len;
	event->argv_len = argv_len;
	
	payload_len = (__u32)sizeof(*event) + filename_len + argv_len;

	// unlikely
	if (payload_len > KSU_SULOG_MAX_PAYLOAD_LEN || (__u32)sizeof(*event) > payload_len)
		goto out_free_payload;

	pending->event_type = event_type;
	pending->payload = payload;
	pending->payload_len = payload_len;
	return pending;

out_free_payload:
	kfree(payload);
out_free_pending:
	kfree(pending);
out_drop:
	ksu_event_queue_drop(&sulog_queue);
	return NULL;
}

static struct ksu_sulog_pending_event *ksu_sulog_capture_grant_root(const struct ksu_sulog_identity *identity, gfp_t gfp)
{
	struct ksu_sulog_pending_event *pending;
	struct ksu_sulog_event *event;

	pending = ksu_sulog_capture(KSU_SULOG_EVENT_IOCTL_GRANT_ROOT, NULL, 0, gfp);
	if (!pending)
		return NULL;

	event = pending->payload;
	ksu_sulog_set_identity(event, identity);
	return pending;
}

int ksu_sulog_events_init(void)
{
	ksu_event_queue_init(&sulog_queue, KSU_SULOG_MAX_QUEUED, KSU_SULOG_MAX_PAYLOAD_LEN);
	return 0;
}

void ksu_sulog_events_exit(void)
{
	ksu_event_queue_destroy(&sulog_queue);
}

static void ksu_sulog_free_pending(struct ksu_sulog_pending_event *pending)
{
	if (!pending)
		return;
	kfree(pending->payload);
	kfree(pending);
}

void ksu_sulog_emit_pending(struct ksu_sulog_pending_event *pending, int retval, gfp_t gfp)
{
	struct ksu_sulog_event *event;

	if (!pending)
		return;

	event = pending->payload;
	event->retval = retval;
	ksu_event_queue_push(&sulog_queue, pending->event_type, 0, pending->payload, pending->payload_len, gfp);
	ksu_sulog_free_pending(pending);
}

static int ksu_sulog_emit_grant_root(int retval, __u32 uid, __u32 euid, gfp_t gfp)
{
	if (!ksu_sulog_is_enabled())
		return 0;

	struct ksu_sulog_pending_event *pending;
	struct ksu_sulog_identity identity = {
		.uid = uid,
		.euid = euid,
	};

	pending = ksu_sulog_capture_grant_root(&identity, gfp);
	if (!pending)
		return 0;

	ksu_sulog_emit_pending(pending, retval, gfp);
	return 0;
}

static int ksu_sulog_emit(__u16 event_type, const char *bprm_argv, size_t bprm_argv_len, gfp_t gfp)
{
	if (!ksu_sulog_is_enabled())
		return 0;

	struct ksu_sulog_pending_event *pending;

	pending = ksu_sulog_capture(event_type, bprm_argv, bprm_argv_len, gfp);
	if (!pending)
		return 0;

	ksu_sulog_emit_pending(pending, 0, gfp);
	return 0;
}

static noinline void do_ksu_sulog_emit_bprm(const char *filename)
{
	// maybe tag the process instead?
	if (!is_ksu_domain())
		return;

	if (!current->mm)
		return;

	unsigned long arg_start = current->mm->arg_start;
	unsigned long arg_end = current->mm->arg_end;
	size_t arg_len = arg_end - arg_start;

	if (arg_len <= 0)
		return;

#define ARGV_MAX_BPRM 128
	char args[ARGV_MAX_BPRM] = {0};

	size_t argv_copy_len = (arg_len > ARGV_MAX_BPRM) ? ARGV_MAX_BPRM : arg_len;

	// we cant use strncpy on here, else it will truncate once it sees \0
	if (copy_from_user_retry(args, (void __user *)arg_start, argv_copy_len))
		return;

	args[argv_copy_len - 1] = '\0';

	// we grab strlen of argv0 as that needs to be kept as \0, basically to skip it
	size_t argv0_len = strnlen(args, argv_copy_len);
	char *buf = args + argv0_len + 1;

flatten:
	if (buf >= args + argv_copy_len - 1)
		goto flatten_done;

	int len = strlen(buf);
	if (!len)
		goto flatten_done;
	
	*(buf + len) = ' ';
	buf = buf + len + 1;

	if (buf - args < argv_copy_len - argv0_len - 1)
		goto flatten;

flatten_done:
	//	this should look like
	//      /system/bin/sh\0-c sh -c id
	ksu_sulog_emit(KSU_SULOG_EVENT_ROOT_EXECVE, args, argv_copy_len, GFP_KERNEL);
}

struct ksu_event_queue *ksu_sulog_get_queue(void)
{
	return &sulog_queue;
}
