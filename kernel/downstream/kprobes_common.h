#ifndef __KSU_H_KPROBES_COMMON
#define __KSU_H_KPROBES_COMMON

// heapified kprobe registration, copied from upstream
static struct kprobe *init_kprobe(const char *name, kprobe_pre_handler_t handler)
{
	struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
	if (!kp)
		return nullptr;

	kp->symbol_name = name;
	kp->pre_handler = handler;

	int ret = register_kprobe(kp);
	pr_info("%s: register %s kprobe: %d\n", __func__, name, ret);
	if (ret) {
		kfree(kp);
		return nullptr;
	}

	return kp;
}

static void destroy_kprobe(struct kprobe **kp_ptr)
{
	struct kprobe *kp = *kp_ptr;
	if (!kp)
		return;

	unregister_kprobe(kp);
	synchronize_rcu();
	kfree(kp);
	*kp_ptr = nullptr;
}

#endif // __KSU_H_KPROBES_COMMON

