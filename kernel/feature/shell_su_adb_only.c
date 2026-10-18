// Apps that manage to run code as the shell uid (e.g. through a system service
// bug) would otherwise inherit the root grant of com.android.shell. When this
// is enabled, a granted shell may only get root if it was spawned by adbd, i.e.
// it is a real `adb shell` session, or by a KernelSU root process (e.g. adb
// daemons provided by modules such as altdb). The latter is no escalation, as
// only processes already granted root by KernelSU run in the ksu domain.
#ifdef KSU_CAN_USE_JUMP_LABEL
static DEFINE_STATIC_KEY_FALSE(ksu_shell_su_adb_only);
#else
static bool ksu_shell_su_adb_only __read_mostly = false;
#endif

// Deny instead of walking an unbounded chain of ancestors
#define MAX_ANCESTOR_DEPTH 128

static noinline bool has_trusted_ancestor(void)
{
	struct task_struct *t;
	int depth = 0;
	bool found = false;

	rcu_read_lock();
	// Stop at init: orphans reparented to it are not attached to a session any more
	for (t = current; t->pid > 1 && depth < MAX_ANCESTOR_DEPTH; t = rcu_dereference(t->real_parent), depth++) {
		const struct cred *cred = __task_cred(t);
		if (is_adbd(cred) || is_task_ksu_domain(cred)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found;
}

static inline bool ksu_shell_su_allowed_for_current(void)
{
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (!static_branch_unlikely(&ksu_shell_su_adb_only)) {
		return true;
	}
#else
	if (likely(!ksu_shell_su_adb_only))
		return true;
#endif

	return has_trusted_ancestor();
}

static int shell_su_adb_only_feature_get(u64 *value)
{
#ifdef KSU_CAN_USE_JUMP_LABEL
	*value = static_key_enabled(&ksu_shell_su_adb_only) ? 1 : 0;
#else
	*value = ksu_shell_su_adb_only ? 1 : 0;
#endif
	return 0;
}

static int shell_su_adb_only_feature_set(u64 value)
{
	bool enable = value != 0;
#ifdef KSU_CAN_USE_JUMP_LABEL
	if (enable) {
		static_key_enable(&ksu_shell_su_adb_only.key);
	} else {
		static_key_disable(&ksu_shell_su_adb_only.key);
	}
#else
	ksu_shell_su_adb_only = !!enable;
#endif
	smp_mb();
	pr_info("shell_su_adb_only: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler shell_su_adb_only_handler = {
	.feature_id = KSU_FEATURE_SHELL_SU_ADB_ONLY,
	.name = "shell_su_adb_only",
	.get_handler = shell_su_adb_only_feature_get,
	.set_handler = shell_su_adb_only_feature_set,
};

void __init ksu_shell_su_adb_only_init(void)
{
	if (ksu_register_feature_handler(&shell_su_adb_only_handler)) {
		pr_err("Failed to register shell_su_adb_only feature handler\n");
	}
}

void __exit ksu_shell_su_adb_only_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_SHELL_SU_ADB_ONLY);
}
