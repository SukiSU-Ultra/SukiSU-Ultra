#if LINUX_VERSION_CODE >= KERNEL_VERSION (6, 7, 0)
static struct group_info root_groups = { .usage = REFCOUNT_INIT(2) };
#else
static struct group_info root_groups = { .usage = ATOMIC_INIT(2) };
#endif

static void setup_groups(struct root_profile *profile, struct cred *cred)
{
	if (profile->groups_count > KSU_MAX_GROUPS) {
		pr_warn("Failed to setgroups, too large group: %d!\n",
			profile->uid);
		return;
	}

	if (profile->groups_count == 1 && profile->groups[0] == 0) {
		// setgroup to root and return early.
		if (cred->group_info)
			put_group_info(cred->group_info);
		cred->group_info = get_group_info(&root_groups);
		return;
	}

	u32 ngroups = profile->groups_count;
	struct group_info *group_info = groups_alloc(ngroups);
	if (!group_info) {
		pr_warn("Failed to setgroups, ENOMEM for: %d\n", profile->uid);
		return;
	}

	int i;
	for (i = 0; i < ngroups; i++) {
		gid_t gid = profile->groups[i];
		kgid_t kgid = make_kgid(current_user_ns(), gid);
		if (!gid_valid(kgid)) {
			pr_warn("Failed to setgroups, invalid gid: %d\n", gid);
			put_group_info(group_info);
			return;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
		group_info->gid[i] = kgid;
#else
		GROUP_AT(group_info, i) = kgid;
#endif
	}

	groups_sort(group_info);
	set_groups(cred, group_info);
	put_group_info(group_info);
}

/**
 * lets just have kernel do cleanup for us (put_seccomp_filter/seccomp_filter_release)
 * this is how the kernel does it and we dont have to do all this refcounting shit that
 * upstream does due to 'current->seccomp.filter = NULL;' which is unnecessary
 *
 * see: seccomp_assign_mode, secure_computing
 * - if this has repercussions, then we just restore all those refcounting shit
 */
static void disable_seccomp(void)
{
	spin_lock_irq(&current->sighand->siglock);

	current->seccomp.mode = 0;
	smp_mb();

#if defined(CONFIG_GENERIC_ENTRY) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	clear_syscall_work(SECCOMP);
#else
	clear_thread_flag(TIF_SECCOMP);
#endif
	spin_unlock_irq(&current->sighand->siglock);
}

static int escape_to_root(bool is_forced)
{
	int ret = 0;
	struct cred *cred;
	struct root_profile *profile = NULL;
	struct user_struct *new_user;

	cred = prepare_creds();
	if (!cred) {
		pr_warn("prepare_creds failed!\n");
		return -ENOMEM;
	}

	if (!is_forced && ksu_get_uid_t(cred->euid) == 0) {
		pr_warn("Already root, don't escape!\n");
		goto out_abort_creds;
	}

	if (test_thread_flag(TIF_KSU_DISABLE_ESCAPE_WITH_ROOT)) {
		pr_warn("TIF_KSU_DISABLE_ESCAPE_WITH_ROOT found, don't escape!\n");
		goto out_abort_creds;
	}

	profile = ksu_get_root_profile(ksu_get_uid_t(cred->uid));

	ksu_get_uid_t(cred->uid) = profile->uid;
	ksu_get_uid_t(cred->suid) = profile->uid;
	ksu_get_uid_t(cred->euid) = profile->uid;
	ksu_get_uid_t(cred->fsuid) = profile->uid;

	ksu_get_uid_t(cred->gid) = profile->gid;
	ksu_get_uid_t(cred->fsgid) = profile->gid;
	ksu_get_uid_t(cred->sgid) = profile->gid;
	ksu_get_uid_t(cred->egid) = profile->gid;
	cred->securebits = 0;

	BUILD_BUG_ON(sizeof(profile->capabilities.effective) != sizeof(kernel_cap_t));

	/*
	 * Mirror the kernel set*uid path: update cred->user first, then
	 * cred->ucounts, before commit_creds(). commit_creds() moves
	 * RLIMIT_NPROC accounting based on cred->user; if uid changes while
	 * user/ucounts stay stale, the old charge can remain pinned to the
	 * previous UID.
	 * See kernel/sys.c:set_user() and kernel/cred.c:set_cred_ucounts() /
	 * commit_creds():
	 * https://github.com/torvalds/linux/blob/v5.14/kernel/sys.c
	 * https://github.com/torvalds/linux/blob/v5.14/kernel/cred.c
	 */
	new_user = alloc_uid(cred->uid);
	if (!new_user) {
		ret = -ENOMEM;
		goto out_abort_creds;
	}

	free_uid(cred->user);
	cred->user = new_user;

	// v5.14+ added cred->ucounts, so we must refresh it after changing uid/user:
	// https://github.com/torvalds/linux/commit/905ae01c4ae2ae3df05bb141801b1db4b7d83c61#diff-ff6060da281bd9ef3f24e17b77a9b0b5b2ed2d7208bb69b29107bee69732bd31
	// on older kernels, per-UID process accounting lives in user_struct.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	if (set_cred_ucounts(cred)) {
		goto out_abort_creds;
	}
#endif

	memcpy(&cred->cap_effective, &profile->capabilities.effective, sizeof(cred->cap_effective));
	memcpy(&cred->cap_permitted, &profile->capabilities.effective, sizeof(cred->cap_permitted));
	memcpy(&cred->cap_bset, &profile->capabilities.effective, sizeof(cred->cap_bset));
	if (profile->uid != 0) {
		memcpy(&cred->cap_inheritable, &profile->capabilities.effective, sizeof(cred->cap_inheritable));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0) || defined(PR_CAP_AMBIENT) // torvalds/linux 58319057
		memcpy(&cred->cap_ambient, &profile->capabilities.effective, sizeof(cred->cap_ambient));
#endif
	}

	setup_groups(profile, cred);
	setup_selinux(profile->selinux_domain, cred);

	commit_creds(cred);

	if (ksu_is_seccomp_enabled())
		disable_seccomp();

	if (profile->flags & FLAG_KSU_NO_NEW_PRIVS) {
		set_thread_flag(TIF_KSU_DISABLE_ESCAPE_WITH_ROOT);
	}
	
	setup_mount_ns(profile->namespaces);
	ksu_put_root_profile(profile);
	return 0;

out_abort_creds:
	if (profile)
		ksu_put_root_profile(profile);
	abort_creds(cred);
	return ret;
}

int escape_with_root_profile(void)
{
	return escape_to_root(false);
}

void escape_to_root_forced(void)
{
	// I'm not really sure which permissions are needed
	// its just escape to root but bypasses cred check
	// which we likely already have on contexts where this will be used.
	escape_to_root(true);
}

void __init ksu_app_profile_init(void) { }
