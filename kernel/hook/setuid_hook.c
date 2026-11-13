static __always_inline void ksu_handle_setresuid_cred(struct cred *new, const struct cred *old)
{
	if (!new || !old)
		return;

	uid_t new_uid = ksu_get_uid_t(new->uid);
	uid_t old_uid = ksu_get_uid_t(old->uid);

	// old process is not root, ignore it.
	if (unlikely(!!old_uid))
		return;

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

	// we dont have those new fancy things upstream has
	// lets just do the original thing where we disable seccomp
	if (unlikely(is_uid_manager(new_uid)))
		goto install_ksu_fd;

	if (ksu_is_allow_uid_for_current(new_uid))
		goto kill_seccomp;

	// Handle kernel umount
	ksu_handle_umount(new, old);
	return;

install_ksu_fd:
	pr_info("install fd for manager: %d\n", new_uid);
	ksu_install_fd();

kill_seccomp:
	disable_seccomp();
	set_thread_flag(TIF_KSU_MANAGED); // sucompat fast-path
	return;
}

#ifdef CONFIG_KSU_SUSFS
/*
 * Entry point for the SUSFS kernel/sys.c inline hook in __sys_setresuid().
 * Upstream KernelSU distinguishes zygote/zygote_next children by their
 * SELinux domain here, so the kernel does not need an LSM task_fix_setuid
 * hook at all (the LSM variants skip it when SUSFS is enabled).
 */
extern u32 susfs_zygote_sid;
extern u32 susfs_zygote_next_sid;
extern int ksu_handle_umount_from_zygote(uid_t old_uid, uid_t new_uid);
extern struct work_struct susfs_extra_works;

static inline void ksu_handle_extra_susfs_work(void)
{
	if (work_pending(&susfs_extra_works))
		return;

	schedule_work(&susfs_extra_works);
}

static int handle_zygote_setresuid(uid_t ruid)
{
	// Check if spawned process is isolated service first, and force to do umount if so
	if (is_isolated_process(ruid)) {
		susfs_set_current_proc_no_su();
		susfs_set_current_proc_umounted();
		goto do_umount;
	}

	// - Since ksu manager app uid is excluded in allow_list_arr, so ksu_uid_should_umount(manager_uid)
	//   will always return true, that's why we need to explicitly check if new_uid belongs to
	//   ksu manager.
	// - Disable seccomp restriction for KSU manager since running with "su" will disable seccomp anyway
	if (likely(ksu_is_manager_appid_valid()) && unlikely(is_uid_manager(ruid))) {
		disable_seccomp();
		pr_info("install fd for manager: %d\n", ruid);
		ksu_install_fd();
		return 0;
	}

	// - Check if spawned process is normal user app and needs to be umounted
	// - Now app_profile for webview_zygote is available in KernelSU manager
	if (likely(is_appuid(ruid) && ksu_uid_should_umount(ruid))) {
		susfs_set_current_proc_no_su();
		susfs_set_current_proc_umounted();
		goto do_umount;
	}

	// Disable seccomp restriction for root allowed apps since running with "su" will disable seccomp anyway
	if (ksu_is_allow_uid_for_current(ruid)) {
		disable_seccomp();
		return 0;
	}

	// Process not umounted but also root not allowed
	susfs_set_current_proc_no_su();
	return 0;

do_umount:
	// Handle kernel umount
	ksu_handle_umount_from_zygote(current_uid().val, ruid);

	// Handle extra susfs work
	ksu_handle_extra_susfs_work();
	return 0;
}

static int handle_zygote_next_setresuid(uid_t ruid)
{
	// Check if spawned process is isolated service first, and force to do umount if so
	if (is_isolated_process(ruid)) {
		susfs_set_current_proc_no_su();
		susfs_set_current_proc_umounted();
		susfs_set_current_proc_umounted_for_zygote_next();
		goto do_susfs_work;
	}

	// - Since ksu manager app uid is excluded in allow_list_arr, so ksu_uid_should_umount(manager_uid)
	//   will always return true, that's why we need to explicitly check if new_uid belongs to
	//   ksu manager.
	// - Disable seccomp restriction for KSU manager since running with "su" will disable seccomp anyway
	if (likely(ksu_is_manager_appid_valid()) && unlikely(is_uid_manager(ruid))) {
		disable_seccomp();
		pr_info("install fd for manager: %d\n", ruid);
		ksu_install_fd();
		return 0;
	}

	// - Check if spawned process is normal user app and needs to be umounted
	// - Now app_profile for webview_zygote is available in KernelSU manager
	if (likely(is_appuid(ruid) && ksu_uid_should_umount(ruid))) {
		susfs_set_current_proc_no_su();
		susfs_set_current_proc_umounted();
		susfs_set_current_proc_umounted_for_zygote_next();
		goto do_susfs_work;
	}

	// Disable seccomp restriction for root allowed apps since running with "su" will disable seccomp anyway
	if (ksu_is_allow_uid_for_current(ruid)) {
		disable_seccomp();
		return 0;
	}

	// Process not umounted but also root not allowed
	susfs_set_current_proc_no_su();
	return 0;

do_susfs_work:
	// Do not umount here as we are in init namespace now

	// Handle extra susfs work
	ksu_handle_extra_susfs_work();
	return 0;
}

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	uid_t cur_uid = current_uid().val;

	if (cur_uid != 0)
		return 0;

	// We only interest in process spawned by zygote or zygote_next
	if (susfs_is_sid_equal(current_cred(), susfs_zygote_sid))
		return handle_zygote_setresuid(ruid);

	if (susfs_is_sid_equal(current_cred(), susfs_zygote_next_sid))
		return handle_zygote_next_setresuid(ruid);

	return 0;
}
#endif // CONFIG_KSU_SUSFS
