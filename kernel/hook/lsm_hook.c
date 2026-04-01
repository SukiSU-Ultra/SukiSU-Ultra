#ifdef CONFIG_KSU_LSM_HOOKS
#define LSM_HOOK_TYPE static int
#else
#define LSM_HOOK_TYPE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_IS_HW_HISI) ||                                     \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
LSM_HOOK_TYPE ksu_key_permission(key_ref_t key_ref, const struct cred *cred, unsigned perm)
{
    if (init_session_keyring != NULL) {
        return 0;
    }

    if (strcmp(current->comm, "init")) {
        // we are only interested in `init` process
        return 0;
    }
    init_session_keyring = cred->session_keyring;
    pr_info("kernel_compat: got init_session_keyring\n");
    return 0;
}
#endif

#ifdef CONFIG_KSU_SUSFS
static inline bool is_zygote_isolated_service_uid(uid_t uid)
{
    uid %= 100000;
    return (uid >= 99000 && uid < 100000);
}

static inline bool is_zygote_normal_app_uid(uid_t uid)
{
    uid %= 100000;
    return (uid >= 10000 && uid < 19999);
}

extern u32 susfs_zygote_sid;
extern struct cred *ksu_cred;

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
extern void susfs_run_sus_path_loop(void);
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH

static void ksu_handle_extra_susfs_work(void)
{
    const struct cred *saved = override_creds(ksu_cred);

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
    susfs_run_sus_path_loop();
#endif // #ifdef CONFIG_KSU_SUSFS_SUS_PATH

    revert_creds(saved);
}

int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids
    uid_t new_uid = ruid;
    uid_t old_uid = current_uid().val;

    // We only interest in process spwaned by zygote
    if (!susfs_is_sid_equal(current_cred(), susfs_zygote_sid))
        return 0;

    // Check if spawned process is isolated service first, and force to do umount if so
    if (is_zygote_isolated_service_uid(new_uid))
        goto do_umount;

    // - Since ksu maanger app uid is excluded in allow_list_arr, so ksu_uid_should_umount(manager_uid)
    //   will always return true, that's why we need to explicitly check if new_uid belongs to
    //   ksu manager
    if (likely(ksu_is_manager_appid_valid()) &&
        unlikely(ksu_get_manager_appid() == new_uid % PER_USER_RANGE))
    {
        disable_seccomp();
        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    // Check if spawned process is normal user app and needs to be umounted
    if (likely(is_zygote_normal_app_uid(new_uid) && ksu_uid_should_umount(new_uid)))
        goto do_umount;

    if (ksu_is_allow_uid_for_current(new_uid)) {
        disable_seccomp();
    }

    return 0;

do_umount:
    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

    // Handle extra susfs work
    ksu_handle_extra_susfs_work();

    // Mark current proc as umounted
    susfs_set_current_proc_umounted();

    return 0;
}
#else
LSM_HOOK_TYPE ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
    uid_t new_uid, old_uid = 0;

    if (unlikely(!new || !old))
        return 0;

    new_uid = new->uid.val;
    old_uid = old->uid.val;

    if (unlikely(is_uid_manager(new_uid))) {
        disable_seccomp();
        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        disable_seccomp();
    }

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

    return 0;
}
#endif

#ifdef CONFIG_KSU_MANUAL_SU
static int ksu_task_alloc_hook(struct task_struct *task, 
                               unsigned long clone_flags)
{
    const struct cred *cred = current_cred();
    
    ksu_try_escalate_for_uid(cred->uid.val);
    
    return 0;
}
#endif

#ifdef CONFIG_KSU_LSM_HOOKS
static struct security_hook_list ksu_hooks[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_IS_HW_HISI) ||                                     \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
    LSM_HOOK_INIT(key_permission, ksu_key_permission),
#endif
#ifndef CONFIG_KSU_SUSFS
    LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
#endif
#ifdef CONFIG_KSU_MANUAL_SU
    LSM_HOOK_INIT(task_alloc, ksu_task_alloc_hook)
#endif
};

void __init ksu_lsm_hook_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
    // https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
    pr_info("LSM hooks initialized.\n");
}
#else
void __init ksu_lsm_hook_init()
{
} /* no opt */
#endif

void ksu_lsm_hook_exit(void)
{
}