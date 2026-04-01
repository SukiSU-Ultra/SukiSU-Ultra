#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

bool ksu_su_compat_enabled __read_mostly = true;

static const char su_path[] = SU_PATH;
static const char sh_path[] = SH_PATH;
static const char ksud_path[] = KSUD_PATH;

static int su_compat_feature_get(u64 *value)
{
    *value = ksu_su_compat_enabled ? 1 : 0;
    return 0;
}

static int su_compat_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_su_compat_enabled = enable;
    pr_info("su_compat: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
    .feature_id = KSU_FEATURE_SU_COMPAT,
    .name = "su_compat",
    .get_handler = su_compat_feature_get,
    .set_handler = su_compat_feature_set,
};

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
    // To avoid having to mmap a page in userspace, just write below the stack
    // pointer.
    char __user *p = (void __user *)current_user_stack_pointer() - len;

    return copy_to_user(p, d, len) ? NULL : p;
}

static char __user *sh_user_path(void)
{
    return userspace_stack_buffer(sh_path, sizeof(sh_path));
}

static char __user *ksud_user_path(void)
{
    return userspace_stack_buffer(ksud_path, sizeof(ksud_path));
}


#ifdef CONFIG_KSU_SUSFS
extern const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr);
/*
 * return 0 -> No further checks should be required afterwards
 * return non-zero -> Further checks should be continued afterwards
 */
int ksu_handle_execveat_init(struct filename *filename, struct user_arg_ptr *argv_user) {
    if (current->pid != 1 && is_init(get_current_cred())) {
        if (unlikely(strcmp(filename->name, KSUD_PATH) == 0)) {
            char tmp_filename[SUSFS_MAX_LEN_PATHNAME] = {0};
            const char __user *argv_user_ptr = get_user_arg_ptr(*argv_user, 0);
            struct ksu_sulog_pending_event *pending_sucompat = NULL;
            int ret = 0;

            pr_info("hook_manager: escape to root for init executing ksud: %d\n", current->pid);
            escape_to_root_for_init();
            if (ret) {
                pr_err("escape_to_root_for_init() failed: %d\n", ret);
                return ret;
            }
            if (!argv_user_ptr || IS_ERR(argv_user_ptr)) {
                pr_err("!argv_user_ptr || IS_ERR(argv_user_ptr)\n");
                return -EFAULT;
            }
            strncpy(tmp_filename, filename->name, SUSFS_MAX_LEN_PATHNAME - 1);
            pending_sucompat = ksu_sulog_capture_sucompat(tmp_filename, argv_user, GFP_KERNEL);
            ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
            return 0;
        } else if (likely(strstr(filename->name, "/app_process") == NULL &&
                    strstr(filename->name, "/adbd") == NULL) &&
                    !susfs_is_current_proc_umounted())
        {
            pr_info("susfs: mark no sucompat checks for pid: '%d', exec: '%s'\n", current->pid, filename->name);
            susfs_set_current_proc_umounted();
            return 0;
        }
        return -EINVAL;
    }
    return -EINVAL;
}

// the call from execve_handler_pre won't provided correct value for __never_use_argument, use them after fix execve_handler_pre, keeping them for consistence for manually patched code
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
                 void *argv_user, void *__never_use_envp,
                 int *__never_use_flags)
{
    struct filename *filename;
    char tmp_filename[SUSFS_MAX_LEN_PATHNAME] = {0};
    const char __user *argv_user_ptr = get_user_arg_ptr(*((struct user_arg_ptr*)argv_user), 0);
    struct ksu_sulog_pending_event *pending_sucompat = NULL;
    int ret;

    if (unlikely(!filename_ptr))
        return 0;

    filename = *filename_ptr;
    if (IS_ERR(filename))
        return 0;

    if (!ksu_handle_execveat_init(filename, (struct user_arg_ptr*)argv_user))
        return 0;

    if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
        return 0;

    pr_info("ksu_handle_execveat_sucompat: su found\n");

    memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

    ret = escape_with_root_profile();
    if (ret)
        pr_err("escape_with_root_profile() failed: %d\n", ret);

    if (!argv_user_ptr || IS_ERR(argv_user_ptr)) {
        pr_err("!argv_user_ptr || IS_ERR(argv_user_ptr)\n");
        return 0;
    }

    strncpy(tmp_filename, filename->name, SUSFS_MAX_LEN_PATHNAME - 1);
    pending_sucompat = ksu_sulog_capture_sucompat(tmp_filename, (struct user_arg_ptr*)argv_user, GFP_KERNEL);
    ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
    return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
            void *envp, int *flags)
{
    if (ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags))
        return 0;

    return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
                        flags);
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
             int *__unused_flags)
{
    char path[sizeof(su_path) + 1] = {0};

    strncpy_from_user(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
        pr_info("ksu_handle_faccessat: su->sh!\n");
        *filename_user = sh_user_path();
    }

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
int ksu_handle_stat(int *dfd, struct filename **filename, int *flags) {
    if (unlikely(IS_ERR(*filename) || (*filename)->name == NULL))
        return 0;

    if (likely(memcmp((*filename)->name, su_path, sizeof(su_path))))
        return 0;

    pr_info("ksu_handle_stat: su->sh!\n");
    memcpy((void *)((*filename)->name), sh_path, sizeof(sh_path));
    return 0;
}
#else
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    if (unlikely(!filename_user))
        return 0;

    char path[sizeof(su_path) + 1] = {0};

    strncpy_from_user(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
        pr_info("ksu_handle_stat: su->sh!\n");
        *filename_user = sh_user_path();
    }

    return 0;
}
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)

int ksu_handle_devpts(struct inode *inode)
{
    if (!current->mm)
        return 0;

    uid_t uid = current_uid().val;
    if (uid % 100000 < 10000)
        // not untrusted_app, ignore it
        return 0;

    if (!__ksu_is_allow_uid_for_current(uid))
        return 0;

    if (ksu_file_sid) {
        struct inode_security_struct *sec = selinux_inode(inode);
        if (sec)
            sec->sid = ksu_file_sid;
    }

    return 0;
}
#else
__attribute__((hot)) static __always_inline bool __is_su_allowed(const void **ptr_to_check)
{
    barrier();
    if (!ksu_su_compat_enabled)
        return false;

    barrier();
    if (likely(!!current->seccomp.mode))
        return false;

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return false;

    if (unlikely(!ptr_to_check))
        return false;

    if (unlikely(!*ptr_to_check))
        return false;

    return true;
}
#define is_su_allowed(ptr) (__is_su_allowed((const void **)ptr))

static noinline int ksu_sucompat_user_common(const char __user **filename_user, const char *syscall_name,
                                             const bool escalate)
{
    char path[sizeof(su_path)] = { 0 }; // sizeof includes nullterm already!
    long len = ksu_strncpy_from_user_nofault(path, *filename_user, sizeof(path));
    int ret = 0;

    if (unlikely(len <= 0))
        return -EFAULT;

    if (likely(memcmp(path, su_path, sizeof(su_path))))
        return 0;

    if (!escalate)
        goto no_escalate;

    ret = escape_with_root_profile();
    if (!!ret)
        return ret;

    // NOTE: we only check file existence, not exec success!
    struct path kpath = { 0 };
    if (!!kern_path(ksud_path, 0, &kpath))
        goto no_ksud;

    path_put(&kpath);
    pr_info("%s su->ksud!\n", syscall_name);
    *filename_user = ksud_user_path();
    return 0;

no_ksud:
no_escalate:
    pr_info("%s su->sh!\n", syscall_name);
    *filename_user = sh_user_path();
    return 0;
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *__unused_flags)
{
    if (!is_su_allowed(filename_user))
        return 0;

    ksu_sucompat_user_common(filename_user, "faccessat", false);
    return 0;
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    if (!is_su_allowed(filename_user))
        return 0;

    ksu_sucompat_user_common(filename_user, "newfstatat", false);
    return 0;
}

int ksu_handle_execve_sucompat(int *fd, const char __user **filename_user, void *argv, void *__never_use_envp,
                               int *__never_use_flags)
{
    struct ksu_sulog_pending_event *pending_root_execve = NULL;
    int ret = 0;

    if (!is_su_allowed(filename_user))
        return 0;

    pending_root_execve =
        ksu_sulog_capture_sucompat(*filename_user, (const char __user *const __user *)argv, GFP_KERNEL);

    ret = ksu_sucompat_user_common(filename_user, "sys_execve", true);
    ksu_sulog_emit_pending(pending_root_execve, ret, GFP_KERNEL);
    return 0;
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv, void *__never_use_envp,
                                 int *__never_use_flags)
{
    struct ksu_sulog_pending_event *pending_root_execve = NULL;
    int ret = 0;

    if (!is_su_allowed(filename_ptr))
        return 0;

    if (likely(memcmp((void *)(*filename_ptr)->name, su_path, sizeof(su_path))))
        return 0;

    pr_info("do_execveat_common su found\n");

    pending_root_execve =
        ksu_sulog_capture_sucompat((*filename_ptr)->name, (const char __user *const __user *)argv, GFP_KERNEL);

    memcpy((void *)(*filename_ptr)->name, ksud_path, sizeof(ksud_path));

    ret = escape_with_root_profile();
    ksu_sulog_emit_pending(pending_root_execve, ret, GFP_KERNEL);
    return 0;
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
    if (unlikely(ksu_boot_completed)) {
        return 0;
    }

    return ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);
}
#endif

// sucompat: permitted process can execute 'su' to gain root access.
void __init ksu_sucompat_init()
{
    if (ksu_register_feature_handler(&su_compat_handler)) {
        pr_err("Failed to register su_compat feature handler\n");
    }
}

void __exit ksu_sucompat_exit()
{
    ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
