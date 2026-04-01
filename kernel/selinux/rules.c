#include "linux/rcupdate.h"
#include "security.h"
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/lockdep.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/rwlock.h>

#include "../klog.h" // IWYU pragma: keep
#include "selinux.h"
#include "sepolicy.h"
#include "ss/services.h"
#include "linux/lsm_audit.h" // IWYU pragma: keep
#include "xfrm.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define SELINUX_POLICY_INSTEAD_SELINUX_SS
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0) && \
    !defined(KSU_COMPAT_HAS_POLICY_MUTEX)

static struct policydb *get_policydb(void)
{
    struct policydb *db;
#ifdef KSU_COMPAT_USE_SELINUX_STATE
#ifdef SELINUX_POLICY_INSTEAD_SELINUX_SS
#error It should not happen!
#else
    struct selinux_ss *ss = selinux_state.ss;
    db = &ss->policydb;
#endif
#else
    db = &policydb;
#endif
    return db;
}

#ifndef KSU_COMPAT_USE_SELINUX_STATE
#ifdef KSU_COMPAT_HAS_EXPORTED_POLICY_RWLOCK
extern rwlock_t policy_rwlock;
#else
DEFINE_MUTEX(ksu_rules);
#endif
#endif

static inline void ksu_lock_sepolicy_legacy(void)
{
#if defined(KSU_COMPAT_USE_SELINUX_STATE) && \
    !defined(SELINUX_POLICY_INSTEAD_SELINUX_SS)
    write_lock_irq(&selinux_state.ss->policy_rwlock);
#elif defined(KSU_COMPAT_HAS_EXPORTED_POLICY_RWLOCK)
    write_lock_irq(&policy_rwlock);
#else
    mutex_lock(&ksu_rules);
#endif
}

static inline void ksu_unlock_sepolicy_legacy(void)
{
#if defined(KSU_COMPAT_USE_SELINUX_STATE) && \
    !defined(SELINUX_POLICY_INSTEAD_SELINUX_SS)
    write_unlock_irq(&selinux_state.ss->policy_rwlock);
#elif defined(KSU_COMPAT_HAS_EXPORTED_POLICY_RWLOCK)
    write_unlock_irq(&policy_rwlock);
#else
    mutex_unlock(&ksu_rules);
#endif
}

#endif

#define ALL NULL

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
extern int avc_ss_reset(u32 seqno);
#else
extern int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
#endif
// reset avc cache table, otherwise the new rules will not take effect if already denied
static void reset_avc_cache()
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    avc_ss_reset(0);
    selnl_notify_policyload(0);
    selinux_status_update_policyload(0);
#else
    struct selinux_avc *avc = NULL;
    avc_ss_reset(avc, 0);
    selnl_notify_policyload(0);
    selinux_status_update_policyload(0);
#endif
    selinux_xfrm_notify_policyload();
}

void apply_kernelsu_rules()
{
    struct policydb *db;

    if (!getenforce()) {
        pr_info("SELinux permissive or disabled, apply rules!\n");
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || \
    defined(KSU_COMPAT_HAS_POLICY_MUTEX)
    struct selinux_policy *pol, *old_pol = selinux_state.policy;
    mutex_lock(&selinux_state.policy_mutex);
    pol = ksu_dup_sepolicy(rcu_dereference_protected(
        old_pol, lockdep_is_held(&selinux_state.policy_mutex)));
    if (!pol) {
        pr_err("failed to dup selinux_policy\n");
        goto out_unlock;
    }
    db = &pol->policydb;
#else
    ksu_lock_sepolicy_legacy();
    db = get_policydb();
#endif

    ksu_permissive(db, KERNEL_SU_DOMAIN);
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "mlstrustedsubject");
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "netdomain");
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "bluetoothdomain");

    // KernelSU file type - restricted access
    ksu_type(db, KERNEL_SU_FILE, "file_type");
    ksu_typeattribute(db, KERNEL_SU_FILE, "mlstrustedobject");
    // Only allow trusted domains to access KernelSU files
    ksu_allow(db, KERNEL_SU_DOMAIN, KERNEL_SU_FILE, ALL, ALL);
    ksu_allow(db, "init", KERNEL_SU_FILE, ALL, ALL);
    ksu_allow(db, "zygote", KERNEL_SU_FILE, ALL, ALL);
	
	// Zygote permissions for Zygisk - using stock types only
	ksu_allow(db, "zygote", "adb_data_file", "dir", "search");
	ksu_allow(db, "zygote", "adb_data_file", "dir", "read");
	ksu_allow(db, "zygote", "adb_data_file", "dir", "open");
	ksu_allow(db, "zygote", "adb_data_file", "file", "read");
	ksu_allow(db, "zygote", "adb_data_file", "file", "open");
	ksu_allow(db, "zygote", "adb_data_file", "file", "execute");
	ksu_allow(db, "zygote", "adb_data_file", "file", "execute_no_trans");
	ksu_allow(db, "zygote", "adb_data_file", "file", "map");
	ksu_allow(db, "zygote", "adb_data_file", "file", "getattr");
	
	// Allow zygote to execute system libraries (for module loading)
	ksu_allow(db, "zygote", "system_file", "file", "execute");
	ksu_allow(db, "zygote", "system_file", "file", "execute_no_trans");
	ksu_allow(db, "zygote", "system_file", "file", "map");
	
	// Zygote ptrace capabilities (for injection)
	ksu_allow(db, "zygote", "zygote", "capability", "sys_ptrace");
	ksu_allow(db, "zygote", "zygote", "process", "ptrace");
	
	// Allow zygote to interact with KernelSU domain
	ksu_allow(db, "zygote", KERNEL_SU_DOMAIN, "file", "read");
	ksu_allow(db, "zygote", KERNEL_SU_DOMAIN, "file", "open");
	ksu_allow(db, "zygote", KERNEL_SU_DOMAIN, "dir", "search");
	ksu_allow(db, "zygote", KERNEL_SU_DOMAIN, "dir", "read");
	ksu_allow(db, "zygote", KERNEL_SU_DOMAIN, "fd", "use");
	ksu_allow(db, "zygote", KERNEL_SU_DOMAIN, "unix_stream_socket", "connectto");
	ksu_allow(db, "zygote", KERNEL_SU_DOMAIN, "unix_stream_socket", "read");
	ksu_allow(db, "zygote", KERNEL_SU_DOMAIN, "unix_stream_socket", "write");
	
	// Memfd/tmpfs for module loading
	ksu_allow(db, "zygote", "zygote", "capability", "ipc_lock");
	ksu_allow(db, "zygote", "tmpfs", "file", "read");
	ksu_allow(db, "zygote", "tmpfs", "file", "write");
	ksu_allow(db, "zygote", "tmpfs", "file", "execute");
	ksu_allow(db, "zygote", "tmpfs", "file", "map");

	// KernelSU domain full permissions
	ksu_allow(db, KERNEL_SU_DOMAIN, ALL, ALL, ALL);

	// ioctl permissions
	if (db->policyvers >= POLICYDB_VERSION_XPERMS_IOCTL) {
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "blk_file", ALL);
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "fifo_file", ALL);
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "chr_file", ALL);
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "file", ALL);
	}

	// Init can trigger ksud
	ksu_allow(db, "init", KERNEL_SU_DOMAIN, ALL, ALL);

	
	// Kernel domain - specific permissions only
	ksu_allow(db, "kernel", "adb_data_file", "dir", "search");
	ksu_allow(db, "kernel", "adb_data_file", "dir", "read");
	ksu_allow(db, "kernel", "adb_data_file", "dir", "open");
	ksu_allow(db, "kernel", "adb_data_file", "file", "read");
	ksu_allow(db, "kernel", "adb_data_file", "file", "open");
	ksu_allow(db, "kernel", "adb_data_file", "file", "execute");
	ksu_allow(db, "kernel", "adb_data_file", "file", "execute_no_trans");
	ksu_allow(db, "kernel", "adb_data_file", "file", "getattr");
	ksu_allow(db, "kernel", "system_file", "file", "execute");
	ksu_allow(db, "kernel", "system_file", "file", "execute_no_trans");
	ksu_allow(db, "kernel", "toolbox_exec", "file", "execute");
	ksu_allow(db, "kernel", "toolbox_exec", "file", "execute_no_trans");
	ksu_allow(db, "kernel", "kernel", "capability", "dac_override");
	ksu_allow(db, "kernel", "kernel", "capability", "dac_read_search");
	
	// Magisk-style rules for compatibility
	// suRights
	ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "search");
	ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "read");
	ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "open");
	ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "read");
	ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "process", "getattr");
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "process", "sigchld");

	// allowLog
	ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "dir", "search");
	ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "read");
	ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "open");
	ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "getattr");

	// dumpsys
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fd", "use");
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "write");
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "read");
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "open");
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "getattr");

	// bootctl
	ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "dir", "search");
	ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "read");
	ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "open");
	ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "process", "getattr");

	// Allow all binder transactions
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "binder", ALL);

	// Allow system server kill su process
	ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "getpgid");
	ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "sigkill");

#ifdef CONFIG_KSU_SUSFS
	susfs_set_priv_app_sid();
	susfs_set_init_sid();
	susfs_set_ksu_sid();
	susfs_set_zygote_sid();
#endif // #ifdef CONFIG_KSU_SUSFS

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || \
    defined(KSU_COMPAT_HAS_POLICY_MUTEX)
    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);
    reset_avc_cache();
out_unlock:
    mutex_unlock(&selinux_state.policy_mutex);
#else
    ksu_unlock_sepolicy_legacy();
    reset_avc_cache();
#endif
}

#define KSU_SEPOLICY_MAX_BATCH_SIZE (8U * 1024U * 1024U)
#define KSU_SEPOLICY_MAX_ARGS 5

#define CMD_NORMAL_PERM 1
#define CMD_XPERM 2
#define CMD_TYPE_STATE 3
#define CMD_TYPE 4
#define CMD_TYPE_ATTR 5
#define CMD_ATTR 6
#define CMD_TYPE_TRANSITION 7
#define CMD_TYPE_CHANGE 8
#define CMD_GENFSCON 9

#define SUBCMD_NORMAL_PERM_ALLOW 1
#define SUBCMD_NORMAL_PERM_DENY 2
#define SUBCMD_NORMAL_PERM_AUDITALLOW 3
#define SUBCMD_NORMAL_PERM_DONTAUDIT 4

#define SUBCMD_XPERM_ALLOW 1
#define SUBCMD_XPERM_AUDITALLOW 2
#define SUBCMD_XPERM_DONTAUDIT 3

#define SUBCMD_TYPE_STATE_PERMISSIVE 1
#define SUBCMD_TYPE_STATE_ENFORCE 2

#define SUBCMD_TYPE_CHANGE_CHANGE 1
#define SUBCMD_TYPE_CHANGE_MEMBER 2

struct sepol_data {
	u32 cmd;
	u32 subcmd;
};

struct sepol_batch_cursor {
    const u8 *cur;
    const u8 *end;
};

static size_t sepol_remaining(const struct sepol_batch_cursor *cursor)
{
    return (size_t)(cursor->end - cursor->cur);
}

static int sepol_read_cmd_header(struct sepol_batch_cursor *cursor,
                                 struct sepol_data *header)
{
    if (sepol_remaining(cursor) < sizeof(*header)) {
        return -EINVAL;
    }

    memcpy(header, cursor->cur, sizeof(*header));
    cursor->cur += sizeof(*header);

    return 0;
}

static int sepol_read_string(struct sepol_batch_cursor *cursor,
                             const char **out)
{
    u32 len;
    const char *str;

    if (sepol_remaining(cursor) < sizeof(len)) {
        return -EINVAL;
    }

    memcpy(&len, cursor->cur, sizeof(len));
    cursor->cur += sizeof(len);


    if (len >= sepol_remaining(cursor)) {


        return -EINVAL;
    }

    str = (const char *)cursor->cur;
    if (memchr(str, '\0', len) != NULL || str[len] != '\0') {
        return -EINVAL;
    }



    cursor->cur += len + 1;
    if (len == 0) {
        *out = ALL;
        return 0;
    }


    *out = str;
    return 0;
}



static int sepol_require_not_all(const char *value, const char *name)
{
    if (value != ALL) {
        return 0;
    }

    pr_err("sepol: %s cannot be ALL.\n", name);
    return -EINVAL;
}


static int sepol_expected_argc(u32 cmd)
{
    switch (cmd) {
    case CMD_NORMAL_PERM:
        return 4;
    case CMD_XPERM:
        return 5;
    case CMD_TYPE_STATE:
        return 1;
    case CMD_TYPE:
    case CMD_TYPE_ATTR:
        return 2;
    case CMD_ATTR:
        return 1;
    case CMD_TYPE_TRANSITION:
        return 5;
    case CMD_TYPE_CHANGE:
        return 4;
    case CMD_GENFSCON:
        return 3;
    default:
        return -EINVAL;
    }
}

static int apply_one_sepolicy_cmd(struct policydb *db,
                                  const struct sepol_data *header,
                                  const char **args)
{
    bool success = false;
    int ret;

    switch (header->cmd) {
    case CMD_NORMAL_PERM:
        if (header->subcmd == SUBCMD_NORMAL_PERM_ALLOW) {
            success = ksu_allow(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == SUBCMD_NORMAL_PERM_DENY) {
            success = ksu_deny(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == SUBCMD_NORMAL_PERM_AUDITALLOW) {
            success = ksu_auditallow(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == SUBCMD_NORMAL_PERM_DONTAUDIT) {
            success = ksu_dontaudit(db, args[0], args[1], args[2], args[3]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case CMD_XPERM:
        ret = sepol_require_not_all(args[3], "operation");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[4], "perm_set");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == SUBCMD_XPERM_ALLOW) {
            success = ksu_allowxperm(db, args[0], args[1], args[2], args[4]);
        } else if (header->subcmd == SUBCMD_XPERM_AUDITALLOW) {
            success =
                ksu_auditallowxperm(db, args[0], args[1], args[2], args[4]);
        } else if (header->subcmd == SUBCMD_XPERM_DONTAUDIT) {
            success =
                ksu_dontauditxperm(db, args[0], args[1], args[2], args[4]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case CMD_TYPE_STATE:
        ret = sepol_require_not_all(args[0], "type");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == SUBCMD_TYPE_STATE_PERMISSIVE) {
            success = ksu_permissive(db, args[0]);
        } else if (header->subcmd == SUBCMD_TYPE_STATE_ENFORCE) {
            success = ksu_enforce(db, args[0]);

        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case CMD_TYPE:
    case CMD_TYPE_ATTR:
        ret = sepol_require_not_all(args[0], "type");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "attribute");
        if (ret < 0) {
            return ret;
        }

        if (header->cmd == CMD_TYPE) {
            success = ksu_type(db, args[0], args[1]);

        } else {
            success = ksu_typeattribute(db, args[0], args[1]);
        }
        if (!success) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    case CMD_ATTR:
        ret = sepol_require_not_all(args[0], "attribute");
        if (ret < 0) {
            return ret;
        }

        if (!ksu_attribute(db, args[0])) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    case CMD_TYPE_TRANSITION: {
        const char *object = ALL;

        ret = sepol_require_not_all(args[0], "src");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "tgt");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "cls");
        if (ret < 0) {
            return ret;

        }
        ret = sepol_require_not_all(args[3], "default_type");
        if (ret < 0) {
            return ret;
        }

        object = args[4];
        success =
            ksu_type_transition(db, args[0], args[1], args[2], args[3], object);
        return success ? 0 : -EINVAL;
    }

    case CMD_TYPE_CHANGE:
        ret = sepol_require_not_all(args[0], "src");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "tgt");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "cls");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[3], "default_type");
        if (ret < 0) {
            return ret;
        }

        if (header->subcmd == SUBCMD_TYPE_CHANGE_CHANGE) {
            success = ksu_type_change(db, args[0], args[1], args[2], args[3]);
        } else if (header->subcmd == SUBCMD_TYPE_CHANGE_MEMBER) {
            success = ksu_type_member(db, args[0], args[1], args[2], args[3]);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", header->subcmd);
        }
        return success ? 0 : -EINVAL;

    case CMD_GENFSCON:
        ret = sepol_require_not_all(args[0], "name");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[1], "path");
        if (ret < 0) {
            return ret;
        }
        ret = sepol_require_not_all(args[2], "context");
        if (ret < 0) {
            return ret;
        }
        if (!ksu_genfscon(db, args[0], args[1], args[2])) {
            pr_err("sepol: %d failed.\n", header->cmd);
            return -EINVAL;
        }
        return 0;

    default:
        pr_err("sepol: unknown cmd: %d\n", header->cmd);
        return -EINVAL;
    }
}

int handle_sepolicy(void __user *user_data, u64 data_len)
{
    struct policydb *db;
    struct sepol_batch_cursor cursor;
    u8 *payload;
    int ret = 0;
    int success_cmd_count = 0;
    u32 cmd_index = 0;

    if (!user_data || !data_len)
        return -EINVAL;

    if (data_len > KSU_SEPOLICY_MAX_BATCH_SIZE)
        return -E2BIG;

    payload = vmalloc((size_t)data_len);
    if (!payload)
        return -ENOMEM;

    if (copy_from_user(payload, user_data, (size_t)data_len)) {
        ret = -EFAULT;
        goto out_free;
    }

    if (!getenforce()) {
        pr_info("SELinux permissive or disabled when handle policy!\n");
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || \
    defined(KSU_COMPAT_HAS_POLICY_MUTEX)
    struct selinux_policy *pol, *old_pol;
    mutex_lock(&selinux_state.policy_mutex);
    old_pol = selinux_state.policy;
    pol = ksu_dup_sepolicy(rcu_dereference_protected(
        old_pol, lockdep_is_held(&selinux_state.policy_mutex)));
    if (!pol) {
        ret = -ENOMEM;
        goto out_unlock;
    }
    db = &pol->policydb;
#else
    ksu_lock_sepolicy_legacy();
    db = get_policydb();
#endif

    cursor.cur = payload;
    cursor.end = payload + (size_t)data_len;

    ret = 0;
    success_cmd_count = 0;
    cmd_index = 0;
    while (cursor.cur < cursor.end) {
        struct sepol_data header;
        const char *args[KSU_SEPOLICY_MAX_ARGS] = { 0 };
        int expected_argc;
        u32 arg_index;

        ret = sepol_read_cmd_header(&cursor, &header);
        if (ret < 0) {
            pr_err("sepol: failed to read cmd header #%u.\n", cmd_index);
            goto out_drop_new_policy;
        }

        expected_argc = sepol_expected_argc(header.cmd);
        if (expected_argc < 0 || expected_argc > KSU_SEPOLICY_MAX_ARGS) {
            ret = -EINVAL;
            pr_err("sepol: invalid cmd header #%u.\n", cmd_index);
            goto out_drop_new_policy;
        }

        for (arg_index = 0; arg_index < (u32)expected_argc; arg_index++) {
            ret = sepol_read_string(&cursor, &args[arg_index]);
            if (ret < 0) {
                pr_err("sepol: failed to read cmd #%u arg #%u.\n", cmd_index,
                       arg_index);
                goto out_drop_new_policy;
            }
        }

        ret = apply_one_sepolicy_cmd(db, &header, args);
        if (ret < 0) {
            pr_err("sepol: cmd #%u failed, cmd=%u subcmd=%u.\n", cmd_index,
                   header.cmd, header.subcmd);
        } else {
            success_cmd_count++;
        }
        cmd_index++;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) || \
    defined(KSU_COMPAT_HAS_POLICY_MUTEX)
    rcu_assign_pointer(selinux_state.policy, pol);
    synchronize_rcu();
    ksu_destroy_sepolicy(old_pol);
    reset_avc_cache();
    ret = success_cmd_count;
    goto out_unlock;

out_drop_new_policy:
    ksu_destroy_sepolicy(pol);
out_unlock:
    mutex_unlock(&selinux_state.policy_mutex);
#else
    ksu_unlock_sepolicy_legacy();
    reset_avc_cache();
    ret = success_cmd_count;
    goto out_free;

out_drop_new_policy:
    ksu_unlock_sepolicy_legacy();
#endif
out_free:
    vfree(payload);
    return ret;
}
