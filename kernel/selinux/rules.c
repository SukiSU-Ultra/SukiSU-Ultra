#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/version.h>

#include "../klog.h" // IWYU pragma: keep
#include "selinux.h"
#include "sepolicy.h"
#include "ss/services.h"
#include "linux/lsm_audit.h"
#include "xfrm.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define SELINUX_POLICY_INSTEAD_SELINUX_SS
#endif

#define KERNEL_SU_DOMAIN "su"
#define KERNEL_SU_FILE "ksu_file"
#define KERNEL_EXEC_TYPE "ksu_exec"
#define ALL NULL

static struct policydb *get_policydb(void)
{
	struct policydb *db;
// selinux_state does not exists before 4.19
#ifdef KSU_COMPAT_USE_SELINUX_STATE
#ifdef SELINUX_POLICY_INSTEAD_SELINUX_SS
	struct selinux_policy *policy = rcu_dereference(selinux_state.policy);
	db = &policy->policydb;
#else
	struct selinux_ss *ss = rcu_dereference(selinux_state.ss);
	db = &ss->policydb;
#endif
#else
	db = &policydb;
#endif
	return db;
}

static DEFINE_MUTEX(ksu_rules);

void ksu_apply_kernelsu_rules()
{
	struct policydb *db;

	if (!ksu_getenforce()) {
		pr_info("SELinux permissive or disabled, apply rules!\n");
	}

	mutex_lock(&ksu_rules);
	
	db = get_policydb();

	ksu_permissive(db, KERNEL_SU_DOMAIN);
	ksu_typeattribute(db, KERNEL_SU_DOMAIN, "mlstrustedsubject");
	ksu_typeattribute(db, KERNEL_SU_DOMAIN, "netdomain");
	ksu_typeattribute(db, KERNEL_SU_DOMAIN, "bluetoothdomain");

	// Create unconstrained file type
	ksu_type(db, KERNEL_SU_FILE, "file_type");
	ksu_typeattribute(db, KERNEL_SU_FILE, "mlstrustedobject");
	ksu_allow(db, ALL, KERNEL_SU_FILE, ALL, ALL);

	// allow all!
	ksu_allow(db, KERNEL_SU_DOMAIN, ALL, ALL, ALL);

	// allow us do any ioctl
	if (db->policyvers >= POLICYDB_VERSION_XPERMS_IOCTL) {
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "blk_file", ALL);
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "fifo_file", ALL);
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "chr_file", ALL);
		ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "file", ALL);
	}

	// we need to save allowlist in /data/adb/ksu
	ksu_allow(db, "kernel", "adb_data_file", "dir", ALL);
	ksu_allow(db, "kernel", "adb_data_file", "file", ALL);
	// we need to search /data/app
	ksu_allow(db, "kernel", "apk_data_file", "file", "open");
	ksu_allow(db, "kernel", "apk_data_file", "dir", "open");
	ksu_allow(db, "kernel", "apk_data_file", "dir", "read");
	ksu_allow(db, "kernel", "apk_data_file", "dir", "search");
	// we may need to do mount on shell
	ksu_allow(db, "kernel", "shell_data_file", "file", ALL);
	// we need to read /data/system/packages.list
	ksu_allow(db, "kernel", "kernel", "capability", "dac_override");
	// Android 10+:
	// http://aospxref.com/android-12.0.0_r3/xref/system/sepolicy/private/file_contexts#512
	ksu_allow(db, "kernel", "packages_list_file", "file", ALL);
	// Kernel 4.4
	ksu_allow(db, "kernel", "packages_list_file", "dir", ALL);
	// Android 9-:
	// http://aospxref.com/android-9.0.0_r61/xref/system/sepolicy/private/file_contexts#360
	ksu_allow(db, "kernel", "system_data_file", "file", ALL);
	ksu_allow(db, "kernel", "system_data_file", "dir", ALL);
	// our ksud triggered by init
	ksu_allow(db, "init", "adb_data_file", "file", ALL);
	ksu_allow(db, "init", "adb_data_file", "dir", ALL); // #1289
	ksu_allow(db, "init", KERNEL_SU_DOMAIN, ALL, ALL);

	// we need to umount modules in zygote
	ksu_allow(db, "zygote", "adb_data_file", "dir", "search");

	// copied from Magisk rules
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
	ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "process",
		  "getattr");

	// For mounting loop devices, mirrors, tmpfs
	ksu_allow(db, "kernel", ALL, "file", "read");
	ksu_allow(db, "kernel", ALL, "file", "write");

	// Allow all binder transactions
	ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "binder", ALL);

	// Allow system server kill su process
	ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "getpgid");
	ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "sigkill");

#ifdef CONFIG_KSU_SUSFS
	// Allow umount in zygote process without installing zygisk
	ksu_allow(db, "zygote", "labeledfs", "filesystem", "unmount");
	susfs_set_init_sid();
	susfs_set_ksu_sid();
	susfs_set_zygote_sid();
#endif

	mutex_unlock(&ksu_rules);
}

#define MAX_SEPOL_LEN 128

#define CMD_NORMAL_PERM 1
#define CMD_XPERM 2
#define CMD_TYPE_STATE 3
#define CMD_TYPE 4
#define CMD_TYPE_ATTR 5
#define CMD_ATTR 6
#define CMD_TYPE_TRANSITION 7
#define CMD_TYPE_CHANGE 8
#define CMD_GENFSCON 9

// keep it!
extern bool ksu_is_compat __read_mostly;

// armv7l kernel compat
#ifdef CONFIG_64BIT
#define usize	u64
#else
#define usize	u32
#endif

struct sepol_data {
	u32 cmd;
	u32 subcmd;
	usize field_sepol1;
	usize field_sepol2;
	usize field_sepol3;
	usize field_sepol4;
	usize field_sepol5;
	usize field_sepol6;
	usize field_sepol7;
};

// ksud 32-bit on arm64 kernel
struct __maybe_unused sepol_data_compat {
	u32 cmd;
	u32 subcmd;
	u32 field_sepol1;
	u32 field_sepol2;
	u32 field_sepol3;
	u32 field_sepol4;
	u32 field_sepol5;
	u32 field_sepol6;
	u32 field_sepol7;
};

static int get_object(char *buf, char __user *user_object, size_t buf_sz,
		      char **object)
{
	if (!user_object) {
		*object = ALL;
		return 0;
	}

	if (strncpy_from_user(buf, user_object, buf_sz) < 0) {
		return -1;
	}

	*object = buf;

	return 0;
}

// reset avc cache table, otherwise the new rules will not take effect if already denied
static void reset_avc_cache()
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0) ||	\
	!defined(KSU_COMPAT_USE_SELINUX_STATE)
	avc_ss_reset(0);
	selnl_notify_policyload(0);
	selinux_status_update_policyload(0);
#else
	struct selinux_avc *avc = selinux_state.avc;
	avc_ss_reset(avc, 0);
	selnl_notify_policyload(0);
	selinux_status_update_policyload(&selinux_state, 0);
#endif
	selinux_xfrm_notify_policyload();
}

int ksu_handle_sepolicy(unsigned long arg3, void __user *arg4)
{
	if (!arg4) {
		return -1;
	}

	if (!ksu_getenforce()) {
		pr_info("SELinux permissive or disabled when handle policy!\n");
	}

	u32 cmd, subcmd;
	char __user *sepol1, *sepol2, *sepol3, *sepol4, *sepol5, *sepol6, *sepol7;

	if (unlikely(ksu_is_compat)) {
		struct sepol_data_compat data_compat;
		if (copy_from_user(&data_compat, arg4, sizeof(struct sepol_data_compat))) {
			pr_err("sepol: copy sepol_data failed.\n");
			return -1;
		}
		pr_info("sepol: running in compat mode!\n");
		sepol1 = compat_ptr(data_compat.field_sepol1);
		sepol2 = compat_ptr(data_compat.field_sepol2);
		sepol3 = compat_ptr(data_compat.field_sepol3);
		sepol4 = compat_ptr(data_compat.field_sepol4);
		sepol5 = compat_ptr(data_compat.field_sepol5);
		sepol6 = compat_ptr(data_compat.field_sepol6);
		sepol7 = compat_ptr(data_compat.field_sepol7);
		cmd = data_compat.cmd;
		subcmd = data_compat.subcmd;
	} else {
		struct sepol_data data;
		if (copy_from_user(&data, arg4, sizeof(struct sepol_data))) {
			pr_err("sepol: copy sepol_data failed.\n");
			return -1;
		}
		sepol1 = data.field_sepol1;
		sepol2 = data.field_sepol2;
		sepol3 = data.field_sepol3;
		sepol4 = data.field_sepol4;
		sepol5 = data.field_sepol5;
		sepol6 = data.field_sepol6;
		sepol7 = data.field_sepol7;
		cmd = data.cmd;
		subcmd = data.subcmd;
	}

	rcu_read_lock();

	struct policydb *db = get_policydb();

	int ret = -1;
	if (cmd == CMD_NORMAL_PERM) {
		char src_buf[MAX_SEPOL_LEN];
		char tgt_buf[MAX_SEPOL_LEN];
		char cls_buf[MAX_SEPOL_LEN];
		char perm_buf[MAX_SEPOL_LEN];

		char *s, *t, *c, *p;
		if (get_object(src_buf, sepol1, sizeof(src_buf), &s) < 0) {
			pr_err("sepol: copy src failed.\n");
			goto exit;
		}

		if (get_object(tgt_buf, sepol2, sizeof(tgt_buf), &t) < 0) {
			pr_err("sepol: copy tgt failed.\n");
			goto exit;
		}

		if (get_object(cls_buf, sepol3, sizeof(cls_buf), &c) < 0) {
			pr_err("sepol: copy cls failed.\n");
			goto exit;
		}

		if (get_object(perm_buf, sepol4, sizeof(perm_buf), &p) <
		    0) {
			pr_err("sepol: copy perm failed.\n");
			goto exit;
		}

		bool success = false;
		if (subcmd == 1) {
			success = ksu_allow(db, s, t, c, p);
		} else if (subcmd == 2) {
			success = ksu_deny(db, s, t, c, p);
		} else if (subcmd == 3) {
			success = ksu_auditallow(db, s, t, c, p);
		} else if (subcmd == 4) {
			success = ksu_dontaudit(db, s, t, c, p);
		} else {
			pr_err("sepol: unknown subcmd: %d\n", subcmd);
		}
		ret = success ? 0 : -1;

	} else if (cmd == CMD_XPERM) {
		char src_buf[MAX_SEPOL_LEN];
		char tgt_buf[MAX_SEPOL_LEN];
		char cls_buf[MAX_SEPOL_LEN];

		char __maybe_unused
			operation[MAX_SEPOL_LEN]; // it is always ioctl now!
		char perm_set[MAX_SEPOL_LEN];

		char *s, *t, *c;
		if (get_object(src_buf, sepol1, sizeof(src_buf), &s) < 0) {
			pr_err("sepol: copy src failed.\n");
			goto exit;
		}
		if (get_object(tgt_buf, sepol2, sizeof(tgt_buf), &t) < 0) {
			pr_err("sepol: copy tgt failed.\n");
			goto exit;
		}
		if (get_object(cls_buf, sepol3, sizeof(cls_buf), &c) < 0) {
			pr_err("sepol: copy cls failed.\n");
			goto exit;
		}
		if (strncpy_from_user(operation, sepol4,
				      sizeof(operation)) < 0) {
			pr_err("sepol: copy operation failed.\n");
			goto exit;
		}
		if (strncpy_from_user(perm_set, sepol5, sizeof(perm_set)) <
		    0) {
			pr_err("sepol: copy perm_set failed.\n");
			goto exit;
		}

		bool success = false;
		if (subcmd == 1) {
			success = ksu_allowxperm(db, s, t, c, perm_set);
		} else if (subcmd == 2) {
			success = ksu_auditallowxperm(db, s, t, c, perm_set);
		} else if (subcmd == 3) {
			success = ksu_dontauditxperm(db, s, t, c, perm_set);
		} else {
			pr_err("sepol: unknown subcmd: %d\n", subcmd);
		}
		ret = success ? 0 : -1;
	} else if (cmd == CMD_TYPE_STATE) {
		char src[MAX_SEPOL_LEN];

		if (strncpy_from_user(src, sepol1, sizeof(src)) < 0) {
			pr_err("sepol: copy src failed.\n");
			goto exit;
		}

		bool success = false;
		if (subcmd == 1) {
			success = ksu_permissive(db, src);
		} else if (subcmd == 2) {
			success = ksu_enforce(db, src);
		} else {
			pr_err("sepol: unknown subcmd: %d\n", subcmd);
		}
		if (success)
			ret = 0;

	} else if (cmd == CMD_TYPE || cmd == CMD_TYPE_ATTR) {
		char type[MAX_SEPOL_LEN];
		char attr[MAX_SEPOL_LEN];

		if (strncpy_from_user(type, sepol1, sizeof(type)) < 0) {
			pr_err("sepol: copy type failed.\n");
			goto exit;
		}
		if (strncpy_from_user(attr, sepol2, sizeof(attr)) < 0) {
			pr_err("sepol: copy attr failed.\n");
			goto exit;
		}

		bool success = false;
		if (cmd == CMD_TYPE) {
			success = ksu_type(db, type, attr);
		} else {
			success = ksu_typeattribute(db, type, attr);
		}
		if (!success) {
			pr_err("sepol: %d failed.\n", cmd);
			goto exit;
		}
		ret = 0;

	} else if (cmd == CMD_ATTR) {
		char attr[MAX_SEPOL_LEN];

		if (strncpy_from_user(attr, sepol1, sizeof(attr)) < 0) {
			pr_err("sepol: copy attr failed.\n");
			goto exit;
		}
		if (!ksu_attribute(db, attr)) {
			pr_err("sepol: %d failed.\n", cmd);
			goto exit;
		}
		ret = 0;

	} else if (cmd == CMD_TYPE_TRANSITION) {
		char src[MAX_SEPOL_LEN];
		char tgt[MAX_SEPOL_LEN];
		char cls[MAX_SEPOL_LEN];
		char default_type[MAX_SEPOL_LEN];
		char object[MAX_SEPOL_LEN];

		if (strncpy_from_user(src, sepol1, sizeof(src)) < 0) {
			pr_err("sepol: copy src failed.\n");
			goto exit;
		}
		if (strncpy_from_user(tgt, sepol2, sizeof(tgt)) < 0) {
			pr_err("sepol: copy tgt failed.\n");
			goto exit;
		}
		if (strncpy_from_user(cls, sepol3, sizeof(cls)) < 0) {
			pr_err("sepol: copy cls failed.\n");
			goto exit;
		}
		if (strncpy_from_user(default_type, sepol4,
				      sizeof(default_type)) < 0) {
			pr_err("sepol: copy default_type failed.\n");
			goto exit;
		}
		char *real_object;
		if (sepol5 == NULL) {
			real_object = NULL;
		} else {
			if (strncpy_from_user(object, sepol5,
					      sizeof(object)) < 0) {
				pr_err("sepol: copy object failed.\n");
				goto exit;
			}
			real_object = object;
		}

		bool success = ksu_type_transition(db, src, tgt, cls,
						   default_type, real_object);
		if (success)
			ret = 0;

	} else if (cmd == CMD_TYPE_CHANGE) {
		char src[MAX_SEPOL_LEN];
		char tgt[MAX_SEPOL_LEN];
		char cls[MAX_SEPOL_LEN];
		char default_type[MAX_SEPOL_LEN];

		if (strncpy_from_user(src, sepol1, sizeof(src)) < 0) {
			pr_err("sepol: copy src failed.\n");
			goto exit;
		}
		if (strncpy_from_user(tgt, sepol2, sizeof(tgt)) < 0) {
			pr_err("sepol: copy tgt failed.\n");
			goto exit;
		}
		if (strncpy_from_user(cls, sepol3, sizeof(cls)) < 0) {
			pr_err("sepol: copy cls failed.\n");
			goto exit;
		}
		if (strncpy_from_user(default_type, sepol4,
				      sizeof(default_type)) < 0) {
			pr_err("sepol: copy default_type failed.\n");
			goto exit;
		}
		bool success = false;
		if (subcmd == 1) {
			success = ksu_type_change(db, src, tgt, cls,
						  default_type);
		} else if (subcmd == 2) {
			success = ksu_type_member(db, src, tgt, cls,
						  default_type);
		} else {
			pr_err("sepol: unknown subcmd: %d\n", subcmd);
		}
		if (success)
			ret = 0;
	} else if (cmd == CMD_GENFSCON) {
		char name[MAX_SEPOL_LEN];
		char path[MAX_SEPOL_LEN];
		char context[MAX_SEPOL_LEN];
		if (strncpy_from_user(name, sepol1, sizeof(name)) < 0) {
			pr_err("sepol: copy name failed.\n");
			goto exit;
		}
		if (strncpy_from_user(path, sepol2, sizeof(path)) < 0) {
			pr_err("sepol: copy path failed.\n");
			goto exit;
		}
		if (strncpy_from_user(context, sepol3, sizeof(context)) <
		    0) {
			pr_err("sepol: copy context failed.\n");
			goto exit;
		}

		if (!ksu_genfscon(db, name, path, context)) {
			pr_err("sepol: %d failed.\n", cmd);
			goto exit;
		}
		ret = 0;
	} else {
		pr_err("sepol: unknown cmd: %d\n", cmd);
	}

exit:
	rcu_read_unlock();

	// only allow and xallow needs to reset avc cache, but we cannot do that because
	// we are in atomic context. so we just reset it every time.
	reset_avc_cache();

	return ret;
}
