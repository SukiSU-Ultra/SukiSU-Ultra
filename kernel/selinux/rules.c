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

void apply_kernelsu_rules()
{
	if (!getenforce()) {
		pr_info("SELinux permissive or disabled, apply rules!\n");
	}

	rcu_read_lock();
	struct policydb *db = get_policydb();

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

	// Custom rules
	ksu_allow(db, "adsprpcd", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "bootanim", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "bootanim", "userspace_reboot_exported_prop", "file", "getattr");
	ksu_allow(db, "bootanim", "userspace_reboot_exported_prop", "file", "open");
	ksu_allow(db, "bootanim", "userspace_reboot_exported_prop", "file", "read");
	ksu_allow(db, "cameraserver", "system_prop", "property_service", "set");
	ksu_allow(db, "cameraserver", "system_prop", "property_service", "set");
	ksu_allow(db, "cnd", "diag_device", "chr_file", "ioctl");
	ksu_allow(db, "cnd", "diag_device", "chr_file", "open");
	ksu_allow(db, "cnd", "diag_device", "chr_file", "read");
	ksu_allow(db, "cnd", "diag_device", "chr_file", "write");
	ksu_allow(db, "hal_audio_default", "audioserver", "fifo_file", "write");
	ksu_allow(db, "hal_audio_default", "exported_system_prop", "property_service", "set");
	ksu_allow(db, "hal_audio_default", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "hal_bluetooth_qti", "persist_file", "dir", "search");
	ksu_allow(db, "hal_bluetooth_qti", "vendor_default_prop", "property_service", "set");
	ksu_allow(db, "hal_camera_default", "default_prop", "property_service", "set");
	ksu_allow(db, "hal_camera_default", "hal_camera_default", "tcp_socket", "create");
	ksu_allow(db, "hal_camera_default", "sysfs_net", "dir", "search");
	ksu_allow(db, "hal_camera_default", "vendor_shell_exec", "file", "execute_no_trans");
	ksu_allow(db, "hal_cryptoeng_oppo", "vendor_default_prop", "property_service", "set");
	ksu_allow(db, "hal_face_oppo", "default_android_hwservice", "hwservice_manager", "find");
	ksu_allow(db, "hal_face_oppo", "hal_face_oppo", "tcp_socket", "create");
	ksu_allow(db, "hal_face_oppo", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "hal_face_oppo", "oppo_sys_wifi_file", "dir", "search");
	ksu_allow(db, "hal_face_oppo", "oppo_sys_wifi_file", "file", "open");
	ksu_allow(db, "hal_face_oppo", "oppo_sys_wifi_file", "file", "read");
	ksu_allow(db, "hal_face_oppo", "sysfs_kgsl", "dir", "search");
	ksu_allow(db, "hal_face_oppo", "sysfs_kgsl", "file", "open");
	ksu_allow(db, "hal_face_oppo", "sysfs_kgsl", "file", "read");
	ksu_allow(db, "hal_face_oppo", "sysfs_net", "dir", "search");
	ksu_allow(db, "hal_face_oppo", "vendor_shell_exec", "file", "execute_no_trans");
	ksu_allow(db, "hal_face_oppo", "vendor_toolbox_exec", "file", "execute_no_trans");
	ksu_allow(db, "hal_fingerprint_oppo_compat", ALL, ALL, ALL);
	ksu_allow(db, "hal_fingerprintpay_oppo", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "hal_gatekeeper_default", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "hal_graphics_allocator_default", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "hal_graphics_composer_default", "diag_device", "chr_file", "ioctl");
	ksu_allow(db, "hal_graphics_composer_default", "diag_device", "chr_file", "open");
	ksu_allow(db, "hal_graphics_composer_default", "diag_device", "chr_file", "read");
	ksu_allow(db, "hal_graphics_composer_default", "diag_device", "chr_file", "write");
	ksu_allow(db, "hal_graphics_composer_default", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "hal_graphics_composer_default", "persist_file", "dir", "search");
	ksu_allow(db, "hal_health_default", "persist_file", "dir", "search");
	ksu_allow(db, "hal_imsrtp", "diag_device", "chr_file", "ioctl");
	ksu_allow(db, "hal_imsrtp", "diag_device", "chr_file", "open");
	ksu_allow(db, "hal_imsrtp", "diag_device", "chr_file", "read");
	ksu_allow(db, "hal_imsrtp", "diag_device", "chr_file", "write");
	ksu_allow(db, "hal_imsrtp", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "hal_keymaster_default", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "hal_rcsservice", "diag_device", "chr_file", "ioctl");
	ksu_allow(db, "hal_rcsservice", "diag_device", "chr_file", "open");
	ksu_allow(db, "hal_rcsservice", "diag_device", "chr_file", "read");
	ksu_allow(db, "hal_rcsservice", "diag_device", "chr_file", "write");
	ksu_allow(db, "hal_sensors_default", "diag_device", "chr_file", "ioctl");
	ksu_allow(db, "hal_sensors_default", "diag_device", "chr_file", "open");
	ksu_allow(db, "hal_sensors_default", "persist_file", "dir", "search");
	ksu_allow(db, "hal_soter_qti", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "hal_wifi_default", "vendor_tombstone_data_file", "dir", "search");
	ksu_allow(db, "hwservicemanager", "init", "binder", "transfer");
	ksu_allow(db, "init", "at_device", "chr_file", "getattr");
	ksu_allow(db, "init", "audio_device", "chr_file", "getattr");
	ksu_allow(db, "init", "avtimer_device", "chr_file", "getattr");
	ksu_allow(db, "init", "block_device", "blk_file", "ioctl");
	ksu_allow(db, "init", "bt_device", "chr_file", "getattr");
	ksu_allow(db, "init", "cache_block_device", "blk_file", "ioctl");
	ksu_allow(db, "init", "device", "blk_file", "ioctl");
	ksu_allow(db, "init", "device", "blk_file", "write");
	ksu_allow(db, "init", "device", "chr_file", "getattr");
	ksu_allow(db, "init", "device_latency", "chr_file", "getattr");
	ksu_allow(db, "init", "dex2oat_exec", "file", "getattr");
	ksu_allow(db, "init", "diag_device", "chr_file", "getattr");
	ksu_allow(db, "init", "fingerprintd_device", "chr_file", "getattr");
	ksu_allow(db, "init", "fuse_device", "chr_file", "getattr");
	ksu_allow(db, "init", "gpu_device", "chr_file", "getattr");
	ksu_allow(db, "init", "graphics_device", "chr_file", "getattr");
	ksu_allow(db, "init", "hal_fingerprint_hwservice", "hwservice_manager", "add");
	ksu_allow(db, "init", "hal_fingerprint_hwservice", "hwservice_manager", "find");
	ksu_allow(db, "init", "hal_fingerprint_oppo", "binder", "call");
	ksu_allow(db, "init", "hal_fingerprint_oppo", "binder", "transfer");
	ksu_allow(db, "init", "hidl_base_hwservice", "hwservice_manager", "add");
	ksu_allow(db, "init", "hwservicemanager", "binder", "call");
	ksu_allow(db, "init", "hwservicemanager", "binder", "transfer");
	ksu_allow(db, "init", "iio_device", "chr_file", "getattr");
	ksu_allow(db, "init", "init", "fifo_file", "ioctl");
	ksu_allow(db, "init", "input_device", "chr_file", "read");
	ksu_allow(db, "init", "ion_device", "chr_file", "getattr");
	ksu_allow(db, "init", "ipa_dev", "chr_file", "getattr");
	ksu_allow(db, "init", "kmsg_debug_device", "chr_file", "open");
	ksu_allow(db, "init", "ppp_device", "chr_file", "getattr");
	ksu_allow(db, "init", "proc", "file", "write");
	ksu_allow(db, "init", "proc_swaps", "file", "getattr");
	ksu_allow(db, "init", "pta_device", "chr_file", "getattr");
	ksu_allow(db, "init", "qce_device", "chr_file", "getattr");
	ksu_allow(db, "init", "qdsp_device", "chr_file", "getattr");
	ksu_allow(db, "init", "qdss_device", "chr_file", "getattr");
	ksu_allow(db, "init", "qtaguid_device", "chr_file", "getattr");
	ksu_allow(db, "init", "ramdump_device", "chr_file", "getattr");
	ksu_allow(db, "init", "rmnet_device", "chr_file", "getattr");
	ksu_allow(db, "init", "rng_device", "chr_file", "getattr");
	ksu_allow(db, "init", "rootfs", "file", "create");
	ksu_allow(db, "init", "rootfs", "file", "unlink");
	ksu_allow(db, "init", "rootfs", "file", "write");
	ksu_allow(db, "init", "rtc_device", "chr_file", "getattr");
	ksu_allow(db, "init", "runtime_event_log_tags_file", "file", "getattr");
	ksu_allow(db, "init", "sensors_device", "chr_file", "getattr");
	ksu_allow(db, "init", "serial_device", "chr_file", "getattr");
	ksu_allow(db, "init", "smcinvoke_device", "chr_file", "getattr");
	ksu_allow(db, "init", "smem_log_device", "chr_file", "getattr");
	ksu_allow(db, "init", "ssr_device", "chr_file", "getattr");
	ksu_allow(db, "init", "sysfs_devices_system_cpu", "file", "write");
	ksu_allow(db, "init", "sysfs", "file", "setattr");
	ksu_allow(db, "init", "sysfs_graphics", "file", "open");
	ksu_allow(db, "init", "sysfs_graphics", "file", "read");
	ksu_allow(db, "init", "sysfs_lowmemorykiller", "file", "open");
	ksu_allow(db, "init", "sysfs_lowmemorykiller", "file", "read");
	ksu_allow(db, "init", "sysfs_msm_power", "file", "open");
	ksu_allow(db, "init", "sysfs_msm_power", "file", "write");
	ksu_allow(db, "init", "sysfs_thermal", "file", "write");
	ksu_allow(db, "init", "system_file", "file", "execute_no_trans");
	ksu_allow(db, "init", "system_server", "binder", "call");
	ksu_allow(db, "init", "tee_device", "chr_file", "getattr");
	ksu_allow(db, "init", "thermal_device", "chr_file", "getattr");
	ksu_allow(db, "init", "tun_device", "chr_file", "getattr");
	ksu_allow(db, "init", "uhid_device", "chr_file", "getattr");
	ksu_allow(db, "init", "uio_device", "chr_file", "getattr");
	ksu_allow(db, "init", "userdata_block_device", "blk_file", "ioctl");
	ksu_allow(db, "init", "usf_device", "chr_file", "getattr");
	ksu_allow(db, "init", "vendor_file", "file", "execute");
	ksu_allow(db, "init", "vendor_file", "file", "execute_no_trans");
	ksu_allow(db, "init", "vendor_toolbox_exec", "file", "execute_no_trans");
	ksu_allow(db, "init", "video_device", "chr_file", "getattr");
	ksu_allow(db, "init", "vndbinder_device", "chr_file", "getattr");
	ksu_allow(db, "init", "wlan_device", "chr_file", "getattr");
	ksu_allow(db, "ipacm-diag", "diag_device", "chr_file", "ioctl");
	ksu_allow(db, "ipacm-diag", "diag_device", "chr_file", "open");
	ksu_allow(db, "ipacm-diag", "diag_device", "chr_file", "read");
	ksu_allow(db, "ipacm-diag", "diag_device", "chr_file", "write");
	ksu_allow(db, "kernel", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "keystore", "shell_data_file", "dir", "search");
	ksu_allow(db, "mediacodec", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "mediaserver", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "mediaswcodec", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "netmgrd", "diag_device", "chr_file", "ioctl");
	ksu_allow(db, "netmgrd", "diag_device", "chr_file", "open");
	ksu_allow(db, "netmgrd", "diag_device", "chr_file", "read");
	ksu_allow(db, "netmgrd", "diag_device", "chr_file", "write");
	ksu_allow(db, "netutils_wrapper", "diag_device", "chr_file", "read");
	ksu_allow(db, "phhsu_daemon", "phhsu_daemon", "capability", "fsetid");
	ksu_allow(db, "platform_app", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "priv_app", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "qti_init_shell", "oppo_qemu_prop", "property_service", "set");
	ksu_allow(db, "qti_init_shell", "persist_file", "dir", "getattr");
	ksu_allow(db, "qti_init_shell", "persist_file", "dir", "search");
	ksu_allow(db, "qti_init_shell", "persist_file", "file", "getattr");
	ksu_allow(db, "qti_init_shell", "persist_file", "file", "open");
	ksu_allow(db, "qti_init_shell", "persist_file", "file", "read");
	ksu_allow(db, "qti_init_shell", "persist_file", "file", "setattr");
	ksu_allow(db, "qti_init_shell", "persist_file", "file", "write");
	ksu_allow(db, "qti_init_shell", "shell_exec", "file", "getattr");
	ksu_allow(db, "qti_init_shell", "shell_exec", "file", "read");
	ksu_allow(db, "qti_init_shell", "toolbox_exec", "file", "execute");
	ksu_allow(db, "qti_init_shell", "toolbox_exec", "file", "execute_no_trans");
	ksu_allow(db, "qti_init_shell", "toolbox_exec", "file", "getattr");
	ksu_allow(db, "qti_init_shell", "toolbox_exec", "file", "read");
	ksu_allow(db, "qti_init_shell", "vendor_file", "file", "entrypoint");
	ksu_allow(db, "rfs_access", "persist_file", "dir", "search");
	ksu_allow(db, "rild", "default_prop", "property_service", "set");
	ksu_allow(db, "rild", "proc", "file", "open");
	ksu_allow(db, "rild", "proc", "file", "read");
	ksu_allow(db, "sensors", "diag_device", "chr_file", "ioctl");
	ksu_allow(db, "sensors", "diag_device", "chr_file", "open");
	ksu_allow(db, "ssgtzd", "smcinvoke_device", "chr_file", "ioctl");
	ksu_allow(db, "ssgtzd", "smcinvoke_device", "chr_file", "open");
	ksu_allow(db, "ssgtzd", "smcinvoke_device", "chr_file", "read");
	ksu_allow(db, "ssgtzd", "smcinvoke_device", "chr_file", "write");
	ksu_allow(db, "surfaceflinger", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "system_app", "default_android_hwservice", "hwservice_manager", "find");
	ksu_allow(db, "system_server", "default_android_hwservice", "hwservice_manager", "find");
	ksu_allow(db, "system_server", "exported_camera_prop", "file", "open");
	ksu_allow(db, "system_server", "exported_camera_prop", "file", "read");
	ksu_allow(db, "system_server", "init", "binder", "call");
	ksu_allow(db, "system_server", "init", "binder", "transfer");
	ksu_allow(db, "system_server", "sysfs", "file", "getattr");
	ksu_allow(db, "system_server", "sysfs", "file", "open");
	ksu_allow(db, "system_server", "sysfs", "file", "read");
	ksu_allow(db, "system_server", "sysfs", "file", "write");
	ksu_allow(db, "system_server", "userspace_reboot_config_prop", "file", "getattr");
	ksu_allow(db, "system_server", "userspace_reboot_config_prop", "file", "open");
	ksu_allow(db, "system_server", "userspace_reboot_config_prop", "file", "read");
	ksu_allow(db, "system_server", "userspace_reboot_exported_prop", "file", "getattr");
	ksu_allow(db, "system_server", "userspace_reboot_exported_prop", "file", "open");
	ksu_allow(db, "system_server", "userspace_reboot_exported_prop", "file", "read");
	ksu_allow(db, "system_server", "vendor_camera_prop", "file", "getattr");
	ksu_allow(db, "system_server", "vendor_camera_prop", "file", "open");
	ksu_allow(db, "system_server", "vendor_camera_prop", "file", "read");
	ksu_allow(db, "tee", "fingerprintd_data_file", ALL, ALL);
	ksu_allow(db, "tee", "oppo_debugfs", "dir", "search");
	ksu_allow(db, "tee", "persist_file", "dir", "search");
	ksu_allow(db, "tee", "tmpfs", "dir", "read");
	ksu_allow(db, "toolbox", "adsprpcd_file", "dir", "getattr");
	ksu_allow(db, "toolbox", "block_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "block_device", "dir", "getattr");
	ksu_allow(db, "toolbox", "block_device", "dir", "open");
	ksu_allow(db, "toolbox", "block_device", "dir", "read");
	ksu_allow(db, "toolbox", "boot_block_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "bt_firmware_file", "dir", "getattr");
	ksu_allow(db, "toolbox", "bt_firmware_file", "filesystem", "getattr");
	ksu_allow(db, "toolbox", "cache_block_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "cgroup_bpf", "dir", "open");
	ksu_allow(db, "toolbox", "cgroup_bpf", "dir", "read");
	ksu_allow(db, "toolbox", "cgroup_bpf", "dir", "search");
	ksu_allow(db, "toolbox", "cgroup_bpf", "file", "getattr");
	ksu_allow(db, "toolbox", "cpu_variant_prop", "file", "getattr");
	ksu_allow(db, "toolbox", "cpu_variant_prop", "file", "open");
	ksu_allow(db, "toolbox", "cpu_variant_prop", "file", "read");
	ksu_allow(db, "toolbox", "debugfs", "dir", "open");
	ksu_allow(db, "toolbox", "debugfs", "dir", "read");
	ksu_allow(db, "toolbox", "debugfs", "file", "getattr");
	ksu_allow(db, "toolbox", "debugfs_mmc", "dir", "open");
	ksu_allow(db, "toolbox", "debugfs_mmc", "dir", "read");
	ksu_allow(db, "toolbox", "debugfs_mmc", "file", "getattr");
	ksu_allow(db, "toolbox", "debugfs_trace_marker", "file", "getattr");
	ksu_allow(db, "toolbox", "debugfs_tracing_debug", "dir", "open");
	ksu_allow(db, "toolbox", "debugfs_tracing_debug", "dir", "read");
	ksu_allow(db, "toolbox", "debugfs_tracing_debug", "file", "getattr");
	ksu_allow(db, "toolbox", "debugfs_tracing", "dir", "open");
	ksu_allow(db, "toolbox", "debugfs_tracing", "dir", "read");
	ksu_allow(db, "toolbox", "debugfs_tracing", "file", "getattr");
	ksu_allow(db, "toolbox", "debugfs_tracing_instances", "dir", "open");
	ksu_allow(db, "toolbox", "debugfs_tracing_instances", "dir", "read");
	ksu_allow(db, "toolbox", "debugfs_wakeup_sources", "file", "getattr");
	ksu_allow(db, "toolbox", "default_prop", "property_service", "set");
	ksu_allow(db, "toolbox", "device", "blk_file", "create");
	ksu_allow(db, "toolbox", "device", "dir", "add_name");
	ksu_allow(db, "toolbox", "device", "dir", "write");
	ksu_allow(db, "toolbox", "dip_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "dm_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "exported_default_prop", "property_service", "set");
	ksu_allow(db, "toolbox", "ffs_prop", "property_service", "set");
	ksu_allow(db, "toolbox", "firmware_file", "dir", "getattr");
	ksu_allow(db, "toolbox", "firmware_file", "filesystem", "getattr");
	ksu_allow(db, "toolbox", "frp_block_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "fusectlfs", "dir", "open");
	ksu_allow(db, "toolbox", "fusectlfs", "dir", "read");
	ksu_allow(db, "toolbox", "init", "fifo_file", "getattr");
	ksu_allow(db, "toolbox", "init", "fifo_file", "ioctl");
	ksu_allow(db, "toolbox", "init", "fifo_file", "read");
	ksu_allow(db, "toolbox", "init", "fifo_file", "write");
	ksu_allow(db, "toolbox", "init", "unix_stream_socket", "connectto");
	ksu_allow(db, "toolbox", "kernel", "security", "setenforce");
	ksu_allow(db, "toolbox", "kernel", "system", "syslog_console");
	ksu_allow(db, "toolbox", "labeledfs", "filesystem", "remount");
	ksu_allow(db, "toolbox", "linkerconfig_file", "dir", "getattr");
	ksu_allow(db, "toolbox", "logdump_partition", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "loop_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "mba_debug_dev", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "mdtp_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "misc_block_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "mnt_user_file", "dir", "getattr");
	ksu_allow(db, "toolbox", "modem_efs_partition_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "modem_efs_partition_device", "blk_file", "open");
	ksu_allow(db, "toolbox", "modem_efs_partition_device", "blk_file", "read");
	ksu_allow(db, "toolbox", "oppo_block_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "oppo_debugfs", "dir", "open");
	ksu_allow(db, "toolbox", "oppo_debugfs", "dir", "read");
	ksu_allow(db, "toolbox", "oppo_debugfs", "file", "getattr");
	ksu_allow(db, "toolbox", "oppo_dump_debugfs", "dir", "open");
	ksu_allow(db, "toolbox", "oppo_dump_debugfs", "dir", "read");
	ksu_allow(db, "toolbox", "oppo_dump_debugfs", "file", "getattr");
	ksu_allow(db, "toolbox", "oppo_rild_sysfs", "file", "getattr");
	ksu_allow(db, "toolbox", "persist_file", "dir", "getattr");
	ksu_allow(db, "toolbox", "persist_file", "dir", "mounton");
	ksu_allow(db, "toolbox", "proc_cmdline", "file", "getattr");
	ksu_allow(db, "toolbox", "proc_cmdline", "file", "open");
	ksu_allow(db, "toolbox", "proc_cmdline", "file", "read");
	ksu_allow(db, "toolbox", "proc_filesystems", "file", "getattr");
	ksu_allow(db, "toolbox", "proc_filesystems", "file", "open");
	ksu_allow(db, "toolbox", "proc_filesystems", "file", "read");
	ksu_allow(db, "toolbox", "property_socket", "sock_file", "write");
	ksu_allow(db, "toolbox", "qti_debugfs", "dir", "open");
	ksu_allow(db, "toolbox", "qti_debugfs", "dir", "read");
	ksu_allow(db, "toolbox", "qti_debugfs", "file", "getattr");
	ksu_allow(db, "toolbox", "ram_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "recovery_block_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "root_block_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "rpmb_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "selinuxfs", "dir", "open");
	ksu_allow(db, "toolbox", "selinuxfs", "dir", "read");
	ksu_allow(db, "toolbox", "selinuxfs", "file", "open");
	ksu_allow(db, "toolbox", "selinuxfs", "file", "read");
	ksu_allow(db, "toolbox", "selinuxfs", "file", "write");
	ksu_allow(db, "toolbox", "ssd_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "sys_engineer_file", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_adsp", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_adsp", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_adsp", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_android_usb", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_android_usb", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_android_usb", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_battery_supply", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_battery_supply", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_battery_supply", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_battery_supply", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_battery_supply", "lnk_file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_battery_supply", "lnk_file", "read");
	ksu_allow(db, "toolbox", "sysfs_bond0", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_boot_adsp", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_cpu_boost", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_cpu_boost", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_cpu_boost", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_cpu_boost", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_data", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_data", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_data", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_data", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_devfreq", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_devfreq", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_devfreq", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_devfreq", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_devfreq", "lnk_file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_devfreq", "lnk_file", "read");
	ksu_allow(db, "toolbox", "sysfs_devices_block", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_devices_block", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_devices_block", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_diag", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_diag", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_diag", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_diag", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_dm", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_dm", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_dm", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_dm", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_dm_verity", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_dt_firmware_android", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_dt_firmware_android", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_dt_firmware_android", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_dt_firmware_android", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_ea", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_ea", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_ea", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_ea", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_extcon", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_extcon", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_fs_ext4_features", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_fs_ext4_features", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_fs_ext4_features", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_fs_ext4_features", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_fs_f2fs", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_fs_f2fs", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_fs_f2fs", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_fs_f2fs", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_graphics", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_graphics", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_graphics", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_graphics", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_graphics", "file", "open");
	ksu_allow(db, "toolbox", "sysfs_graphics", "file", "read");
	ksu_allow(db, "toolbox", "sysfs_graphics", "lnk_file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_graphics", "lnk_file", "read");
	ksu_allow(db, "toolbox", "sysfs_hwrandom", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_hwrandom", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_hwrandom", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_hwrandom", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_io_sched_tuneable", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_io_sched_tuneable", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_io_sched_tuneable", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_io_sched_tuneable", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_ipv4", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_ipv4", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_ipv4", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_ipv4", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_irqbalance", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_jpeg", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_kernel_notes", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_kgsl", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_kgsl", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_kgsl", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_kgsl", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_kgsl", "lnk_file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_kgsl", "lnk_file", "read");
	ksu_allow(db, "toolbox", "sysfs_kgsl_proc", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_kgsl_proc", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_kgsl_proc", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_kgsl_snapshot", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_kgsl_snapshot", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_kgsl_snapshot", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_kgsl_snapshot", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_leds", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_leds", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_leds", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_leds", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_loop", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_loop", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_loop", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_lowmemorykiller", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_lowmemorykiller", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_lowmemorykiller", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_lowmemorykiller", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_mmc_host", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_mmc_host", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_mmc_host", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_mmc_host", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_mpdecision", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_msm_perf", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_msm_perf", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_msm_perf", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_msm_perf", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_msm_power", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_msm_power", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_msm_power", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_msm_power", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_msm_stats", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_msm_stats", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_msm_stats", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_msm_stats", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_net", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_net", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_net", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_net", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_power", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_poweron_alarm", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_process_reclaim", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_process_reclaim", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_process_reclaim", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_process_reclaim", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_rtc", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_rtc", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_rtc", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_slpi", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_slpi", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_slpi", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_slpi", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_spmi_dev", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_spmi_dev", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_spmi_dev", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_spmi_dev", "lnk_file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_spmi_dev", "lnk_file", "read");
	ksu_allow(db, "toolbox", "sysfs_switch", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_switch", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_switch", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_switch", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_uio", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_uio", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_uio", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_uio_file", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_uio_file", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_uio_file", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_uio_file", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_uio_file", "lnk_file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_uio_file", "lnk_file", "read");
	ksu_allow(db, "toolbox", "sysfs_uio", "lnk_file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_uio", "lnk_file", "read");
	ksu_allow(db, "toolbox", "sysfs_usb_supply", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_usb_supply", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_usb_supply", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_usb_supply", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_usb_supply", "lnk_file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_usb_supply", "lnk_file", "read");
	ksu_allow(db, "toolbox", "sysfs_usermodehelper", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_vibrator", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_vmpressure", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_vmpressure", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_vmpressure", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_vmpressure", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_wake_lock", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_wakelock_profiler", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_wakeup_reasons", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_wakeup_reasons", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_wakeup_reasons", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_wakeup_reasons", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_wlan_con_mode", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_wlan_fwpath", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_wlan_parameters", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_zram", "dir", "open");
	ksu_allow(db, "toolbox", "sysfs_zram", "dir", "read");
	ksu_allow(db, "toolbox", "sysfs_zram", "dir", "search");
	ksu_allow(db, "toolbox", "sysfs_zram", "file", "getattr");
	ksu_allow(db, "toolbox", "sysfs_zram_uevent", "file", "getattr");
	ksu_allow(db, "toolbox", "system_block_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "system_prop", "property_service", "set");
	ksu_allow(db, "toolbox", "tmpfs", "dir", "add_name");
	ksu_allow(db, "toolbox", "tmpfs", "dir", "create");
	ksu_allow(db, "toolbox", "tmpfs", "dir", "mounton");
	ksu_allow(db, "toolbox", "tmpfs", "dir", "open");
	ksu_allow(db, "toolbox", "tmpfs", "dir", "read");
	ksu_allow(db, "toolbox", "tmpfs", "dir", "remove_name");
	ksu_allow(db, "toolbox", "tmpfs", "dir", "setattr");
	ksu_allow(db, "toolbox", "tmpfs", "dir", "write");
	ksu_allow(db, "toolbox", "tmpfs", "file", "create");
	ksu_allow(db, "toolbox", "tmpfs", "file", "getattr");
	ksu_allow(db, "toolbox", "tmpfs", "file", "open");
	ksu_allow(db, "toolbox", "tmpfs", "file", "read");
	ksu_allow(db, "toolbox", "tmpfs", "file", "relabelfrom");
	ksu_allow(db, "toolbox", "tmpfs", "file", "rename");
	ksu_allow(db, "toolbox", "tmpfs", "file", "setattr");
	ksu_allow(db, "toolbox", "tmpfs", "filesystem", "mount");
	ksu_allow(db, "toolbox", "tmpfs", "file", "unlink");
	ksu_allow(db, "toolbox", "tmpfs", "file", "write");
	ksu_allow(db, "toolbox", "toolbox", "capability2", "syslog");
	ksu_allow(db, "toolbox", "toolbox", "capability", "mknod");
	ksu_allow(db, "toolbox", "userdata_block_device", "blk_file", "getattr");
	ksu_allow(db, "toolbox", "vendor_configs_file", "dir", "mounton");
	ksu_allow(db, "toolbox", "vendor_display_prop", "property_service", "set");
	ksu_allow(db, "toolbox", "vendor_file", "file", "getattr");
	ksu_allow(db, "toolbox", "vendor_file", "file", "mounton");
	ksu_allow(db, "toolbox", "vendor_file", "file", "open");
	ksu_allow(db, "toolbox", "vendor_file", "file", "read");
	ksu_allow(db, "toolbox", "vendor_file", "file", "relabelto");
	ksu_allow(db, "toolbox", "vendor_overlay_file", "dir", "search");
	ksu_allow(db, "toolbox", "vendor_overlay_file", "file", "mounton");
	ksu_allow(db, "ueventd", "persist_file", "dir", "search");
	ksu_allow(db, "ueventd", "persist_file", "file", "getattr");
	ksu_allow(db, "ueventd", "persist_file", "file", "open");
	ksu_allow(db, "ueventd", "persist_file", "file", "read");
	ksu_allow(db, "vendor_init", "system_data_file", "dir", "setattr");
	ksu_allow(db, "vendor_init", "time_data_file", "dir", "getattr");
	ksu_allow(db, "vendor_init", "tombstone_data_file", "dir", "getattr");
	ksu_allow(db, "vendor_init", "tombstone_data_file", "dir", "search");
	ksu_allow(db, "vold_prepare_subdirs", "face_data_file", "dir", "getattr");
	ksu_allow(db, "vold", "sysfs_mmc_host", "file", "write");
	ksu_allow(db, "wcnss_service", "persist_file", "dir", "search");
	ksu_allow(db, "zygote", "exported_camera_prop", "file", "getattr");
	ksu_allow(db, "zygote", "exported_camera_prop", "file", "open");
	ksu_allow(db, "zygote", "exported_camera_prop", "file", "read");

	rcu_read_unlock();
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

int handle_sepolicy(unsigned long arg3, void __user *arg4)
{
	if (!arg4) {
		return -1;
	}

	if (!getenforce()) {
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