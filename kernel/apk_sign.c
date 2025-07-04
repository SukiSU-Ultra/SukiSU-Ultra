#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>
#ifdef CONFIG_KSU_DEBUG
#include <linux/moduleparam.h>
#endif
#include <crypto/hash.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <crypto/sha2.h>
#else
#include <crypto/sha.h>
#endif

#include "apk_sign.h"
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"
#include "manager_sign.h"


static struct dynamic_sign_config dynamic_sign = {
    .size = 0x300, 
    .hash = "0000000000000000000000000000000000000000000000000000000000000000",
    .is_set = 0
};

static DEFINE_SPINLOCK(dynamic_sign_lock);

static struct work_struct ksu_save_dynamic_sign_work;

static int save_dynamic_sign_config_direct(void)
{
    struct file *fp;
    loff_t pos = 0;
    unsigned long flags;
    struct dynamic_sign_config config_to_save;
    int ret = 0;
    
    spin_lock_irqsave(&dynamic_sign_lock, flags);
    config_to_save = dynamic_sign;
    spin_unlock_irqrestore(&dynamic_sign_lock, flags);
    
    if (!config_to_save.is_set) {
        pr_info("Dynamic sign config not set, skipping save\n");
        return 0;
    }
    
    fp = ksu_filp_open_compat(DYNAMIC_SIGN_CONFIG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(fp)) {
        ret = PTR_ERR(fp);
        pr_err("Failed to open dynamic sign config file for writing: %d\n", ret);
        
        fp = ksu_filp_open_compat(DYNAMIC_SIGN_CONFIG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (IS_ERR(fp)) {
            ret = PTR_ERR(fp);
            pr_err("Failed to open dynamic sign config file with 0600 permissions: %d\n", ret);
            return ret;
        }
    }
    
    ret = ksu_kernel_write_compat(fp, &config_to_save, sizeof(config_to_save), &pos);
    if (ret != sizeof(config_to_save)) {
        pr_err("Failed to write dynamic sign config: wrote %d bytes, expected %zu\n", 
               ret, sizeof(config_to_save));
        ret = (ret < 0) ? ret : -EIO;
    } else {
        ret = 0;
        pr_info("Dynamic sign config saved successfully to %s\n", DYNAMIC_SIGN_CONFIG_PATH);
    }
    
    filp_close(fp, 0);
    return ret;
}

static void do_save_dynamic_sign_config(struct work_struct *work)
{
    int ret = save_dynamic_sign_config_direct();
    if (ret) {
        pr_err("Failed to save dynamic sign config in work queue: %d\n", ret);
    }
}

// Save the dynamic signature configuration to a file
int ksu_save_dynamic_sign_config(void)
{
    int ret = save_dynamic_sign_config_direct();
    if (ret == 0) {
        return 0;
    }
    
    return ksu_queue_work(&ksu_save_dynamic_sign_work);
}

// Load Dynamic Signature Configuration from File
int ksu_load_dynamic_sign_config(void)
{
    struct file *fp;
    loff_t pos = 0;
    struct dynamic_sign_config loaded_config;
    unsigned long flags;
    ssize_t ret;
    
    fp = ksu_filp_open_compat(DYNAMIC_SIGN_CONFIG_PATH, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        if (PTR_ERR(fp) == -ENOENT) {
            pr_info("No saved dynamic sign config found\n");
            return 0;
        }
        pr_err("Failed to open dynamic sign config file: %ld\n", PTR_ERR(fp));
        return PTR_ERR(fp);
    }
    
    ret = ksu_kernel_read_compat(fp, &loaded_config, sizeof(loaded_config), &pos);
    filp_close(fp, 0);
    
    if (ret <= 0) {
        pr_info("Dynamic sign config file is empty or read error: %zd\n", ret);
        return 0;
    }
    
    if (ret != sizeof(loaded_config)) {
        pr_err("Failed to read complete dynamic sign config: %zd/%zu\n", ret, sizeof(loaded_config));
        return -EIO;
    }
    
    // Verify the loaded configuration
    if (loaded_config.size < 0x100 || loaded_config.size > 0x1000) {
        pr_err("Invalid saved config size: 0x%x\n", loaded_config.size);
        return -EINVAL;
    }
    
    if (strlen(loaded_config.hash) != 64) {
        pr_err("Invalid saved config hash length: %zu\n", strlen(loaded_config.hash));
        return -EINVAL;
    }
    
    // Configuration for application loading
    spin_lock_irqsave(&dynamic_sign_lock, flags);
    dynamic_sign = loaded_config;
    spin_unlock_irqrestore(&dynamic_sign_lock, flags);
    
    pr_info("Dynamic sign config loaded: size=0x%x, hash=%.16s...\n", 
            loaded_config.size, loaded_config.hash);
    
    return 0;
}

// Clearing Dynamic Signature Configuration
int ksu_clear_dynamic_sign_config(void)
{
    struct path path;
    unsigned long flags;
    int ret = 0;
    
    // Deleting configuration files
    if (!kern_path(DYNAMIC_SIGN_CONFIG_PATH, 0, &path)) {
        struct dentry *dentry = path.dentry;
        struct inode *dir = d_inode(dentry->d_parent);
        
        inode_lock(dir);
        
        // Use different vfs_unlink parameters depending on the kernel version
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
        ret = vfs_unlink(&init_user_ns, dir, dentry, NULL);
#else
        ret = vfs_unlink(dir, dentry, NULL);
#endif
        
        inode_unlock(dir);
        path_put(&path);
        
        if (ret) {
            pr_err("Failed to remove dynamic sign config file: %d\n", ret);
        } else {
            pr_info("Dynamic sign config file removed\n");
        }
    }
    
    // Reset Configuration to Defaults
    spin_lock_irqsave(&dynamic_sign_lock, flags);
    dynamic_sign.size = 0x300;
    strcpy(dynamic_sign.hash, "0000000000000000000000000000000000000000000000000000000000000000");
    dynamic_sign.is_set = 0;
    spin_unlock_irqrestore(&dynamic_sign_lock, flags);
    
    pr_info("Dynamic sign config cleared\n");
    return ret;
}

int ksu_set_dynamic_sign(unsigned int size, const char *hash)
{
    unsigned long flags;
    int i;
    int ret;
    
    if (!hash) {
        pr_err("hash pointer is null\n");
        return -EINVAL;
    }
    
    if (size < 0x100 || size > 0x1000) {
        pr_err("invalid size: 0x%x\n", size);
        return -EINVAL;
    }
    
    if (strlen(hash) != 64) {
        pr_err("invalid hash length: %zu\n", strlen(hash));
        return -EINVAL;
    }
    
    for (i = 0; i < 64; i++) {
        char c = hash[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            pr_err("invalid hash character at position %d: %c\n", i, c);
            return -EINVAL;
        }
    }
    
    spin_lock_irqsave(&dynamic_sign_lock, flags);
    dynamic_sign.size = size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    strscpy(dynamic_sign.hash, hash, sizeof(dynamic_sign.hash));
#else
    strlcpy(dynamic_sign.hash, hash, sizeof(dynamic_sign.hash));
#endif
    dynamic_sign.is_set = 1;
    spin_unlock_irqrestore(&dynamic_sign_lock, flags);
	
    ret = ksu_save_dynamic_sign_config();
    if (ret) {
        pr_err("Failed to save dynamic sign config: %d\n", ret);
    }
    
    pr_info("dynamic sign updated: size=0x%x, hash=%.16s...\n", size, hash);
    return 0;
}

int ksu_get_dynamic_sign(unsigned int *size, char *hash, int hash_size)
{
    unsigned long flags;
    
    if (!size || !hash || hash_size < 65) {
        return -EINVAL;
    }
    
    spin_lock_irqsave(&dynamic_sign_lock, flags);
    if (dynamic_sign.is_set) {
        *size = dynamic_sign.size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
        strscpy(hash, dynamic_sign.hash, hash_size);
#else
        strlcpy(hash, dynamic_sign.hash, hash_size);
#endif
    }
    spin_unlock_irqrestore(&dynamic_sign_lock, flags);
    
    return dynamic_sign.is_set ? 0 : -ENODATA;
}

void ksu_dynamic_sign_init(void)
{
    INIT_WORK(&ksu_save_dynamic_sign_work, do_save_dynamic_sign_config);
}

void ksu_dynamic_sign_exit(void)
{
    do_save_dynamic_sign_config(NULL);
}

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct apk_sign_key {
	unsigned size;
	const char *sha256;
} apk_sign_keys[] = {
	{EXPECTED_SIZE, EXPECTED_HASH},
	{EXPECTED_SIZE_SHIRKNEKO, EXPECTED_HASH_SHIRKNEKO}, // SukiSU
	{EXPECTED_SIZE_OTHER, EXPECTED_HASH_OTHER}, // Dynamic Sign
#ifdef CONFIG_KSU_MULTI_MANAGER_SUPPORT
	{EXPECTED_SIZE_RSUNTK, EXPECTED_HASH_RSUNTK}, // RKSU
	{EXPECTED_SIZE_NEKO, EXPECTED_HASH_NEKO}, // Neko/KernelSU
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	{EXPECTED_SIZE_5EC1CFF, EXPECTED_HASH_5EC1CFF}, // MKSU
	{EXPECTED_SIZE_WEISHU, EXPECTED_HASH_WEISHU}, // KSU
#endif
#endif
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
	return sdesc;
}

static int calc_hash(struct crypto_shash *alg, const unsigned char *data,
		     unsigned int datalen, unsigned char *digest)
{
	struct sdesc *sdesc;
	int ret;

	sdesc = init_sdesc(alg);
	if (IS_ERR(sdesc)) {
		pr_info("can't alloc sdesc\n");
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

static int ksu_sha256(const unsigned char *data, unsigned int datalen,
		      unsigned char *digest)
{
	struct crypto_shash *alg;
	char *hash_alg_name = "sha256";
	int ret;

	alg = crypto_alloc_shash(hash_alg_name, 0, 0);
	if (IS_ERR(alg)) {
		pr_info("can't alloc alg %s\n", hash_alg_name);
		return PTR_ERR(alg);
	}
	ret = calc_hash(alg, data, datalen, digest);
	crypto_free_shash(alg);
	return ret;
}

static bool check_block(struct file *fp, u32 *size4, loff_t *pos, u32 *offset)
{
	int i;
	struct apk_sign_key sign_key;

	ksu_kernel_read_compat(fp, size4, 0x4, pos); // signer-sequence length
	ksu_kernel_read_compat(fp, size4, 0x4, pos); // signer length
	ksu_kernel_read_compat(fp, size4, 0x4, pos); // signed data length

	*offset += 0x4 * 3;

	ksu_kernel_read_compat(fp, size4, 0x4, pos); // digests-sequence length

	*pos += *size4;
	*offset += 0x4 + *size4;

	ksu_kernel_read_compat(fp, size4, 0x4, pos); // certificates length
	ksu_kernel_read_compat(fp, size4, 0x4, pos); // certificate length
	*offset += 0x4 * 2;

	for (i = 0; i < ARRAY_SIZE(apk_sign_keys); i++) {
		sign_key = apk_sign_keys[i];

		if (i == 2) {
			unsigned long flags;
			spin_lock_irqsave(&dynamic_sign_lock, flags);
			if (dynamic_sign.is_set) {
				sign_key.size = dynamic_sign.size;
				sign_key.sha256 = dynamic_sign.hash;
			}
			spin_unlock_irqrestore(&dynamic_sign_lock, flags);
		}

		if (*size4 != sign_key.size)
			continue;
		*offset += *size4;

#define CERT_MAX_LENGTH 1024
		char cert[CERT_MAX_LENGTH];
		if (*size4 > CERT_MAX_LENGTH) {
			pr_info("cert length overlimit\n");
			return false;
		}
		ksu_kernel_read_compat(fp, cert, *size4, pos);
		unsigned char digest[SHA256_DIGEST_SIZE];
		if (IS_ERR(ksu_sha256(cert, *size4, digest))) {
			pr_info("sha256 error\n");
			return false;
		}

		char hash_str[SHA256_DIGEST_SIZE * 2 + 1];
		hash_str[SHA256_DIGEST_SIZE * 2] = '\0';

		bin2hex(hash_str, digest, SHA256_DIGEST_SIZE);
		pr_info("sha256: %s, expected: %s\n", hash_str,
			sign_key.sha256);
		if (strcmp(sign_key.sha256, hash_str) == 0) {
			return true;
		}
	}
	return false;
}

struct zip_entry_header {
	uint32_t signature;
	uint16_t version;
	uint16_t flags;
	uint16_t compression;
	uint16_t mod_time;
	uint16_t mod_date;
	uint32_t crc32;
	uint32_t compressed_size;
	uint32_t uncompressed_size;
	uint16_t file_name_length;
	uint16_t extra_field_length;
} __attribute__((packed));

// This is a necessary but not sufficient condition, but it is enough for us
static bool has_v1_signature_file(struct file *fp)
{
	struct zip_entry_header header;
	const char MANIFEST[] = "META-INF/MANIFEST.MF";

	loff_t pos = 0;

	while (ksu_kernel_read_compat(fp, &header,
				      sizeof(struct zip_entry_header), &pos) ==
	       sizeof(struct zip_entry_header)) {
		if (header.signature != 0x04034b50) {
			// ZIP magic: 'PK'
			return false;
		}
		// Read the entry file name
		if (header.file_name_length == sizeof(MANIFEST) - 1) {
			char fileName[sizeof(MANIFEST)];
			ksu_kernel_read_compat(fp, fileName,
					       header.file_name_length, &pos);
			fileName[header.file_name_length] = '\0';

			// Check if the entry matches META-INF/MANIFEST.MF
			if (strncmp(MANIFEST, fileName, sizeof(MANIFEST) - 1) ==
			    0) {
				return true;
			}
		} else {
			// Skip the entry file name
			pos += header.file_name_length;
		}

		// Skip to the next entry
		pos += header.extra_field_length + header.compressed_size;
	}

	return false;
}

static __always_inline bool check_v2_signature(char *path)
{
	unsigned char buffer[0x11] = { 0 };
	u32 size4;
	u64 size8, size_of_block;

	loff_t pos;

	bool v2_signing_valid = false;
	int v2_signing_blocks = 0;
	bool v3_signing_exist = false;
	bool v3_1_signing_exist = false;

	int i;
	struct file *fp = ksu_filp_open_compat(path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_err("open %s error.\n", path);
		return false;
	}

	// disable inotify for this file
	fp->f_mode |= FMODE_NONOTIFY;

	// https://en.wikipedia.org/wiki/Zip_(file_format)#End_of_central_directory_record_(EOCD)
	for (i = 0;; ++i) {
		unsigned short n;
		pos = generic_file_llseek(fp, -i - 2, SEEK_END);
		ksu_kernel_read_compat(fp, &n, 2, &pos);
		if (n == i) {
			pos -= 22;
			ksu_kernel_read_compat(fp, &size4, 4, &pos);
			if ((size4 ^ 0xcafebabeu) == 0xccfbf1eeu) {
				break;
			}
		}
		if (i == 0xffff) {
			pr_info("error: cannot find eocd\n");
			goto clean;
		}
	}

	pos += 12;
	// offset
	ksu_kernel_read_compat(fp, &size4, 0x4, &pos);
	pos = size4 - 0x18;

	ksu_kernel_read_compat(fp, &size8, 0x8, &pos);
	ksu_kernel_read_compat(fp, buffer, 0x10, &pos);
	if (strcmp((char *)buffer, "APK Sig Block 42")) {
		goto clean;
	}

	pos = size4 - (size8 + 0x8);
	ksu_kernel_read_compat(fp, &size_of_block, 0x8, &pos);
	if (size_of_block != size8) {
		goto clean;
	}

	int loop_count = 0;
	while (loop_count++ < 10) {
		uint32_t id;
		uint32_t offset;
		ksu_kernel_read_compat(fp, &size8, 0x8,
				       &pos); // sequence length
		if (size8 == size_of_block) {
			break;
		}
		ksu_kernel_read_compat(fp, &id, 0x4, &pos); // id
		offset = 4;
		if (id == 0x7109871au) {
			v2_signing_blocks++;
			v2_signing_valid = check_block(fp, &size4, &pos, &offset);
		} else if (id == 0xf05368c0u) {
			// http://aospxref.com/android-14.0.0_r2/xref/frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java#73
			v3_signing_exist = true;
		} else if (id == 0x1b93ad61u) {
			// http://aospxref.com/android-14.0.0_r2/xref/frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java#74
			v3_1_signing_exist = true;
		} else {
#ifdef CONFIG_KSU_DEBUG
			pr_info("Unknown id: 0x%08x\n", id);
#endif
		}
		pos += (size8 - offset);
	}

	if (v2_signing_blocks != 1) {
#ifdef CONFIG_KSU_DEBUG
		pr_err("Unexpected v2 signature count: %d\n",
		       v2_signing_blocks);
#endif
		v2_signing_valid = false;
	}

	if (v2_signing_valid) {
		int has_v1_signing = has_v1_signature_file(fp);
		if (has_v1_signing) {
			pr_err("Unexpected v1 signature scheme found!\n");
			filp_close(fp, 0);
			return false;
		}
	}
clean:
	filp_close(fp, 0);

	if (v3_signing_exist || v3_1_signing_exist) {
#ifdef CONFIG_KSU_DEBUG
		pr_err("Unexpected v3 signature scheme found!\n");
#endif
		return false;
	}

	return v2_signing_valid;
}

#ifdef CONFIG_KSU_DEBUG

int ksu_debug_manager_uid = -1;

#include "manager.h"

static int set_expected_size(const char *val, const struct kernel_param *kp)
{
	int rv = param_set_uint(val, kp);
	ksu_set_manager_uid(ksu_debug_manager_uid);
	pr_info("ksu_manager_uid set to %d\n", ksu_debug_manager_uid);
	return rv;
}

static struct kernel_param_ops expected_size_ops = {
	.set = set_expected_size,
	.get = param_get_uint,
};

module_param_cb(ksu_debug_manager_uid, &expected_size_ops,
		&ksu_debug_manager_uid, S_IRUSR | S_IWUSR);

#endif

bool ksu_is_manager_apk(char *path)
{
	return check_v2_signature(path);
}