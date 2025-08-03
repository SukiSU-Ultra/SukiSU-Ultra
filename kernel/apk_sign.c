#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/workqueue.h>
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
#include "dynamic_sign.h"
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"
#include "manager_sign.h"

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct apk_sign_key {
	unsigned size;
	const char *sha256;
} apk_sign_keys[] = {
	{EXPECTED_SIZE_SHIRKNEKO, EXPECTED_HASH_SHIRKNEKO}, // ShirkNeko/SukiSU
	{EXPECTED_SIZE_OTHER, EXPECTED_HASH_OTHER}, // Dynamic Sign
#ifdef EXPECTED_SIZE
	{EXPECTED_SIZE, EXPECTED_HASH}, // Custom
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
			if (strncmp(MANIFEST, fileName, sizeof(MANIFEST) - 1) == 0) {
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

// Generic Signature Block Verification
static int verify_signature_block(struct file *fp, u32 *size4, loff_t *pos, u32 *offset, int *matched_index)
{
	int i;
	struct apk_sign_key sign_key;
	bool signature_valid = false;

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

		if (i == 1) { // Dynamic Sign indexing
			unsigned int size;
			const char *hash;
			if (ksu_get_dynamic_sign_config(&size, &hash)) {
				sign_key.size = size;
				sign_key.sha256 = hash;
			}
		}

		if (*size4 != sign_key.size)
			continue;

#define CERT_MAX_LENGTH 1024
		char cert[CERT_MAX_LENGTH];
		if (*size4 > CERT_MAX_LENGTH) {
			pr_info("cert length overlimit\n");
			continue;
		}
		
		loff_t cert_pos = *pos;
		ksu_kernel_read_compat(fp, cert, *size4, &cert_pos);
		unsigned char digest[SHA256_DIGEST_SIZE];
		if (IS_ERR(ksu_sha256(cert, *size4, digest))) {
			pr_info("sha256 error\n");
			continue;
		}

		char hash_str[SHA256_DIGEST_SIZE * 2 + 1];
		hash_str[SHA256_DIGEST_SIZE * 2] = '\0';

		bin2hex(hash_str, digest, SHA256_DIGEST_SIZE);
		pr_info("sha256: %s, expected: %s, index: %d\n", hash_str, sign_key.sha256, i);
		
		if (strcmp(sign_key.sha256, hash_str) == 0) {
			signature_valid = true;
			if (matched_index) {
				*matched_index = i;
			}
			break;
		}
	}
	
	*offset += *size4;
	*pos += *size4;
	
	return signature_valid ? 1 : 0;
}

// Generic APK signature parsing
static int parse_apk_signature(char *path, bool check_multi_manager, int *signature_index)
{
	unsigned char buffer[0x11] = { 0 };
	u32 size4;
	u64 size8, size_of_block;
	loff_t pos;
	bool v2_signing_valid = false;
	int v2_signing_blocks = 0;
	bool v3_signing_exist = false;
	bool v3_1_signing_exist = false;
	int matched_index = -1;
	int i;
	struct file *fp = ksu_filp_open_compat(path, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_err("open %s error.\n", path);
		return -1;
	}

	// If you want to check for multi-manager APK signing, but dynamic signing is not enabled, skip
	if (check_multi_manager && !ksu_is_dynamic_sign_enabled()) {
		filp_close(fp, 0);
		return 0;
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

	// Parsing the signature block
	int loop_count = 0;
	while (loop_count++ < 10) {
		uint32_t id;
		uint32_t offset;
		ksu_kernel_read_compat(fp, &size8, 0x8, &pos); // sequence length
		if (size8 == size_of_block) {
			break;
		}
		ksu_kernel_read_compat(fp, &id, 0x4, &pos); // id
		offset = 4;
		if (id == 0x7109871au) {
			v2_signing_blocks++;
			int result = verify_signature_block(fp, &size4, &pos, &offset, &matched_index);
			if (result == 1) {
				v2_signing_valid = true;
			}
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
		pr_err("Unexpected v2 signature count: %d\n", v2_signing_blocks);
#endif
		v2_signing_valid = false;
	}

	// Check v1 signatures
	if (v2_signing_valid) {
		bool has_v1_signing = has_v1_signature_file(fp);
		if (has_v1_signing) {
			pr_err("Unexpected v1 signature scheme found!\n");
			filp_close(fp, 0);
			return -1;
		}
	}

clean:
	filp_close(fp, 0);

	if (v3_signing_exist || v3_1_signing_exist) {
#ifdef CONFIG_KSU_DEBUG
		pr_err("Unexpected v3 signature scheme found!\n");
#endif
		return -1;
	}

	if (v2_signing_valid) {
		if (signature_index) {
			*signature_index = matched_index;
		}
		
		if (check_multi_manager) {
			// 0: ShirkNeko/SukiSU, 1: Dynamic Sign
			if (matched_index == 0 || matched_index == 1) {
				pr_info("Multi-manager APK detected (dynamic_sign enabled): signature_index=%d\n", matched_index);
				return 1;
			}
			return 0;
		} else {
			// Common manager check: any valid signature will do
			return 1;
		}
	}

	return 0;
}

bool ksu_is_multi_manager_apk(char *path, int *signature_index)
{
	int result = parse_apk_signature(path, true, signature_index);
	return result == 1;
}

static __always_inline bool check_v2_signature(char *path)
{
	int result = parse_apk_signature(path, false, NULL);
	return result == 1;
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

bool is_manager_apk(char *path)
{
	return check_v2_signature(path);
}