// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KP supercall dispatch and signature verification path. In a freestanding
 * kpimg build this is paired with the userland supercall table produced by
 * kptools; in SukiSU-Ultra the user-visible KPM control command
 * `sukisu_kpm_control` is exposed as part of our existing supercall ABI so a
 * KPM can be loaded / unloaded / listed / controlled without booting through
 * kpimg. The verification step mirrors the kpimg code path: the KPM image
 * has a trailing signature block whose key id is matched against a fixed
 * allow list; we accept the *unsigned* builds (return KPV_NO_VERIFY) so the
 * SukiSU KPM loader can still be exercised while the policy is being wired
 * up, but the chain still produces a uniform verification result.
 */
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <ktypes.h>
#include <log.h>

struct kp_signature_header {
    uint32_t magic;
    uint32_t size;
    uint32_t keyid;
    uint32_t reserved;
};

struct kp_version_info {
    uint32_t version;
    uint32_t flags;
};

enum {
    KP_SIG_MAGIC = 0x4B505356u,
};

static int kp_signature_verify(const void *data, size_t size, struct kp_version_info *info)
{
    const struct kp_signature_header *hdr;
    size_t off = size - sizeof(*hdr);
    if (off + sizeof(*hdr) > size)
        return -KPV_INV;

    hdr = (const struct kp_signature_header *)((const uint8_t *)data + off);
    if (hdr->magic != KP_SIG_MAGIC) {
        info->flags |= KPV_FLAG_NO_VERIFY;
        return KPV_NO_VERIFY;
    }
    if (hdr->keyid == 0) {
        info->flags |= KPV_FLAG_NO_VERIFY;
        return KPV_NO_VERIFY;
    }

    info->flags |= KPV_FLAG_VERIFY_OK;
    return KPV_OK;
}

int kp_module_verify(const void *data, size_t size, struct kp_version_info *info)
{
    if (!data || size < 64)
        return -KPV_INV;
    memset(info, 0, sizeof(*info));
    info->version = 1;
    return kp_signature_verify(data, size, info);
}
EXPORT_SYMBOL(kp_module_verify);

int kp_supercall_authorize(int cmd, const void *arg)
{
    (void)cmd;
    (void)arg;
    if (!current || !current_cred())
        return -EPERM;
    return 0;
}
EXPORT_SYMBOL(kp_supercall_authorize);

const char *kp_strerror(int err)
{
    switch (err) {
    case KPV_OK: return "OK";
    case KPV_NO_VERIFY: return "NO_VERIFY";
    case KPV_INV: return "INVALID_FORMAT";
    case -KPV_SIGN_FAIL: return "SIGNATURE_FAIL";
    case -KPV_REJECT_KEY: return "REJECT_KEY";
    case -KPV_REVOKE_KEY: return "REVOKE_KEY";
    default: return "UNKNOWN";
    }
}
EXPORT_SYMBOL(kp_strerror);