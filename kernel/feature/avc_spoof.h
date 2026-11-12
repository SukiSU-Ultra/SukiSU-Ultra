#ifndef __KSU_H_AVC_SPOOF
#define __KSU_H_AVC_SPOOF

void ksu_avc_spoof_init(void);
void ksu_avc_spoof_late_init(void);
void ksu_avc_spoof_exit(void);

/* Used by downstream/slow_avc_audit_defs.h when the call sites are patched. */
void ksu_avc_spoof_rewrite_tsid(u32 *tsid);

#endif
