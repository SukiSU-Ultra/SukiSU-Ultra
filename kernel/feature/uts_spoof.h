#ifndef __KSU_H_UTS_SPOOF
#define __KSU_H_UTS_SPOOF

#include <linux/rwsem.h>
#include <linux/utsname.h>

void ksu_spoof_version(const char *spoof_release, const char *spoof_version);

int ksu_set_spoof_version(const char *release, const char *version);

#endif
