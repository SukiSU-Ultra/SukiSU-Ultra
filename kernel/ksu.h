#ifndef __KSU_H_KSU
#define __KSU_H_KSU

#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/cred.h>

#define KERNEL_SU_VERSION KSU_VERSION
#define KERNEL_SU_OPTION 0xDEADBEEF

extern bool ksu_uid_scanner_enabled;

#define EVENT_POST_FS_DATA 1
#define EVENT_BOOT_COMPLETED 2
#define EVENT_MODULE_MOUNTED 3

// SukiSU Ultra kernel su version full strings
#ifndef KSU_VERSION_FULL 
#define KSU_VERSION_FULL "v3.x-00000000@unknown"
#endif
#define KSU_FULL_VERSION_STRING 255

#define DYNAMIC_MANAGER_OP_SET 0
#define DYNAMIC_MANAGER_OP_GET 1
#define DYNAMIC_MANAGER_OP_CLEAR 2

#define UID_SCANNER_OP_GET_STATUS 0
#define UID_SCANNER_OP_TOGGLE 1
#define UID_SCANNER_OP_CLEAR_ENV 2

struct dynamic_manager_user_config {
    unsigned int operation;
    unsigned int size;
    char hash[65];
};

struct manager_list_info {
    int count;
    struct {
        uid_t uid;
        int signature_index;
    } managers[2];
};

bool ksu_queue_work(struct work_struct *work);

#if 0
static inline int startswith(char *s, char *prefix)
{
    return strncmp(s, prefix, strlen(prefix));
}

static inline int endswith(const char *s, const char *t)
{
    size_t slen = strlen(s);
    size_t tlen = strlen(t);
    if (tlen > slen)
        return 1;
    return strcmp(s + slen - tlen, t);
}
#endif

extern struct cred* ksu_cred;

#endif
