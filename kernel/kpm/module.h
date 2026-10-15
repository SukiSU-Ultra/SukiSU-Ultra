#ifndef __SUKISU_KPM_MODULE_H
#define __SUKISU_KPM_MODULE_H

#include <linux/elf.h>
#include <linux/list.h>
#include <linux/types.h>

#define KPM_NAME_LEN 32
#define KPM_VERSION_LEN 32
#define KPM_LICENSE_LEN 32
#define KPM_AUTHOR_LEN 32
#define KPM_DESCRIPTION_LEN 512
#define KPM_ARGS_LEN 1024
#define KPM_LOAD_ERROR_MESSAGE_LEN 160
#define KPM_LOAD_RESULT_MAGIC 0x4b504d52U

typedef long (*kpm_init_fn)(const char *args, const char *event, void *reserved);
typedef long (*kpm_ctl0_fn)(const char *args, char __user *out, int out_len);
typedef long (*kpm_ctl1_fn)(void *arg1, void *arg2, void *arg3);
typedef long (*kpm_exit_fn)(void *reserved);
typedef long (*kpm_event_fn)(const char *event, const char *args, void *reserved);

struct kpm_load_result {
    __u32 magic;
    __u32 size;
    __s32 code;
    char message[KPM_LOAD_ERROR_MESSAGE_LEN];
};

struct kpm_info {
    const char *base;
    unsigned long size;
    const char *name;
    const char *version;
    const char *license;
    const char *author;
    const char *description;
    char error[KPM_LOAD_ERROR_MESSAGE_LEN];
};

struct kpm_load_info {
    const Elf64_Ehdr *hdr;
    unsigned long len;
    Elf64_Shdr *sections;
    const char *section_names;
    char *strtab;
    struct kpm_info info;
    unsigned int sym_index;
    unsigned int str_index;
    unsigned long sym_offset;
    unsigned long str_offset;
};

struct kpm_module {
    struct list_head list;
    struct kpm_info info;
    char *args;
    char *control_args;
    char load_event[32];
    char load_source[16];
    kpm_init_fn init;
    kpm_ctl0_fn ctl0;
    kpm_ctl1_fn ctl1;
    kpm_exit_fn exit;
    kpm_event_fn event;
    unsigned int size;
    void *start;
};

long kpm_load_path(const char *path, const char *args, void __user *reserved);
long kpm_load_image(const void *data, size_t len, const char *args, const char *event,
                    const char *source, void __user *reserved);
long kpm_unload(const char *name, void __user *reserved);
long kpm_control(const char *name, const char *args, char __user *out, int out_len);
long kpm_control1(const char *name, void *arg1, void *arg2, void *arg3);
int kpm_count(void);
int kpm_list(char __user *out, int out_len);
int kpm_info(const char *name, char __user *out, int out_len);
long kpm_notify(const char *event, const char *args, void *reserved);
void kpm_init(void);

#endif
