#ifndef __SUKISU_KPMODULE_ABI_H
#define __SUKISU_KPMODULE_ABI_H

#define KPM_NAME_LEN 32
#define KPM_VERSION_LEN 32
#define KPM_LICENSE_LEN 32
#define KPM_AUTHOR_LEN 32
#define KPM_DESCRIPTION_LEN 512
#define KPM_ARGS_LEN 1024

#define KPM_INFO(field, value, limit) \
    _Static_assert(sizeof(value) <= limit, "KPM metadata is too long"); \
    static const char __kpm_info_##field[] __attribute__((used, section(".kpm.info"), aligned(1))) = #field "=" value

#define KPM_NAME(value) KPM_INFO(name, value, KPM_NAME_LEN)
#define KPM_VERSION(value) KPM_INFO(version, value, KPM_VERSION_LEN)
#define KPM_LICENSE(value) KPM_INFO(license, value, KPM_LICENSE_LEN)
#define KPM_AUTHOR(value) KPM_INFO(author, value, KPM_AUTHOR_LEN)
#define KPM_DESCRIPTION(value) KPM_INFO(description, value, KPM_DESCRIPTION_LEN)

typedef long (*kpm_initcall_t)(const char *args, const char *event, void *reserved);
typedef long (*kpm_ctl0call_t)(const char *args, char *out, int out_len);
typedef long (*kpm_ctl1call_t)(void *arg1, void *arg2, void *arg3);
typedef long (*kpm_exitcall_t)(void *reserved);
typedef long (*kpm_eventcall_t)(const char *event, const char *args, void *reserved);

#define KPM_INIT(function) \
    static kpm_initcall_t __kpm_init_##function __attribute__((used, section(".kpm.init"))) = function
#define KPM_CTL0(function) \
    static kpm_ctl0call_t __kpm_ctl0_##function __attribute__((used, section(".kpm.ctl0"))) = function
#define KPM_CTL1(function) \
    static kpm_ctl1call_t __kpm_ctl1_##function __attribute__((used, section(".kpm.ctl1"))) = function
#define KPM_EXIT(function) \
    static kpm_exitcall_t __kpm_exit_##function __attribute__((used, section(".kpm.exit"))) = function
#define KPM_EVENT(function) \
    static kpm_eventcall_t __kpm_event_##function __attribute__((used, section(".kpm.event"))) = function

#endif
