#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kernfs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <asm/elf.h>    /* 包含 ARM64 重定位类型定义 */
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <linux/version.h>
#include <linux/export.h>
#include <linux/slab.h>
#include "kpm.h"
#include "compact.h"
#include <linux/types.h>
#include <linux/stddef.h>

// 结构体成员元数据
struct DynamicStructMember {
    const char* name;
    size_t size;
    size_t offset;
};

// 结构体元数据（包含总大小）
struct DynamicStructInfo {
    const char* name;
    size_t count;
    size_t total_size;
    struct DynamicStructMember* members;
};

// 定义结构体元数据的宏（直接使用 struct 名称）
#define DYNAMIC_STRUCT_BEGIN(struct_name) \
    static struct DynamicStructMember struct_name##_members[] = {

#define DEFINE_MEMBER(struct_name, member) \
    { \
        .name = #member, \
        .size = sizeof(((struct struct_name*)0)->member), \
        .offset = offsetof(struct struct_name, member) \
    },

#define DYNAMIC_STRUCT_END(struct_name) \
    }; \
    static struct DynamicStructInfo struct_name##_info = { \
        .name = #struct_name, \
        .count = sizeof(struct_name##_members) / sizeof(struct DynamicStructMember), \
        .total_size = sizeof(struct struct_name), \
        .members = struct_name##_members \
    };

// ==================================================================================

#include <linux/version.h>

#define KERNEL_VERSION_6_1 KERNEL_VERSION(6, 1, 0)
#define KERNEL_VERSION_5_15 KERNEL_VERSION(5, 15, 0)

#include <../fs/mount.h>
#include <linux/mount.h>

// 定义元数据
DYNAMIC_STRUCT_BEGIN(mount)
    DEFINE_MEMBER(mount, mnt_parent)
    DEFINE_MEMBER(mount, mnt)
    DEFINE_MEMBER(mount, mnt_id)
    DEFINE_MEMBER(mount, mnt_group_id)
    DEFINE_MEMBER(mount, mnt_expiry_mark)
    DEFINE_MEMBER(mount, mnt_master)
    DEFINE_MEMBER(mount, mnt_devname)
DYNAMIC_STRUCT_END(mount)

DYNAMIC_STRUCT_BEGIN(vfsmount)
    DEFINE_MEMBER(vfsmount, mnt_root)
    DEFINE_MEMBER(vfsmount, mnt_sb)
    DEFINE_MEMBER(vfsmount, mnt_flags)
DYNAMIC_STRUCT_END(vfsmount)

DYNAMIC_STRUCT_BEGIN(mnt_namespace)
    DEFINE_MEMBER(mnt_namespace, ns)
    DEFINE_MEMBER(mnt_namespace, root)
    DEFINE_MEMBER(mnt_namespace, seq)
    DEFINE_MEMBER(mnt_namespace, mounts)
#if LINUX_VERSION_CODE < KERNEL_VERSION_5_15
    DEFINE_MEMBER(mnt_namespace, count)
#endif
DYNAMIC_STRUCT_END(mnt_namespace)

#include <linux/kprobes.h>

#ifdef CONFIG_KPROBES
DYNAMIC_STRUCT_BEGIN(kprobe)
    DEFINE_MEMBER(kprobe, addr)
    DEFINE_MEMBER(kprobe, symbol_name)
    DEFINE_MEMBER(kprobe, offset)
    DEFINE_MEMBER(kprobe, pre_handler)
    DEFINE_MEMBER(kprobe, post_handler)
#if LINUX_VERSION_CODE < KERNEL_VERSION_5_15
    DEFINE_MEMBER(kprobe, fault_handler)
#endif
    DEFINE_MEMBER(kprobe, flags)
DYNAMIC_STRUCT_END(kprobe)
#endif

#include <linux/mm.h>
#include <linux/mm_types.h>

DYNAMIC_STRUCT_BEGIN(vm_area_struct)
    DEFINE_MEMBER(vm_area_struct,vm_start)
    DEFINE_MEMBER(vm_area_struct,vm_end)
    DEFINE_MEMBER(vm_area_struct,vm_flags)
    DEFINE_MEMBER(vm_area_struct,anon_vma)
    DEFINE_MEMBER(vm_area_struct,vm_pgoff)
    DEFINE_MEMBER(vm_area_struct,vm_file)
    DEFINE_MEMBER(vm_area_struct,vm_private_data)
    #ifdef CONFIG_ANON_VMA_NAME
    DEFINE_MEMBER(vm_area_struct, anon_name)
    #endif
    DEFINE_MEMBER(vm_area_struct, vm_ops)
DYNAMIC_STRUCT_END(vm_area_struct)

DYNAMIC_STRUCT_BEGIN(vm_operations_struct)
    DEFINE_MEMBER(vm_operations_struct, open)
    DEFINE_MEMBER(vm_operations_struct, close)
    DEFINE_MEMBER(vm_operations_struct, name)
    DEFINE_MEMBER(vm_operations_struct, access)
DYNAMIC_STRUCT_END(vm_operations_struct)

#include <linux/netlink.h>

DYNAMIC_STRUCT_BEGIN(netlink_kernel_cfg)
    DEFINE_MEMBER(netlink_kernel_cfg, groups)
    DEFINE_MEMBER(netlink_kernel_cfg, flags)
    DEFINE_MEMBER(netlink_kernel_cfg, input)
    DEFINE_MEMBER(netlink_kernel_cfg, cb_mutex)
    DEFINE_MEMBER(netlink_kernel_cfg, bind)
    DEFINE_MEMBER(netlink_kernel_cfg, unbind)
#if LINUX_VERSION_CODE < KERNEL_VERSION_6_1
    DEFINE_MEMBER(netlink_kernel_cfg, compare)
#endif
DYNAMIC_STRUCT_END(netlink_kernel_cfg)


#include <linux/sched.h>
DYNAMIC_STRUCT_BEGIN(task_struct)
    DEFINE_MEMBER(task_struct, pid)
    DEFINE_MEMBER(task_struct, tgid)
    DEFINE_MEMBER(task_struct, cred)
    DEFINE_MEMBER(task_struct, real_cred)
    DEFINE_MEMBER(task_struct, comm)
    DEFINE_MEMBER(task_struct, parent)
    DEFINE_MEMBER(task_struct, group_leader)
    DEFINE_MEMBER(task_struct, mm)
    DEFINE_MEMBER(task_struct, active_mm)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) 
    DEFINE_MEMBER(task_struct, pids[PIDTYPE_PID].pid)
#else
    DEFINE_MEMBER(task_struct, thread_pid)
#endif
    DEFINE_MEMBER(task_struct, files)
    DEFINE_MEMBER(task_struct, seccomp)
#ifdef CONFIG_THREAD_INFO_IN_TASK
    DEFINE_MEMBER(task_struct, thread_info)
#endif
#ifdef CONFIG_CGROUPS
    DEFINE_MEMBER(task_struct, cgroups)
#endif
#ifdef CONFIG_SECURITY
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0))
    DEFINE_MEMBER(task_struct, security)
#else    
    DEFINE_MEMBER(task_struct, cred)
#endif    
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0))
    DEFINE_MEMBER(task_struct, thread)
#else    
    DEFINE_MEMBER(task_struct, thread_info)
#endif
DYNAMIC_STRUCT_END(task_struct)

// =====================================================================================================================

#define STRUCT_INFO(name) &(name##_info)

static
struct DynamicStructInfo* dynamic_struct_infos[] = {
    STRUCT_INFO(mount),
    STRUCT_INFO(vfsmount),
    STRUCT_INFO(mnt_namespace),
    #ifdef CONFIG_KPROBES
        STRUCT_INFO(kprobe),
    #endif
    STRUCT_INFO(vm_area_struct),
    STRUCT_INFO(vm_operations_struct),
    STRUCT_INFO(netlink_kernel_cfg),
    STRUCT_INFO(task_struct)
};

// return 0 if successful
// return -1 if struct not defined
int sukisu_super_find_struct(
    const char* struct_name,
    size_t* out_size,
    int* out_members
) {
    for(size_t i = 0; i < (sizeof(dynamic_struct_infos) / sizeof(dynamic_struct_infos[0])); i++) {
        struct DynamicStructInfo* info = dynamic_struct_infos[i];
        if(strcmp(struct_name, info->name) == 0) {
            if(out_size)
                *out_size = info->total_size;
            if(out_members)
                *out_members = info->count;
            return 0;
        }
    }
    return -1;
}
EXPORT_SYMBOL(sukisu_super_find_struct);

// Dynamic access struct
// return 0 if successful
// return -1 if struct not defined
// return -2 if member not defined
int sukisu_super_access (
    const char* struct_name,
    const char* member_name,
    size_t* out_offset,
    size_t* out_size
) {
    for(size_t i = 0; i < (sizeof(dynamic_struct_infos) / sizeof(dynamic_struct_infos[0])); i++) {
        struct DynamicStructInfo* info = dynamic_struct_infos[i];
        if(strcmp(struct_name, info->name) == 0) {
            for (size_t i1 = 0; i1 < info->count; i1++) {
                if (strcmp(info->members[i1].name, member_name) == 0) {
                    if(out_offset)
                        *out_offset = info->members[i].offset;
                    if(out_size)
                        *out_size = info->members[i].size;
                    return 0;
                }
            }
            return -2;
        }
    }
    return -1;
}
EXPORT_SYMBOL(sukisu_super_access);

// 动态 container_of 宏
#define DYNAMIC_CONTAINER_OF(offset, member_ptr) ({ \
    (offset != (size_t)-1) ? (void*)((char*)(member_ptr) - offset) : NULL; \
})

// Dynamic container_of
// return 0 if success
// return -1 if current struct not defined
// return -2 if target member not defined
int sukisu_super_container_of(
    const char* struct_name,
    const char* member_name,
    void* ptr,
    void** out_ptr
) {
    if(ptr == NULL) {
        return -3;
    }
    for(size_t i = 0; i < (sizeof(dynamic_struct_infos) / sizeof(dynamic_struct_infos[0])); i++) {
        struct DynamicStructInfo* info = dynamic_struct_infos[i];
        if(strcmp(struct_name, info->name) == 0) {
            for (size_t i1 = 0; i1 < info->count; i1++) {
                if (strcmp(info->members[i1].name, member_name) == 0) {
                    *out_ptr = (void*) DYNAMIC_CONTAINER_OF(info->members[i1].offset, ptr);
                    return 0;
                }
            }
            return -2;
        }
    }
    return -1;
}
EXPORT_SYMBOL(sukisu_super_container_of);