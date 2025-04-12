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
#include "../allowlist.h"
#include "../manager.h"

unsigned long sukisu_compact_find_symbol(const char* name);

// ======================================================================
// 兼容函数 for KPM

static
int sukisu_is_su_allow_uid(uid_t uid) {
    return ksu_is_allow_uid(uid) ? 1 : 0;
}

static
int sukisu_get_ap_mod_exclude(uid_t uid) {
    // Not supported
    return 0;
}

static
int sukisu_is_uid_should_umount(uid_t uid) {
    return ksu_uid_should_umount(uid) ? 1 : 0;
}

static
int sukisu_is_current_uid_manager() {
    return is_manager();
}

static
uid_t sukisu_get_manager_uid() {
    return ksu_manager_uid;
}

// ======================================================================

struct CompactAddressSymbol {
    const char* symbol_name;
    void* addr;
};

static struct CompactAddressSymbol address_symbol [] = {
    { "kallsyms_lookup_name", &kallsyms_lookup_name },
    { "compact_find_symbol", &sukisu_compact_find_symbol },
    { "is_run_in_sukisu_ultra", (void*)1 },
    { "is_su_allow_uid", &sukisu_is_su_allow_uid },
    { "get_ap_mod_exclude", &sukisu_get_ap_mod_exclude },
    { "is_uid_should_umount", &sukisu_is_uid_should_umount },
    { "is_current_uid_manager", &sukisu_is_current_uid_manager },
    { "get_manager_uid", &sukisu_get_manager_uid }
};

unsigned long sukisu_compact_find_symbol(const char* name) {
    int i;
    unsigned long addr;

    // 先自己在地址表部分查出来
    for(i = 0; i < (sizeof(address_symbol) / sizeof(struct CompactAddressSymbol)); i++) {
        struct CompactAddressSymbol* symbol = &address_symbol[i];
        if(strcmp(name, symbol->symbol_name) == 0) {
            return (unsigned long) symbol->addr;
        }
    }

    // 通过内核来查
    addr = kallsyms_lookup_name(name);
    if(addr) {
        return addr;
    }

    return 0;
}

EXPORT_SYMBOL(sukisu_compact_find_symbol);
