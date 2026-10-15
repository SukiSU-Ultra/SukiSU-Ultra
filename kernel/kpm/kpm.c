#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "../infra/symbol_resolver.h"
#include "kpm.h"
#include "kpm_reloc.h"
#include "module.h"

static int kpm_copy_user_string(char *dst, size_t size, unsigned long pointer)
{
    long copied;
    if (!pointer || !access_ok((void __user *)pointer, size))
        return -EFAULT;
    copied = strncpy_from_user(dst, (const char __user *)pointer, size - 1);
    if (copied < 0)
        return copied;
    dst[copied] = '\0';
    return 0;
}

#define KPM_MAX_IMAGE_SIZE (64UL * 1024UL * 1024UL)
#define KPM_PAGE_SIZE PAGE_SIZE

static LIST_HEAD(kpm_modules);
static DEFINE_MUTEX(kpm_lock);

static int kpm_find_section(const struct kpm_load_info *info, const char *name)
{
    for (unsigned int i = 1; i < info->hdr->e_shnum; ++i) {
        const Elf64_Shdr *section = &info->sections[i];
        if ((section->sh_flags & SHF_ALLOC) &&
            !strcmp(info->section_names + section->sh_name, name))
            return i;
    }
    return 0;
}

static char *kpm_modinfo(const struct kpm_load_info *info, const char *tag)
{
    const Elf64_Shdr *section = &info->sections[kpm_find_section(info, ".kpm.info")];
    char *cursor = (char *)info->hdr + section->sh_offset;
    char *end = cursor + section->sh_size;
    size_t tag_len = strlen(tag);

    while (cursor < end && *cursor) {
        if (!strncmp(cursor, tag, tag_len) && cursor[tag_len] == '=')
            return cursor + tag_len + 1;
        cursor += strlen(cursor) + 1;
    }
    return NULL;
}

static int kpm_prepare(struct kpm_load_info *info)
{
    const Elf64_Shdr *symtab = NULL;

    if (info->len < sizeof(*info->hdr) || memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) ||
        info->hdr->e_type != ET_REL || info->hdr->e_machine != EM_AARCH64 ||
        info->hdr->e_shentsize != sizeof(Elf64_Shdr) || !info->hdr->e_shnum ||
        info->hdr->e_shstrndx >= info->hdr->e_shnum)
        return -ENOEXEC;
    if (info->hdr->e_shoff > info->len ||
        info->hdr->e_shnum > (info->len - info->hdr->e_shoff) / sizeof(Elf64_Shdr))
        return -ENOEXEC;

    info->sections = (Elf64_Shdr *)((u8 *)info->hdr + info->hdr->e_shoff);
    if (info->sections[info->hdr->e_shstrndx].sh_offset >= info->len)
        return -ENOEXEC;
    info->section_names = (const char *)info->hdr + info->sections[info->hdr->e_shstrndx].sh_offset;

    for (unsigned int i = 1; i < info->hdr->e_shnum; ++i) {
        Elf64_Shdr *section = &info->sections[i];
        if (section->sh_type != SHT_NOBITS &&
            (section->sh_offset > info->len || section->sh_size > info->len - section->sh_offset))
            return -ENOEXEC;
        section->sh_addr = (Elf64_Addr)((u8 *)info->hdr + section->sh_offset);
        if (section->sh_type == SHT_SYMTAB)
            symtab = section;
    }

    if (!kpm_find_section(info, ".kpm.init") || !kpm_find_section(info, ".kpm.exit") ||
        !kpm_find_section(info, ".kpm.info") || !symtab)
        return -ENOEXEC;

    info->sym_index = symtab - info->sections;
    info->str_index = symtab->sh_link;
    if (info->str_index >= info->hdr->e_shnum)
        return -ENOEXEC;
    info->strtab = (char *)info->hdr + info->sections[info->str_index].sh_offset;
    info->info.base = (const char *)info->sections[kpm_find_section(info, ".kpm.info")].sh_addr;
    info->info.size = info->sections[kpm_find_section(info, ".kpm.info")].sh_size;
    info->info.name = kpm_modinfo(info, "name");
    info->info.version = kpm_modinfo(info, "version");
    info->info.license = kpm_modinfo(info, "license");
    info->info.author = kpm_modinfo(info, "author");
    info->info.description = kpm_modinfo(info, "description");
    if (!info->info.name || !info->info.version)
        return -ENOEXEC;
    return 0;
}

static int kpm_layout(struct kpm_module *module, struct kpm_load_info *info)
{
    unsigned int size = 0;
    for (unsigned int pass = 0; pass < 3; ++pass) {
        for (unsigned int i = 1; i < info->hdr->e_shnum; ++i) {
            Elf64_Shdr *section = &info->sections[i];
            bool executable = section->sh_flags & SHF_EXECINSTR;
            bool writable = section->sh_flags & SHF_WRITE;
            if (!(section->sh_flags & SHF_ALLOC) || (pass == 0 && !executable) ||
                (pass == 1 && (executable || writable)) || (pass == 2 && !writable))
                continue;
            size = ALIGN(size, section->sh_addralign ?: 1);
            section->sh_entsize = size;
            size += section->sh_size;
        }
        size = ALIGN(size, KPM_PAGE_SIZE);
    }
    module->size = size;
    module->start = vzalloc(size);
    return module->start ? 0 : -ENOMEM;
}

static int kpm_resolve_symbols(struct kpm_load_info *info)
{
    Elf64_Shdr *symtab = &info->sections[info->sym_index];
    Elf64_Sym *symbols = (Elf64_Sym *)(uintptr_t)symtab->sh_addr;
    unsigned int count = symtab->sh_size / sizeof(*symbols);
    for (unsigned int i = 1; i < count; ++i) {
        if (symbols[i].st_shndx == SHN_UNDEF) {
            unsigned long address = find_kernel_symbol_exact(info->strtab + symbols[i].st_name);
            if (!address)
                return -ENOENT;
            symbols[i].st_value = address;
        } else if (symbols[i].st_shndx < info->hdr->e_shnum &&
                   symbols[i].st_shndx != SHN_ABS) {
            symbols[i].st_value += info->sections[symbols[i].st_shndx].sh_addr;
        }
    }
    return 0;
}

static void kpm_copy_sections(struct kpm_module *module, struct kpm_load_info *info)
{
    for (unsigned int i = 1; i < info->hdr->e_shnum; ++i) {
        Elf64_Shdr *section = &info->sections[i];
        const char *name = info->section_names + section->sh_name;
        void *destination;
        if (!(section->sh_flags & SHF_ALLOC))
            continue;
        destination = (u8 *)module->start + section->sh_entsize;
        if (section->sh_type != SHT_NOBITS)
            memcpy(destination, (void *)(uintptr_t)section->sh_addr, section->sh_size);
        section->sh_addr = (Elf64_Addr)(uintptr_t)destination;
            if (!module->init && !strcmp(name, ".kpm.init")) module->init = destination;
        if (!module->ctl0 && !strcmp(name, ".kpm.ctl0")) module->ctl0 = destination;
        if (!module->ctl1 && !strcmp(name, ".kpm.ctl1")) module->ctl1 = destination;
        if (!module->exit && !strcmp(name, ".kpm.exit")) module->exit = destination;
        if (!module->event && !strcmp(name, ".kpm.event")) module->event = destination;
        if (!module->info.base && !strcmp(name, ".kpm.info")) module->info.base = destination;
    }
    module->info.name = module->info.base + (info->info.name - info->info.base);
    module->info.version = module->info.base + (info->info.version - info->info.base);
    module->info.license = info->info.license ? module->info.base + (info->info.license - info->info.base) : NULL;
    module->info.author = info->info.author ? module->info.base + (info->info.author - info->info.base) : NULL;
    module->info.description = info->info.description ? module->info.base + (info->info.description - info->info.base) : NULL;
}

static void kpm_set_result(void __user *reserved, long code, const char *message)
{
    struct kpm_load_result result = { .magic = KPM_LOAD_RESULT_MAGIC, .size = sizeof(result), .code = code };
    if (!reserved)
        return;
    if (message)
        strscpy(result.message, message, sizeof(result.message));
    copy_to_user(reserved, &result, sizeof(result));
}

long kpm_load_image(const void *data, size_t len, const char *args, const char *event,
                    const char *source, void __user *reserved)
{
    struct kpm_load_info info = { .hdr = data, .len = len };
    struct kpm_module *module;
    long rc;

    if (!data || len > KPM_MAX_IMAGE_SIZE) return -EINVAL;
    rc = kpm_prepare(&info);
    if (rc) {
        strscpy(info.info.error, "invalid KPM ELF image", sizeof(info.info.error));
        goto fail;
    }
    mutex_lock(&kpm_lock);
    if (list_empty(&kpm_modules) == false) {
        struct kpm_module *item;
        list_for_each_entry(item, &kpm_modules, list)
            if (!strcmp(item->info.name, info.info.name)) {
                rc = -EEXIST;
                strscpy(info.info.error, "module already exists", sizeof(info.info.error));
                goto unlock_fail;
            }
    }
    module = vzalloc(sizeof(*module));
    if (!module) { rc = -ENOMEM; goto unlock_fail; }
    module->info = info.info;
    module->info.base = NULL;
    strscpy(module->load_event, event ?: "", sizeof(module->load_event));
    strscpy(module->load_source, source ?: "embedded", sizeof(module->load_source));
    if (args) { module->args = kstrdup(args, GFP_KERNEL); if (!module->args) { rc = -ENOMEM; goto free_module; } }
    rc = kpm_layout(module, &info);
    if (rc) goto free_args;
    kpm_copy_sections(module, &info);
    rc = kpm_resolve_symbols(&info);
    if (!rc) {
        for (unsigned int i = 1; i < info.hdr->e_shnum; ++i)
            if (info.sections[i].sh_type == SHT_RELA && (info.sections[info.sections[i].sh_info].sh_flags & SHF_ALLOC))
                rc = kpm_apply_relocations(info.sections, info.sym_index, i, module);
    }
    if (!module->init || !module->exit) { rc = -ENOEXEC; goto free_memory; }
    mutex_unlock(&kpm_lock);
    rc = module->init(module->args, event, reserved);
    if (rc) goto free_memory;
    mutex_lock(&kpm_lock);
    list_add_tail(&module->list, &kpm_modules);
    mutex_unlock(&kpm_lock);
    kpm_set_result(reserved, 0, "module loaded");
    return 0;
free_memory:
    vfree(module->start);
free_args:
    kfree(module->args);
free_module:
    vfree(module);
unlock_fail:
    mutex_unlock(&kpm_lock);
fail:
    kpm_set_result(reserved, rc, info.info.error[0] ? info.info.error : "module load failed");
    return rc;
}

long kpm_load_path(const char *path, const char *args, void __user *reserved)
{
    struct file *file;
    loff_t size, pos = 0;
    void *data;
    long rc;
    if (!path || !*path) return -EINVAL;
    file = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(file)) return PTR_ERR(file);
    size = i_size_read(file_inode(file));
    if (size <= 0 || size > KPM_MAX_IMAGE_SIZE) { rc = -EINVAL; goto out_close; }
    data = vmalloc(size);
    if (!data) { rc = -ENOMEM; goto out_close; }
    rc = kernel_read(file, data, size, &pos);
    if (rc == size) rc = kpm_load_image(data, size, args, "load-file", "file", reserved);
    else if (rc >= 0) rc = -EIO;
    vfree(data);
out_close:
    filp_close(file, NULL);
    return rc;
}

long kpm_unload(const char *name, void __user *reserved)
{
    struct kpm_module *module;
    long rc;
    if (!name) return -EINVAL;
    mutex_lock(&kpm_lock);
    list_for_each_entry(module, &kpm_modules, list) {
        if (strcmp(module->info.name, name)) continue;
        list_del(&module->list);
        mutex_unlock(&kpm_lock);
        rc = module->exit ? module->exit(reserved) : 0;
        vfree(module->start); kfree(module->args); kfree(module->control_args); vfree(module);
        return rc;
    }
    mutex_unlock(&kpm_lock);
    return -ENOENT;
}

long kpm_control(const char *name, const char *args, char __user *out, int out_len)
{
    struct kpm_module *module;
    long rc = -ENOENT;
    mutex_lock(&kpm_lock);
    list_for_each_entry(module, &kpm_modules, list) if (!strcmp(module->info.name, name)) {
        if (!module->ctl0) rc = -ENOSYS;
        else {
            mutex_unlock(&kpm_lock);
            return module->ctl0(args, out, out_len);
        }
        break;
    }
    mutex_unlock(&kpm_lock);
    return rc;
}

long kpm_control1(const char *name, void *a1, void *a2, void *a3)
{
    struct kpm_module *module;
    long rc = -ENOENT;
    mutex_lock(&kpm_lock);
    list_for_each_entry(module, &kpm_modules, list) {
        if (strcmp(module->info.name, name)) continue;
        rc = module->ctl1 ? module->ctl1(a1, a2, a3) : -ENOSYS;
        break;
    }
    mutex_unlock(&kpm_lock);
    return rc;
}

int kpm_count(void)
{
    struct kpm_module *module;
    int count = 0;
    mutex_lock(&kpm_lock);
    list_for_each_entry(module, &kpm_modules, list) ++count;
    mutex_unlock(&kpm_lock);
    return count;
}

int kpm_list(char __user *out, int len)
{
    struct kpm_module *module;
    int used = 0;
    if (!out || len <= 0) return -EINVAL;
    mutex_lock(&kpm_lock);
    list_for_each_entry(module, &kpm_modules, list) {
        int name_len = strlen(module->info.name);
        if (used + name_len + 1 >= len) break;
        if (copy_to_user(out + used, module->info.name, name_len) ||
            copy_to_user(out + used + name_len, "\n", 1)) {
            mutex_unlock(&kpm_lock);
            return -EFAULT;
        }
        used += name_len + 1;
    }
    mutex_unlock(&kpm_lock);
    if (used && copy_to_user(out + used - 1, "\0", 1)) return -EFAULT;
    return used;
}

int kpm_info(const char *name, char __user *out, int len)
{
    struct kpm_module *module;
    char buffer[1024];
    int size = -ENOENT;
    if (!out || len <= 0) return -EINVAL;
    mutex_lock(&kpm_lock);
    list_for_each_entry(module, &kpm_modules, list) {
        if (strcmp(module->info.name, name)) continue;
        size = scnprintf(buffer, sizeof(buffer), "name=%s\nversion=%s\nlicense=%s\nauthor=%s\ndescription=%s\nargs=%s\nload_event=%s\nload_source=%s\n", module->info.name, module->info.version ?: "", module->info.license ?: "", module->info.author ?: "", module->info.description ?: "", module->args ?: "", module->load_event, module->load_source);
        break;
    }
    mutex_unlock(&kpm_lock);
    if (size < 0) return size;
    if (copy_to_user(out, buffer, min(size + 1, len))) return -EFAULT;
    return size;
}

long kpm_notify(const char *event, const char *args, void *reserved) { return 0; }
void kpm_init(void) { pr_info("kpm: KernelPatchModule loader enabled\n"); }

int do_kpm(void __user *arg)
{
    struct ksu_kpm_cmd command;
    char path[PATH_MAX], name[KPM_NAME_LEN], args[KPM_ARGS_LEN];
    char __user *buffer;
    int result = -EINVAL;
    if (copy_from_user(&command, arg, sizeof(command))) return -EFAULT;
    switch (command.control_code) {
    case SUKISU_KPM_LOAD:
        result = kpm_copy_user_string(path, sizeof(path), command.arg1);
        if (!result && command.arg2) result = kpm_copy_user_string(args, sizeof(args), command.arg2);
        if (!result) result = kpm_load_path(path, command.arg2 ? args : NULL, NULL);
        break;
    case SUKISU_KPM_UNLOAD:
        result = kpm_copy_user_string(name, sizeof(name), command.arg1);
        if (!result) result = kpm_unload(name, NULL);
        break;
    case SUKISU_KPM_NUM:
        result = kpm_count();
        break;
    case SUKISU_KPM_LIST:
        buffer = (char __user *)(uintptr_t)command.arg1;
        result = kpm_list(buffer, command.arg2);
        break;
    case SUKISU_KPM_INFO:
        result = kpm_copy_user_string(name, sizeof(name), command.arg1);
        if (!result) result = kpm_info(name, (char __user *)(uintptr_t)command.arg2, 256);
        break;
    case SUKISU_KPM_CONTROL:
        result = kpm_copy_user_string(name, sizeof(name), command.arg1);
        if (!result) { result = kpm_copy_user_string(args, sizeof(args), command.arg2); if (!result) result = kpm_control(name, args, NULL, 0); }
        break;
    case SUKISU_KPM_VERSION: {
        static const char version[] = "KernelPatchModule-compatible";
        size_t size = min_t(size_t, command.arg2, sizeof(version));
        result = copy_to_user((void __user *)(uintptr_t)command.arg1, version, size) ? -EFAULT : 0;
        break;
    }
    default: break;
    }
    if (command.result_code && copy_to_user((void __user *)(uintptr_t)command.result_code, &result, sizeof(result))) return -EFAULT;
    return 0;
}

EXPORT_SYMBOL(kpm_load_path);
EXPORT_SYMBOL(kpm_unload);
EXPORT_SYMBOL(kpm_count);
EXPORT_SYMBOL(kpm_list);
EXPORT_SYMBOL(kpm_info);
