/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Ported to SukiSU-Ultra: 2025 Liankong.
 *
 * KPM (KernelPatch Module) ELF loader. Verifies, lays out, relocates,
 * and runs AArch64 KPM objects built with the .kpm.* section macros
 * from kpmodule.h.
 *
 * Differences from upstream KernelPatch:
 *   - Uses `vmalloc` (and `set_memory_x`/`set_memory_nx`) instead of
 *     the KP tlsf pool. This avoids pulling in 37 KB of allocator code
 *     while still keeping a module's .text executable at runtime.
 *   - `symbol_lookup_name` is shimmed on top of SukiSU's
 *     `find_kernel_symbol_exact`, falling back to `kallsyms_lookup_name`
 *     so KP can still call into its `compact` symbol table.
 *   - The result struct written to `reserved` follows the
 *     KPM_LOAD_RESULT_MAGIC layout from kpmodule.h.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
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
#include <linux/rculist.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/mm_types.h>
#include <linux/errno.h>
#include <asm/cacheflush.h>
#include <asm/elf.h>
#include <asm/pgtable.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/set_memory.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/sched.h>

#include "infra/symbol_resolver.h"
#include "module.h"
#include "kpmodule.h"
#include "kp_symbols.h"
#include "kp_hook_runtime.h"
#include "relo.h"
#include "kpmodule.h"

#define KPM_LOAD_PREFIX "KPM-MOD: "
#define logkfi(fmt, ...) pr_info(KPM_LOAD_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)
#define logkfd(fmt, ...) pr_debug(KPM_LOAD_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)
#define logkfe(fmt, ...) pr_err(KPM_LOAD_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)
#define logke(fmt, ...) pr_err(KPM_LOAD_PREFIX fmt, ##__VA_ARGS__)
#define logki(fmt, ...) pr_info(KPM_LOAD_PREFIX fmt, ##__VA_ARGS__)
#define logkd(fmt, ...) pr_debug(KPM_LOAD_PREFIX fmt, ##__VA_ARGS__)

#define SZ_128M 0x08000000

static inline unsigned long align(unsigned long x)
{
    return ALIGN(x, PAGE_SIZE);
}

#define elf_check_arch(x) ((x)->e_machine == EM_AARCH64)

#define ARCH_SHF_SMALL 0

struct load_info {
    struct {
        const char *base;
        unsigned long size;
        const char *name, *version, *license, *author, *description;
        char error_msg[KPM_LOAD_ERROR_MESSAGE_LEN];
    } info;
    const Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings, *strtab;
    unsigned long symoffs, stroffs;
    struct {
        unsigned int sym, str, mod, info;
    } index;
};

struct kpm_module kpm_modules = { 0 };
static DEFINE_SPINLOCK(kpm_module_lock);

static void set_load_error(struct load_info *info, const char *message)
{
    if (!info || !message) return;
    snprintf(info->info.error_msg, sizeof(info->info.error_msg), "%s",
             message);
}

static const char *load_error(const struct load_info *info,
                              const char *fallback)
{
    if (info && info->info.error_msg[0]) return info->info.error_msg;
    return fallback;
}

static int kpm_load_result_enabled(void __user *reserved)
{
    struct kpm_load_result result;

    if (!reserved) return 0;
    if (copy_from_user(&result, reserved, sizeof(result))) return 0;
    return result.magic == KPM_LOAD_RESULT_MAGIC &&
           result.size >= sizeof(result);
}

static void set_kpm_load_result(void __user *reserved, long code,
                                const char *message)
{
    struct kpm_load_result result;

    if (!kpm_load_result_enabled(reserved)) return;
    memset(&result, 0, sizeof(result));
    result.magic = KPM_LOAD_RESULT_MAGIC;
    result.size = sizeof(result);
    result.code = (int)code;
    if (message)
        snprintf(result.message, sizeof(result.message), "%s", message);
    if (copy_to_user(reserved, &result, sizeof(result)))
        pr_debug(KPM_LOAD_PREFIX "set_kpm_load_result: copy_to_user failed\n");
}

static char *next_string(char *string, unsigned long *secsize)
{
    while (string[0]) {
        string++;
        if ((*secsize)-- <= 1) return NULL;
    }
    while (!string[0]) {
        string++;
        if ((*secsize)-- <= 1) return NULL;
    }
    return string;
}

/* Update size with this section: return offset. */
static long get_offset(struct kpm_module *mod, unsigned int *size, Elf_Shdr *sechdr,
                       unsigned int section)
{
    long ret = ALIGN(*size, sechdr->sh_addralign ?: 1);
    *size = ret + sechdr->sh_size;
    return ret;
}

static char *get_next_modinfo(const struct load_info *info, const char *tag,
                              char *prev)
{
    char *p;
    unsigned int taglen = strlen(tag);
    Elf_Shdr *infosec = &info->sechdrs[info->index.info];
    unsigned long size = infosec->sh_size;
    char *modinfo = (char *)info->hdr + infosec->sh_offset;
    if (prev) {
        size -= prev - modinfo;
        modinfo = next_string(prev, &size);
    }
    for (p = modinfo; p; p = next_string(p, &size)) {
        if (strncmp(p, tag, taglen) == 0 && p[taglen] == '=')
            return p + taglen + 1;
    }
    return NULL;
}

static char *get_modinfo(const struct load_info *info, const char *tag)
{
    return get_next_modinfo(info, tag, NULL);
}

static int find_sec(const struct load_info *info, const char *name)
{
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if ((shdr->sh_flags & SHF_ALLOC) &&
            strcmp(info->secstrings + shdr->sh_name, name) == 0)
            return i;
    }
    return 0;
}

static void *get_sh_base(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return NULL;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return (void *)info->hdr + infosec->sh_offset;
}

static unsigned long get_sh_size(struct load_info *info, const char *secname)
{
    int idx = find_sec(info, secname);
    if (!idx) return 0;
    Elf_Shdr *infosec = &info->sechdrs[idx];
    return infosec->sh_entsize;
}

static void layout_sections(struct kpm_module *mod, struct load_info *info)
{
    static unsigned long const masks[][2] = {
        /* NOTE: all executable code must be the first section in this
         * array; otherwise modify the text_size finder in the two loops
         * below. */
        { SHF_EXECINSTR | SHF_ALLOC, ARCH_SHF_SMALL },
        { SHF_ALLOC, SHF_WRITE | ARCH_SHF_SMALL },
        { SHF_WRITE | SHF_ALLOC, ARCH_SHF_SMALL },
        { ARCH_SHF_SMALL | SHF_ALLOC, 0 }
    };

    for (int i = 0; i < info->hdr->e_shnum; i++)
        info->sechdrs[i].sh_entsize = ~0UL;

    for (int m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
        for (int i = 0; i < info->hdr->e_shnum; ++i) {
            Elf_Shdr *s = &info->sechdrs[i];
            if ((s->sh_flags & masks[m][0]) != masks[m][0] ||
                (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
                continue;
            s->sh_entsize = get_offset(mod, &mod->size, s, i);
        }
        switch (m) {
        case 0: /* executable */
            mod->size = align(mod->size);
            mod->text_size = mod->size;
            break;
        case 1: /* RO: text and ro-data */
            mod->size = align(mod->size);
            mod->ro_size = mod->size;
            break;
        case 2:
            break;
        case 3: /* whole */
            mod->size = align(mod->size);
            break;
        }
    }

    /*
     * Reserve a KPM-internal PLT (procedure linkage table) immediately
     * after the KPM image. Each PLT entry is 16 bytes (4 insns: movz,
     * movk, movk, br x16) and gets used by the relocation engine to
     * bounce R_AARCH64_CALL26 / R_AARCH64_JUMP26 branches whose target
     * lies more than 32 MiB from the KPM base. The reservation is
     * independent of the actual number of branches that will overflow;
     * any unused entries stay zero-initialised and are never executed.
     *
     * SUKISU_KPM_PLT_RESERVED sets the upper bound. 64 entries is
     * 1 KiB -- a single extra page for a KPM of any realistic
     * size, and far more than the handful of CALL26/JUMP26 relocations
     * a KPM typically has.
     */
#define SUKISU_KPM_PLT_RESERVED 64
#define SUKISU_KPM_PLT_ENTRY_BYTES 20
    mod->plt_size = SUKISU_KPM_PLT_RESERVED * SUKISU_KPM_PLT_ENTRY_BYTES;
    mod->size += mod->plt_size;
#undef SUKISU_KPM_PLT_RESERVED
#undef SUKISU_KPM_PLT_ENTRY_BYTES
}

static bool is_core_symbol(const Elf_Sym *src, const Elf_Shdr *sechdrs,
                           unsigned int shnum)
{
    const Elf_Shdr *sec;
    if (src->st_shndx == SHN_UNDEF || src->st_shndx >= shnum || !src->st_name)
        return false;
    sec = sechdrs + src->st_shndx;
    if (!(sec->sh_flags & SHF_ALLOC) || !(sec->sh_flags & SHF_EXECINSTR))
        return false;
    return true;
}

/* Change all symbols so that st_value encodes the pointer directly. */
static int simplify_symbols(struct kpm_module *mod, struct load_info *info)
{
    Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
    Elf_Sym *sym = (void *)symsec->sh_addr;
    unsigned long secbase;
    unsigned int i;
    int ret = 0;

    for (i = 1; i < symsec->sh_size / sizeof(Elf_Sym); i++) {
        const char *name = info->strtab + sym[i].st_name;
        switch (sym[i].st_shndx) {
        case SHN_COMMON:
            if (!strncmp(name, "__gnu_lto", 9)) {
                logke("Please compile with -fno-common\n");
                ret = -ENOEXEC;
            }
            break;
        case SHN_ABS:
            break;
        case SHN_UNDEF: {
            unsigned long addr = sukisu_kpm_symbol_lookup(name);
            if (!addr)
                addr = find_kernel_symbol_exact(name);
            if (!addr)
                addr = (unsigned long)kallsyms_lookup_name(name);
            if (!addr) {
                logke("unknown symbol: %s\n", name);
                if (!info->info.error_msg[0])
                    snprintf(info->info.error_msg,
                             sizeof(info->info.error_msg),
                             "unknown symbol: %s", name);
                ret = -ENOENT;
                break;
            }
            sym[i].st_value = addr;
            break;
        }
        default:
            secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
            sym[i].st_value += secbase;
            break;
        }
    }
    return ret;
}

static int apply_relocations(struct kpm_module *mod, const struct load_info *info)
{
    int rc = 0;
    unsigned int i;
    for (i = 1; i < info->hdr->e_shnum; i++) {
        unsigned int infosec = info->sechdrs[i].sh_info;
        if (infosec >= info->hdr->e_shnum) continue;
        if (!(info->sechdrs[infosec].sh_flags & SHF_ALLOC)) continue;
        if (info->sechdrs[i].sh_type == SHT_REL) {
            rc = kpm_apply_relocate(info->sechdrs, info->strtab, info->index.sym,
                                    i, mod);
        } else if (info->sechdrs[i].sh_type == SHT_RELA) {
            rc = kpm_apply_relocate_add(info->sechdrs, info->strtab,
                                        info->index.sym, i, mod);
        }
        if (rc < 0) break;
    }
    return rc;
}

/* todo: free .strtab and .symtab after relocation */
static void layout_symtab(struct kpm_module *mod, struct load_info *info)
{
    Elf_Shdr *symsect = info->sechdrs + info->index.sym;
    Elf_Shdr *strsect = info->sechdrs + info->index.str;
    const Elf_Sym *src;
    unsigned int i, nsrc, ndst, strtab_size = 0;

    symsect->sh_flags |= SHF_ALLOC;
    symsect->sh_entsize = get_offset(mod, &mod->size, symsect, info->index.sym);

    src = (void *)info->hdr + symsect->sh_offset;
    nsrc = symsect->sh_size / sizeof(*src);

    strtab_size = 1;
    for (ndst = i = 0; i < nsrc; i++) {
        if (i == 0 ||
            is_core_symbol(src + i, info->sechdrs, info->hdr->e_shnum)) {
            strtab_size += strlen(&info->strtab[src[i].st_name]) + 1;
            ndst++;
        }
    }

    info->symoffs = ALIGN(mod->size, symsect->sh_addralign ?: 1);
    info->stroffs = mod->size = info->symoffs + ndst * sizeof(Elf_Sym);
    mod->size += strtab_size;

    strsect->sh_flags |= SHF_ALLOC;
    strsect->sh_entsize = get_offset(mod, &mod->size, strsect, info->index.str);
}

static int rewrite_section_headers(struct load_info *info)
{
    info->sechdrs[0].sh_addr = 0;
    for (int i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (shdr->sh_type != SHT_NOBITS &&
            info->len < shdr->sh_offset + shdr->sh_size) {
            return -ENOEXEC;
        }
        shdr->sh_addr = (size_t)info->hdr + shdr->sh_offset;
    }
    return 0;
}

static int move_module(struct kpm_module *mod, struct load_info *info)
{
    logki("alloc module size: %x\n", mod->size);
    mod->start = vmalloc(mod->size);
    if (!mod->start) return -ENOMEM;
    memset(mod->start, 0, mod->size);

    /*
     * The trailing plt_size bytes of the allocation form the KPM
     * PLT. The PLT area must be inside the KPM image so that a
     * `bl <plt_entry>` instruction stays within the 26-bit signed
     * range (KPM image is < 1 MiB in practice) regardless of where
     * vmalloc() actually placed the KPM.
     *
     * memset above already zeroed this region, so unused PLT slots
     * remain in their reset state and are never executed.
     */
    mod->plt_start = mod->start + mod->size - mod->plt_size;
    mod->plt_next = 0;

    logkd("final section addresses:\n");

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        void *dest;
        Elf_Shdr *shdr = &info->sechdrs[i];
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;

        dest = mod->start + shdr->sh_entsize;
        const char *sname = info->secstrings + shdr->sh_name;

        logkd("    %s %llx %llx\n", sname, (unsigned long long)dest,
              (unsigned long long)shdr->sh_size);

        if (shdr->sh_type != SHT_NOBITS)
            memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

        shdr->sh_addr = (unsigned long)dest;

        if (!mod->init && !strcmp(".kpm.init", sname))
            mod->init = (mod_initcall_t *)dest;
        if (!strcmp(".kpm.ctl0", sname)) mod->ctl0 = (mod_ctl0call_t *)dest;
        if (!strcmp(".kpm.ctl1", sname)) mod->ctl1 = (mod_ctl1call_t *)dest;
        if (!mod->exit && !strcmp(".kpm.exit", sname))
            mod->exit = (mod_exitcall_t *)dest;
        if (!mod->event && !strcmp(".kpm.event", sname))
            mod->event = (mod_eventcall_t *)dest;
        if (!mod->info.base && !strcmp(".kpm.info", sname))
            mod->info.base = (const char *)dest;
    }
    mod->info.name = info->info.name - info->info.base + mod->info.base;
    mod->info.version =
        info->info.version - info->info.base + mod->info.base;

    if (info->info.license)
        mod->info.license =
            info->info.license - info->info.base + mod->info.base;
    if (info->info.author)
        mod->info.author =
            info->info.author - info->info.base + mod->info.base;
    if (info->info.description)
        mod->info.description =
            info->info.description - info->info.base + mod->info.base;

    return 0;
}

static int setup_load_info(struct load_info *info)
{
    int rc = 0;
    info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
    info->secstrings =
        (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;

    if ((rc = rewrite_section_headers(info))) {
        logke("rewrite section error\n");
        set_load_error(info, "rewrite section headers failed");
        return rc;
    }

    if (!find_sec(info, ".kpm.init") || !find_sec(info, ".kpm.exit")) {
        logke("no .kpm.init or .kpm.exit section\n");
        set_load_error(info, "no .kpm.init or .kpm.exit section");
        return -ENOEXEC;
    }

    info->index.info = find_sec(info, ".kpm.info");
    if (!info->index.info) {
        logke("no .kpm.info section\n");
        set_load_error(info, "no .kpm.info section");
        return -ENOEXEC;
    }
    info->info.base = get_sh_base(info, ".kpm.info");
    info->info.size = get_sh_size(info, ".kpm.info");

    const char *name = get_modinfo(info, "name");
    if (!name) {
        logke("module name not found\n");
        set_load_error(info, "module name not found");
        return -ENOEXEC;
    }
    info->info.name = name;
    logkd("loading module:\n");
    logkd("    name: %s\n", name);

    const char *version = get_modinfo(info, "version");
    if (!version) {
        logkd("module version not found\n");
        set_load_error(info, "module version not found");
        return -ENOEXEC;
    }
    info->info.version = version;
    logkd("    version: %s\n", version);

    const char *license = get_modinfo(info, "license");
    info->info.license = license;
    logkd("    license: %s\n", license);

    const char *author = get_modinfo(info, "author");
    info->info.author = author;
    logkd("    author: %s\n", author);

    const char *description = get_modinfo(info, "description");
    info->info.description = description;
    logkd("    description: %s\n", description);

    for (int i = 1; i < info->hdr->e_shnum; i++) {
        if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
            info->index.sym = i;
            info->index.str = info->sechdrs[i].sh_link;
            info->strtab = (char *)info->hdr +
                           info->sechdrs[info->index.str].sh_offset;
            break;
        }
    }

    if (info->index.sym == 0) {
        logkd("module has no symbols (stripped?)\n");
        set_load_error(info, "module has no symbols (stripped?)");
        return -ENOEXEC;
    }
    return 0;
}

static int elf_header_check(struct load_info *info)
{
    if (info->len <= sizeof(*(info->hdr))) {
        set_load_error(info, "ELF header is truncated");
        return -ENOEXEC;
    }
    if (memcmp(info->hdr->e_ident, ELFMAG, SELFMAG) ||
        info->hdr->e_type != ET_REL || !elf_check_arch(info->hdr) ||
        info->hdr->e_shentsize != sizeof(Elf_Shdr)) {
        set_load_error(info, "ELF header is not a supported AArch64 relocatable module");
        return -ENOEXEC;
    }
    if (info->hdr->e_shoff >= info->len ||
        (info->hdr->e_shnum * sizeof(Elf_Shdr) >
         info->len - info->hdr->e_shoff)) {
        set_load_error(info, "ELF section headers are invalid");
        return -ENOEXEC;
    }
    return 0;
}

struct kpm_module *kpm_find_module(const char *name)
{
    struct kpm_module *pos;
    list_for_each_entry(pos, &kpm_modules.list, list)
    {
        if (!strcmp(name, pos->info.name)) {
            return pos;
        }
    }
    return NULL;
}
EXPORT_SYMBOL(kpm_find_module);

long kpm_load_module_ex(const void *data, int len, const char *args,
                          const char *event, const char *source,
                          void *__user reserved)
{
    struct load_info load_info = {
        .len = len,
        .hdr = data,
    };
    struct load_info *info = &load_info;
    long rc = 0;

    if ((rc = elf_header_check(info))) goto out;
    if ((rc = setup_load_info(info))) goto out;

    if (kpm_find_module(info->info.name)) {
        logkfd("%s exist\n", info->info.name);
        set_load_error(info, "module already exists");
        rc = -EEXIST;
        goto out;
    }

    struct kpm_module *mod = vzalloc(sizeof(struct kpm_module));
    if (!mod) {
        set_load_error(info, "allocate module state failed");
        rc = -ENOMEM;
        goto out;
    }
    snprintf(mod->load_event, sizeof(mod->load_event), "%s",
             event ? event : "");
    snprintf(mod->load_source, sizeof(mod->load_source), "%s",
             source ? source : "embedded");

    if (args) {
        mod->args = vmalloc(strlen(args) + 1);
        if (!mod->args) {
            set_load_error(info, "allocate module args failed");
            rc = -ENOMEM;
            goto free1;
        }
        strcpy(mod->args, args);
    }

    layout_sections(mod, info);
    layout_symtab(mod, info);

    if ((rc = move_module(mod, info))) {
        set_load_error(info, "allocate executable module memory failed");
        goto free;
    }
    if ((rc = simplify_symbols(mod, info))) goto free;
    if ((rc = apply_relocations(mod, info))) {
        set_load_error(info, "apply relocations failed");
        goto free;
    }

    /* Make module .text executable; vmalloc pages default to NX.
     *
     * Two disjoint regions need X permission:
     *
     *   1. KPM .text (mod->text_size bytes). Pre-PLT loader used a
     *      single call here, so we keep that exact range to preserve
     *      the W^X posture of any .rodata / .data / .bss pages that
     *      happen to sit on the same vmalloc page as .text.
     *
     *   2. The .kpm.plt area at the very tail of the allocation
     *      (mod->plt_size bytes). In practice PLT is < 1 KiB and the
     *      KPM image is < 32 KiB, so PLT shares the trailing page
     *      with the last bytes of .bss and set_memory_x is a no-op
     *      for any page that already contains KPM .text. When the
     *      KPM is large enough that PLT lands on a dedicated page
     *      (KPM > ~32 KiB), that page must be X-marked or the first
     *      CALL26 into the PLT will fault on execute.
     */
    if (mod->text_size) {
        int xrc = set_memory_x((unsigned long)mod->start,
                               DIV_ROUND_UP(mod->text_size, PAGE_SIZE));
        if (xrc) {
            logke("set_memory_x(.text) failed: %d\n", xrc);
            set_load_error(info, "make module text executable failed");
            rc = xrc;
            goto free;
        }
        /*
         * set_memory_x already issues the dsb/isb needed for I-cache
         * coherency on aarch64, so an extra flush_icache_range() here
         * would be redundant. We keep the call site in case a future
         * KPM port targets a KMI that does not have set_memory_x.
         */
    }
    if (mod->plt_size) {
        /*
         * The PLT area is not page-aligned (mod->plt_start sits at
         * the tail of the KPM image, which is page-aligned at
         * mod->start, plus a sections-byte offset). Round the start
         * down and the size up to page boundaries so that
         * set_memory_x() flips the X bit on every page the PLT
         * actually touches -- otherwise the bytes that overflow into
         * a fresh page would remain NX and the first br to a PLT
         * entry straddling that page would fault on execute.
         */
        unsigned long plt_start = mod->plt_start;
        unsigned long plt_end = plt_start + mod->plt_size;
        unsigned long plt_start_aligned = plt_start & PAGE_MASK;
        unsigned long plt_size_aligned =
            DIV_ROUND_UP(plt_end - plt_start_aligned, PAGE_SIZE);
        logki("KPM-MOD: plt area [%lx, %lx) -> set_memory_x([%lx + %lu pages)\n",
              plt_start, plt_end, plt_start_aligned, plt_size_aligned);
        int xrc = set_memory_x(plt_start_aligned, plt_size_aligned);
        if (xrc) {
            logke("set_memory_x(.plt) failed: %d\n", xrc);
            set_load_error(info, "make module plt executable failed");
            rc = xrc;
            goto free;
        }
    }

    /*
     * Print a one-line snapshot of where the KPM landed and how big
     * each section ended up so that post-mortem analysis of a
     * crash -- the KPM init_module call below may take the device
     * down with it -- has the relocation context in dmesg.
     */
    logki("KPM-MOD: [%s] start=%px size=%x text_size=%x plt=[%px +%u/%u]\n",
          info->info.name, mod->start, mod->size, mod->text_size,
          mod->plt_start, mod->plt_next, mod->plt_size);

    rc = (*mod->init)(mod->args, event, reserved);

    if (!rc) {
        logkfi("[%s] succeed with [%s]\n", mod->info.name, args);
        list_add_tail(&mod->list, &kpm_modules.list);
        goto out;
    } else {
        set_load_error(info, "module init failed");
        logkfi("[%s] failed with [%s] error: %ld, try exit ...\n",
               mod->info.name, args, rc);
        (*mod->exit)(reserved);
    }

free:
    if (mod->start) vfree(mod->start);
    if (mod->args) kvfree(mod->args);
free1:
    kvfree(mod);
out:
    set_kpm_load_result(reserved, rc,
                        rc ? load_error(info, "load module failed")
                           : "module loaded");
    return rc;
}
EXPORT_SYMBOL(kpm_load_module_ex);

long kpm_unload_module(const char *name, void *__user reserved)
{
    if (!name) return -EINVAL;
    logkfe("name: %s\n", name);

    rcu_read_lock();
    struct kpm_module *mod = kpm_find_module(name);
    if (mod) list_del_rcu(&mod->list);
    rcu_read_unlock();
    if (!mod) return -ENOENT;

    /*
     * The module exit callback is arbitrary teardown: it may sleep and
     * may call synchronize_rcu() (e.g. unregister_break_hook /
     * unregister_step_hook). It must therefore run outside the RCU
     * read-side critical section -- calling synchronize_rcu() while
     * holding rcu_read_lock() self-deadlocks, since the grace period
     * cannot end while the caller is itself a reader.
     */
    long rc = (*mod->exit)(reserved);

    /* Drain readers that found mod before it was unlinked, then free. */
    synchronize_rcu();

    if (mod->args) kvfree(mod->args);
    if (mod->ctl_args) kvfree(mod->ctl_args);
    if (mod->start) vfree(mod->start);
    kvfree(mod);
    logkfi("name: %s, rc: %ld\n", name, rc);
    return rc;
}
EXPORT_SYMBOL(kpm_unload_module);

long kpm_load_module(const void *data, int len, const char *args,
                      const char *event, void *__user reserved)
{
    return kpm_load_module_ex(data, len, args, event, "embedded", reserved);
}
EXPORT_SYMBOL(kpm_load_module);

long kpm_load_module_path_event(const char *path, const char *args,
                                const char *event, void *__user reserved)
{
    long rc = 0;
    logkfd("%s\n", path);
    if (!path) {
        rc = -EINVAL;
        set_kpm_load_result(reserved, rc, "module path is null");
        return rc;
    }

    struct file *filp = filp_open(path, O_RDONLY, 0);
    if (unlikely(!filp || IS_ERR(filp))) {
        logkfe("open module: %s error\n", path);
        rc = PTR_ERR(filp);
        set_kpm_load_result(reserved, rc, "open module file failed");
        goto out;
    }
    loff_t len = vfs_llseek(filp, 0, SEEK_END);
    logkfd("module size: %llx\n", (unsigned long long)len);
    vfs_llseek(filp, 0, SEEK_SET);

    void *data = vmalloc(len);
    if (!data) {
        rc = -ENOMEM;
        set_kpm_load_result(reserved, rc, "allocate module file buffer failed");
        goto close;
    }
    memset(data, 0, len);

    loff_t pos = 0;
    kernel_read(filp, data, len, &pos);
    filp_close(filp, NULL);
    filp = NULL;

    if (pos != len) {
        logkfe("read module: %s error\n", path);
        rc = -EIO;
        set_kpm_load_result(reserved, rc, "read module file failed");
        goto free;
    }

    rc = kpm_load_module_ex(data, len, args, event ? event : "load-file", "file",
                        reserved);
free:
    kvfree(data);
close:
    if (filp) filp_close(filp, NULL);
out:
    return rc;
}
EXPORT_SYMBOL(kpm_load_module_path_event);

long kpm_load_module_path(const char *path, const char *args, void *__user reserved)
{
    return kpm_load_module_path_event(path, args, "load-file", reserved);
}
EXPORT_SYMBOL(kpm_load_module_path);

long kpm_module_control0(const char *name, const char *ctl_args,
                         char *__user out_msg, int outlen)
{
    if (!name || !ctl_args) return -EINVAL;
    int args_len = strlen(ctl_args);
    if (args_len <= 0) return -EINVAL;

    logkfi("name %s, args: %s\n", name, ctl_args);

    long rc = 0;
    rcu_read_lock();

    struct kpm_module *mod = kpm_find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }

    if (!mod->ctl0 || !*mod->ctl0) {
        logkfe("no ctl0\n");
        rc = -ENOSYS;
        goto out;
    }

    if (mod->ctl_args) kvfree(mod->ctl_args);

    mod->ctl_args = vmalloc(args_len + 1);
    if (!mod->ctl_args) {
        rc = -ENOMEM;
        goto out;
    }

    strcpy(mod->ctl_args, ctl_args);

    rc = (*mod->ctl0)(mod->ctl_args, out_msg, outlen);

    logkfi("name: %s, rc: %ld\n", name, rc);
out:
    rcu_read_unlock();
    return rc;
}
EXPORT_SYMBOL(kpm_module_control0);

long kpm_module_control1(const char *name, void *a1, void *a2, void *a3)
{
    logkfi("name %s, a1: %llx, a2: %llx, a3: %llx\n", name,
           (unsigned long long)a1, (unsigned long long)a2,
           (unsigned long long)a3);
    long rc = 0;
    rcu_read_lock();

    struct kpm_module *mod = kpm_find_module(name);
    if (!mod) {
        rc = -ENOENT;
        goto out;
    }

    if (!mod->ctl1 || !*mod->ctl1) {
        logkfe("no ctl1\n");
        rc = -ENOSYS;
        goto out;
    }

    rc = (*mod->ctl1)(a1, a2, a3);

    logkfi("name: %s, rc: %ld\n", name, rc);
out:
    rcu_read_unlock();
    return rc;
}
EXPORT_SYMBOL(kpm_module_control1);

long kpm_notify_modules_event(const char *event, const char *args,
                              void *__user reserved)
{
    if (!event) return -EINVAL;

    long result = 0;
    int count = 0;
    rcu_read_lock();

    struct kpm_module *pos;
    list_for_each_entry(pos, &kpm_modules.list, list)
    {
        if (!pos->event || !*pos->event) continue;

        long rc = (*pos->event)(event, args, reserved);
        logkfi("event: %s, module: %s, rc: %ld\n", event, pos->info.name, rc);
        if (rc < 0 && !result) result = rc;
        count++;
    }

    rcu_read_unlock();
    return result ?: count;
}
EXPORT_SYMBOL(kpm_notify_modules_event);

int kpm_get_module_nums(void)
{
    rcu_read_lock();

    struct kpm_module *pos;
    int n = 0;
    list_for_each_entry(pos, &kpm_modules.list, list)
    {
        n++;
    }
    rcu_read_unlock();

    logkfd("%d\n", n);
    return n;
}
EXPORT_SYMBOL(kpm_get_module_nums);

int kpm_list_modules(char *out_names, int size)
{
    if (!out_names || size <= 0) return -EINVAL;
    out_names[0] = '\0';

    rcu_read_lock();

    struct kpm_module *pos;
    int off = 0;
    list_for_each_entry(pos, &kpm_modules.list, list)
    {
        off += snprintf(out_names + off, size - 1 - off, "%s\n",
                        pos->info.name);
    }
    if (off > 0) out_names[off - 1] = '\0';

    rcu_read_unlock();
    return off;
}
EXPORT_SYMBOL(kpm_list_modules);

int kpm_get_module_info(const char *name, char *out_info, int size)
{
    if (size <= 0) return 0;
    rcu_read_lock();

    struct kpm_module *mod = kpm_find_module(name);
    if (!mod) {
        rcu_read_unlock();
        return -ENOENT;
    }

    int sz = snprintf(
        out_info, size,
        "name=%s\n"
        "version=%s\n"
        "license=%s\n"
        "author=%s\n"
        "description=%s\n"
        "args=%s\n",
        mod->info.name, mod->info.version, mod->info.license, mod->info.author,
        mod->info.description, mod->args ? mod->args : "");

    if (sz < 0) sz = 0;
    if (sz < size) {
        int tail = snprintf(out_info + sz, size - sz,
                            "load_event=%s\n"
                            "load_source=%s\n",
                            mod->load_event, mod->load_source);
        if (tail > 0) sz += tail;
    }

    out_info[size - 1] = '\0';
    logkfd("%s", out_info);

    rcu_read_unlock();
    return sz;
}
EXPORT_SYMBOL(kpm_get_module_info);

void kpm_module_init(void)
{
    kp_compat_init();
    kp_hook_runtime_init();
    INIT_LIST_HEAD(&kpm_modules.list);
    spin_lock_init(&kpm_module_lock);
}
