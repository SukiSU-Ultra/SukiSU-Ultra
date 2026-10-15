#ifndef __SUKISU_KPM_RELOC_H
#define __SUKISU_KPM_RELOC_H

#include <linux/elf.h>
#include "module.h"

int kpm_apply_relocations(Elf64_Shdr *sections, unsigned int sym_index,
                          unsigned int rel_index, struct kpm_module *module);

#endif
