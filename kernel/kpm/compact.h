#ifndef __SUKISU_KPM_COMPACT_H
#define __SUKISU_KPM_COMPACT_H

/*
 * Compact symbol table: gives a KPM module a stable, version-independent
 * way to reach a small number of well-known SukiSU-Ultra symbols. Modeled
 * after KernelPatch's `compact_find_symbol`.
 *
 * The exported `sukisu_compact_find_symbol` is the single entry point that
 * a KPM should call to resolve a name; it first walks the in-kernel
 * `address_symbol` table, then falls back to the generic kernel symbol
 * resolver.
 */

extern unsigned long sukisu_compact_find_symbol(const char *name);

#endif
