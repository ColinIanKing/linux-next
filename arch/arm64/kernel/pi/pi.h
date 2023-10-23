// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

#include <linux/types.h>

#define __prel64_initconst	__section(".init.rodata.prel64")

typedef volatile signed long prel64_t;

static inline void *prel64_to_pointer(const prel64_t *offset)
{
	if (!*offset)
		return NULL;
	return (void *)offset + *offset;
}

extern bool dynamic_scs_is_enabled;

extern pgd_t init_idmap_pg_dir[], init_idmap_pg_end[];

void init_feature_override(u64 boot_status, const void *fdt, int chosen);
u64 kaslr_early_init(void *fdt, int chosen);
void relocate_kernel(u64 offset);
int scs_patch(const u8 eh_frame[], int size);

void map_range(u64 *pgd, u64 start, u64 end, u64 pa, pgprot_t prot,
	       int level, pte_t *tbl, bool may_use_cont, u64 va_offset);

asmlinkage u64 create_init_idmap(pgd_t *pgd, pteval_t clrmask);
