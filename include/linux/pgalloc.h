/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGALLOC_H
#define _LINUX_PGALLOC_H

#include <linux/pgtable.h>
#include <asm/pgalloc.h>

static inline void pgd_populate_kernel(unsigned long addr, pgd_t *pgd,
				       p4d_t *p4d)
{
	pgd_populate(&init_mm, pgd, p4d);
	if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_PGD_MODIFIED)
		arch_sync_kernel_mappings(addr, addr);
}

static inline void p4d_populate_kernel(unsigned long addr, p4d_t *p4d,
				       pud_t *pud)
{
	p4d_populate(&init_mm, p4d, pud);
	if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_P4D_MODIFIED)
		arch_sync_kernel_mappings(addr, addr);
}

#endif /* _LINUX_PGALLOC_H */
