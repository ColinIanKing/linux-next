/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGALLOC_H
#define _LINUX_PGALLOC_H

#include <linux/pgtable.h>
#include <asm/pgalloc.h>

#define pgd_populate_kernel(addr, pgd, p4d)				\
	do {								\
		pgd_populate(&init_mm, pgd, p4d);			\
		if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_PGD_MODIFIED)	\
			arch_sync_kernel_mappings(addr, addr);		\
	} while (0)

#define p4d_populate_kernel(addr, p4d, pud)				\
	do {								\
		p4d_populate(&init_mm, p4d, pud);			\
		if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_P4D_MODIFIED)	\
			arch_sync_kernel_mappings(addr, addr);		\
	} while (0)

#endif /* _LINUX_PGALLOC_H */
