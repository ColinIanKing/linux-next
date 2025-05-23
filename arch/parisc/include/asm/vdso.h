/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PARISC_VDSO_H__
#define __PARISC_VDSO_H__

#ifndef __ASSEMBLER__

#ifdef CONFIG_64BIT
#include <generated/vdso64-offsets.h>
#endif
#include <generated/vdso32-offsets.h>

#define VDSO64_SYMBOL(tsk, name) ((tsk)->mm->context.vdso_base + (vdso64_offset_##name))
#define VDSO32_SYMBOL(tsk, name) ((tsk)->mm->context.vdso_base + (vdso32_offset_##name))

#endif /* __ASSEMBLER__ */

/* Default link addresses for the vDSOs */
#define VDSO_LBASE	0

#define VDSO_VERSION_STRING	LINUX_6.11

#endif /* __PARISC_VDSO_H__ */
