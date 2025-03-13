/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_ASM_BUG_H
/*
 * Copyright (C) 2017  ARM Limited
 */
#define __ASM_ASM_BUG_H

#include <asm/brk-imm.h>

#ifdef CONFIG_DEBUG_BUGVERBOSE

#ifdef CONFIG_KUNIT_SUPPRESS_BACKTRACE
# define HAVE_BUG_FUNCTION
# define __BUG_FUNC_PTR(func)	.long func - .;
#else
# define __BUG_FUNC_PTR(func)
#endif

#define _BUGVERBOSE_LOCATION(file, func, line) __BUGVERBOSE_LOCATION(file, func, line)
#define __BUGVERBOSE_LOCATION(file, func, line)		\
		.pushsection .rodata.str,"aMS",@progbits,1;	\
	14472:	.string file;					\
		.popsection;					\
								\
		.long 14472b - .;				\
		__BUG_FUNC_PTR(func)				\
		.short line;
#else
#define _BUGVERBOSE_LOCATION(file, func, line)
#endif

#ifdef CONFIG_GENERIC_BUG

#define __BUG_ENTRY(flags, func)			\
		.pushsection __bug_table,"aw";		\
		.align 2;				\
	14470:	.long 14471f - .;			\
_BUGVERBOSE_LOCATION(__FILE__, func, __LINE__)		\
		.short flags; 				\
		.align 2;				\
		.popsection;				\
	14471:
#else
#define __BUG_ENTRY(flags, func)
#endif

#define ASM_BUG_FLAGS(flags, func)			\
	__BUG_ENTRY(flags, func)			\
	brk	BUG_BRK_IMM

#define ASM_BUG()	ASM_BUG_FLAGS(0, .)

#endif /* __ASM_ASM_BUG_H */
