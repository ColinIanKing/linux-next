/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_BUG_H
#define __ASM_BUG_H

#include <asm/break.h>
#include <kunit/bug.h>
#include <linux/stringify.h>
#include <linux/objtool.h>

#ifndef CONFIG_DEBUG_BUGVERBOSE
#define _BUGVERBOSE_LOCATION(file, func, line)
#else
#ifdef CONFIG_KUNIT_SUPPRESS_BACKTRACE
# define HAVE_BUG_FUNCTION
# define __BUG_FUNC_PTR(func)  .long func - .;
#else
# define __BUG_FUNC_PTR(func)
#endif /* CONFIG_KUNIT_SUPPRESS_BACKTRACE */

#define __BUGVERBOSE_LOCATION(file, func, line)			\
		.pushsection .rodata.str, "aMS", @progbits, 1;	\
	10002:	.string file;					\
		.popsection;					\
								\
		.long 10002b - .;				\
		__BUG_FUNC_PTR(func)				\
		.short line;
#define _BUGVERBOSE_LOCATION(file, func, line) __BUGVERBOSE_LOCATION(file, func, line)
#endif

#ifndef CONFIG_GENERIC_BUG
#define __BUG_ENTRY(flags, func)
#else
#define __BUG_ENTRY(flags, func)				\
		.pushsection __bug_table, "aw";			\
		.align 2;					\
	10000:	.long 10001f - .;				\
		_BUGVERBOSE_LOCATION(__FILE__, func, __LINE__)	\
		.short flags; 					\
		.popsection;					\
	10001:
#endif

#define ASM_BUG_FLAGS(flags, func)				\
	__BUG_ENTRY(flags, func)				\
	break		BRK_BUG;

#define ASM_BUG()	ASM_BUG_FLAGS(0, .)

#ifdef HAVE_BUG_FUNCTION
# define __BUG_FUNC    __func__
#else
# define __BUG_FUNC    NULL
#endif

#define __BUG_FLAGS(flags, extra)				\
	asm_inline volatile (__stringify(ASM_BUG_FLAGS(flags, %0)) \
			     extra : : "i" (__BUG_FUNC) );

#define __WARN_FLAGS(flags)					\
do {								\
	instrumentation_begin();				\
	if (!KUNIT_IS_SUPPRESSED_WARNING(__func__))			\
		__BUG_FLAGS(BUGFLAG_WARNING|(flags), ANNOTATE_REACHABLE(10001b));\
	instrumentation_end();					\
} while (0)

#define BUG()							\
do {								\
	instrumentation_begin();				\
	__BUG_FLAGS(0, "");					\
	unreachable();						\
} while (0)

#define HAVE_ARCH_BUG

#include <asm-generic/bug.h>

#endif /* __ASM_BUG_H */
