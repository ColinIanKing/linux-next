/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KUnit helpers for backtrace suppression
 *
 * Copyright (c) 2024 Guenter Roeck <linux@roeck-us.net>
 */

#ifndef _KUNIT_BUG_H
#define _KUNIT_BUG_H

#ifndef __ASSEMBLY__

#include <linux/kconfig.h>

#ifdef CONFIG_KUNIT_SUPPRESS_BACKTRACE

#include <linux/stringify.h>
#include <linux/types.h>

struct __suppressed_warning {
	struct list_head node;
	const char *function;
	int counter;
};

void __kunit_start_suppress_warning(struct __suppressed_warning *warning);
void __kunit_end_suppress_warning(struct __suppressed_warning *warning);
bool __kunit_is_suppressed_warning(const char *function);

#define DEFINE_SUPPRESSED_WARNING(func)	\
	struct __suppressed_warning __kunit_suppress_##func = \
		{ .function = __stringify(func), .counter = 0 }

#define KUNIT_START_SUPPRESSED_WARNING(func) \
	__kunit_start_suppress_warning(&__kunit_suppress_##func)

#define KUNIT_END_SUPPRESSED_WARNING(func) \
	__kunit_end_suppress_warning(&__kunit_suppress_##func)

#define KUNIT_IS_SUPPRESSED_WARNING(func) \
	__kunit_is_suppressed_warning(func)

#define SUPPRESSED_WARNING_COUNT(func) \
	(__kunit_suppress_##func.counter)

#else /* CONFIG_KUNIT_SUPPRESS_BACKTRACE */

#define DEFINE_SUPPRESSED_WARNING(func)
#define KUNIT_START_SUPPRESSED_WARNING(func)
#define KUNIT_END_SUPPRESSED_WARNING(func)
#define KUNIT_IS_SUPPRESSED_WARNING(func) (false)
#define SUPPRESSED_WARNING_COUNT(func) (0)

#endif /* CONFIG_KUNIT_SUPPRESS_BACKTRACE */
#endif /* __ASSEMBLY__ */
#endif /* _KUNIT_BUG_H */
