// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit helpers for backtrace suppression
 *
 * Copyright (c) 2024 Guenter Roeck <linux@roeck-us.net>
 */

#include <kunit/bug.h>
#include <linux/export.h>
#include <linux/list.h>
#include <linux/string.h>

static LIST_HEAD(suppressed_warnings);

void __kunit_start_suppress_warning(struct __suppressed_warning *warning)
{
	list_add(&warning->node, &suppressed_warnings);
}
EXPORT_SYMBOL_GPL(__kunit_start_suppress_warning);

void __kunit_end_suppress_warning(struct __suppressed_warning *warning)
{
	list_del(&warning->node);
}
EXPORT_SYMBOL_GPL(__kunit_end_suppress_warning);

bool __kunit_is_suppressed_warning(const char *function)
{
	struct __suppressed_warning *warning;

	if (!function)
		return false;

	list_for_each_entry(warning, &suppressed_warnings, node) {
		if (!strcmp(function, warning->function))
			return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(__kunit_is_suppressed_warning);
