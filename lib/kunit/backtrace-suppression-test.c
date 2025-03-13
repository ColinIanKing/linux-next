// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit test for suppressing warning tracebacks
 *
 * Copyright (C) 2024, Guenter Roeck
 * Author: Guenter Roeck <linux@roeck-us.net>
 */

#include <kunit/test.h>
#include <linux/bug.h>

static void backtrace_suppression_test_warn_direct(struct kunit *test)
{
	DEFINE_SUPPRESSED_WARNING(backtrace_suppression_test_warn_direct);

	KUNIT_START_SUPPRESSED_WARNING(backtrace_suppression_test_warn_direct);
	WARN(1, "This backtrace should be suppressed");
	KUNIT_END_SUPPRESSED_WARNING(backtrace_suppression_test_warn_direct);

	KUNIT_EXPECT_EQ(test, SUPPRESSED_WARNING_COUNT(backtrace_suppression_test_warn_direct), 1);
}

static void trigger_backtrace_warn(void)
{
	WARN(1, "This backtrace should be suppressed");
}

static void backtrace_suppression_test_warn_indirect(struct kunit *test)
{
	DEFINE_SUPPRESSED_WARNING(trigger_backtrace_warn);

	KUNIT_START_SUPPRESSED_WARNING(trigger_backtrace_warn);
	trigger_backtrace_warn();
	KUNIT_END_SUPPRESSED_WARNING(trigger_backtrace_warn);

	KUNIT_EXPECT_EQ(test, SUPPRESSED_WARNING_COUNT(trigger_backtrace_warn), 1);
}

static void backtrace_suppression_test_warn_multi(struct kunit *test)
{
	DEFINE_SUPPRESSED_WARNING(trigger_backtrace_warn);
	DEFINE_SUPPRESSED_WARNING(backtrace_suppression_test_warn_multi);

	KUNIT_START_SUPPRESSED_WARNING(backtrace_suppression_test_warn_multi);
	KUNIT_START_SUPPRESSED_WARNING(trigger_backtrace_warn);
	WARN(1, "This backtrace should be suppressed");
	trigger_backtrace_warn();
	KUNIT_END_SUPPRESSED_WARNING(trigger_backtrace_warn);
	KUNIT_END_SUPPRESSED_WARNING(backtrace_suppression_test_warn_multi);

	KUNIT_EXPECT_EQ(test, SUPPRESSED_WARNING_COUNT(backtrace_suppression_test_warn_multi), 1);
	KUNIT_EXPECT_EQ(test, SUPPRESSED_WARNING_COUNT(trigger_backtrace_warn), 1);
}

static void backtrace_suppression_test_warn_on_direct(struct kunit *test)
{
	DEFINE_SUPPRESSED_WARNING(backtrace_suppression_test_warn_on_direct);

	if (!IS_ENABLED(CONFIG_DEBUG_BUGVERBOSE) && !IS_ENABLED(CONFIG_KALLSYMS))
		kunit_skip(test, "requires CONFIG_DEBUG_BUGVERBOSE or CONFIG_KALLSYMS");

	KUNIT_START_SUPPRESSED_WARNING(backtrace_suppression_test_warn_on_direct);
	WARN_ON(1);
	KUNIT_END_SUPPRESSED_WARNING(backtrace_suppression_test_warn_on_direct);

	KUNIT_EXPECT_EQ(test,
			SUPPRESSED_WARNING_COUNT(backtrace_suppression_test_warn_on_direct), 1);
}

static void trigger_backtrace_warn_on(void)
{
	WARN_ON(1);
}

static void backtrace_suppression_test_warn_on_indirect(struct kunit *test)
{
	DEFINE_SUPPRESSED_WARNING(trigger_backtrace_warn_on);

	if (!IS_ENABLED(CONFIG_DEBUG_BUGVERBOSE))
		kunit_skip(test, "requires CONFIG_DEBUG_BUGVERBOSE");

	KUNIT_START_SUPPRESSED_WARNING(trigger_backtrace_warn_on);
	trigger_backtrace_warn_on();
	KUNIT_END_SUPPRESSED_WARNING(trigger_backtrace_warn_on);

	KUNIT_EXPECT_EQ(test, SUPPRESSED_WARNING_COUNT(trigger_backtrace_warn_on), 1);
}

static struct kunit_case backtrace_suppression_test_cases[] = {
	KUNIT_CASE(backtrace_suppression_test_warn_direct),
	KUNIT_CASE(backtrace_suppression_test_warn_indirect),
	KUNIT_CASE(backtrace_suppression_test_warn_multi),
	KUNIT_CASE(backtrace_suppression_test_warn_on_direct),
	KUNIT_CASE(backtrace_suppression_test_warn_on_indirect),
	{}
};

static struct kunit_suite backtrace_suppression_test_suite = {
	.name = "backtrace-suppression-test",
	.test_cases = backtrace_suppression_test_cases,
};
kunit_test_suites(&backtrace_suppression_test_suite);

MODULE_LICENSE("GPL");
