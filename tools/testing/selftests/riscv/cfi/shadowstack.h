/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef SELFTEST_SHADOWSTACK_TEST_H
#define SELFTEST_SHADOWSTACK_TEST_H
#include <stddef.h>
#include <linux/prctl.h>

/*
 * a cfi test returns true for success or false for fail
 * takes a number for test number to index into array and void pointer.
 */
typedef bool (*shstk_test_func)(unsigned long test_num, void *);

struct shadow_stack_tests {
	char *name;
	shstk_test_func t_func;
};

bool shadow_stack_fork_test(unsigned long test_num, void *ctx);
bool shadow_stack_map_test(unsigned long test_num, void *ctx);
bool shadow_stack_protection_test(unsigned long test_num, void *ctx);
bool shadow_stack_gup_tests(unsigned long test_num, void *ctx);
bool shadow_stack_signal_test(unsigned long test_num, void *ctx);

int execute_shadow_stack_tests(void);

#endif
