// SPDX-License-Identifier: GPL-2.0

/* Based on Christian Brauner's clone3() example */

#define _GNU_SOURCE
#include <asm/mman.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>

#include "../kselftest.h"
#include "../ksft_shstk.h"
#include "clone3_selftests.h"

static bool shadow_stack_supported;
static size_t max_supported_args_size;

enum test_mode {
	CLONE3_ARGS_NO_TEST,
	CLONE3_ARGS_ALL_0,
	CLONE3_ARGS_INVAL_EXIT_SIGNAL_BIG,
	CLONE3_ARGS_INVAL_EXIT_SIGNAL_NEG,
	CLONE3_ARGS_INVAL_EXIT_SIGNAL_CSIG,
	CLONE3_ARGS_INVAL_EXIT_SIGNAL_NSIG,
	CLONE3_ARGS_SHADOW_STACK,
	CLONE3_ARGS_SHADOW_STACK_MISALIGNED,
	CLONE3_ARGS_SHADOW_STACK_NO_TOKEN,
	CLONE3_ARGS_SHADOW_STACK_NORMAL_MEMORY,
};

typedef bool (*filter_function)(void);
typedef size_t (*size_function)(void);

struct test {
	const char *name;
	uint64_t flags;
	size_t size;
	size_function size_function;
	int expected;
	bool e2big_valid;
	enum test_mode test_mode;
	filter_function filter;
};


/*
 * We check for shadow stack support by attempting to use
 * map_shadow_stack() since features may have been locked by the
 * dynamic linker resulting in spurious errors when we attempt to
 * enable on startup.  We warn if the enable failed.
 */
static void test_shadow_stack_supported(void)
{
	long ret;

	ret = syscall(__NR_map_shadow_stack, 0, getpagesize(), 0);
	if (ret == -1) {
		ksft_print_msg("map_shadow_stack() not supported\n");
	} else if ((void *)ret == MAP_FAILED) {
		ksft_print_msg("Failed to map shadow stack\n");
	} else {
		ksft_print_msg("Shadow stack supportd\n");
		shadow_stack_supported = true;

		if (!shadow_stack_enabled)
			ksft_print_msg("Mapped but did not enable shadow stack\n");
	}
}

static void *get_shadow_stack_page(unsigned long flags)
{
	unsigned long long page;

	page = syscall(__NR_map_shadow_stack, 0, getpagesize(), flags);
	if ((void *)page == MAP_FAILED) {
		ksft_print_msg("map_shadow_stack() failed: %d\n", errno);
		return 0;
	}

	return (void *)page;
}

static int call_clone3(uint64_t flags, size_t size, enum test_mode test_mode)
{
	struct __clone_args args = {
		.flags = flags,
		.exit_signal = SIGCHLD,
	};

	struct clone_args_extended {
		struct __clone_args args;
		__aligned_u64 excess_space[2];
	} args_ext;

	pid_t pid = -1;
	void *p;
	int status;

	memset(&args_ext, 0, sizeof(args_ext));
	if (size > sizeof(struct __clone_args))
		args_ext.excess_space[1] = 1;

	if (size == 0)
		size = sizeof(struct __clone_args);

	switch (test_mode) {
	case CLONE3_ARGS_NO_TEST:
		/*
		 * Uses default 'flags' and 'SIGCHLD'
		 * assignment.
		 */
		break;
	case CLONE3_ARGS_ALL_0:
		args.flags = 0;
		args.exit_signal = 0;
		break;
	case CLONE3_ARGS_INVAL_EXIT_SIGNAL_BIG:
		args.exit_signal = 0xbadc0ded00000000ULL;
		break;
	case CLONE3_ARGS_INVAL_EXIT_SIGNAL_NEG:
		args.exit_signal = 0x0000000080000000ULL;
		break;
	case CLONE3_ARGS_INVAL_EXIT_SIGNAL_CSIG:
		args.exit_signal = 0x0000000000000100ULL;
		break;
	case CLONE3_ARGS_INVAL_EXIT_SIGNAL_NSIG:
		args.exit_signal = 0x00000000000000f0ULL;
		break;
	case CLONE3_ARGS_SHADOW_STACK:
		p = get_shadow_stack_page(SHADOW_STACK_SET_TOKEN);
		p += getpagesize() - sizeof(void *);
		args.shstk_token = (unsigned long long)p;
		break;
	case CLONE3_ARGS_SHADOW_STACK_MISALIGNED:
		p = get_shadow_stack_page(SHADOW_STACK_SET_TOKEN);
		p += getpagesize() - sizeof(void *) - 1;
		args.shstk_token = (unsigned long long)p;
		break;
	case CLONE3_ARGS_SHADOW_STACK_NORMAL_MEMORY:
		p = malloc(getpagesize());
		p += getpagesize() - sizeof(void *);
		args.shstk_token = (unsigned long long)p;
		break;
	case CLONE3_ARGS_SHADOW_STACK_NO_TOKEN:
		p = get_shadow_stack_page(0);
		p += getpagesize() - sizeof(void *);
		args.shstk_token = (unsigned long long)p;
		break;
	}

	memcpy(&args_ext.args, &args, sizeof(struct __clone_args));

	pid = sys_clone3((struct __clone_args *)&args_ext, size);
	if (pid < 0) {
		ksft_print_msg("%s - Failed to create new process\n",
				strerror(errno));
		return -errno;
	}

	if (pid == 0) {
		ksft_print_msg("I am the child, my PID is %d\n", getpid());
		/*
		 * Use a raw syscall to ensure we don't get issues
		 * with manually specified shadow stack and exit handlers.
		 */
		syscall(__NR_exit, EXIT_SUCCESS);
		ksft_print_msg("CHILD FAILED TO EXIT PID is %d\n", getpid());
	}

	ksft_print_msg("I am the parent (%d). My child's pid is %d\n",
			getpid(), pid);

	if (waitpid(-1, &status, __WALL) < 0) {
		ksft_print_msg("waitpid() returned %s\n", strerror(errno));
		return -errno;
	}
	if (!WIFEXITED(status)) {
		ksft_print_msg("Child did not exit normally, status 0x%x\n",
			       status);
		return EXIT_FAILURE;
	}
	if (WEXITSTATUS(status))
		return WEXITSTATUS(status);

	return 0;
}

static void test_clone3(const struct test *test)
{
	size_t size;
	int ret;

	if (test->filter && test->filter()) {
		ksft_test_result_skip("%s\n", test->name);
		return;
	}

	if (test->size_function)
		size = test->size_function();
	else
		size = test->size;

	ksft_print_msg("Running test '%s'\n", test->name);

	ksft_print_msg(
		"[%d] Trying clone3() with flags %#" PRIx64 " (size %zu)\n",
		getpid(), test->flags, size);
	ret = call_clone3(test->flags, size, test->test_mode);
	ksft_print_msg("[%d] clone3() with flags says: %d expected %d\n",
			getpid(), ret, test->expected);
	if (ret != test->expected) {
		if (test->e2big_valid && ret == -E2BIG) {
			ksft_print_msg("Test reported -E2BIG\n");
			ksft_test_result_skip("%s\n", test->name);
			return;
		}
		ksft_print_msg(
			"[%d] Result (%d) is different than expected (%d)\n",
			getpid(), ret, test->expected);
		ksft_test_result_fail("%s\n", test->name);
		return;
	}

	ksft_test_result_pass("%s\n", test->name);
}

static bool not_root(void)
{
	if (getuid() != 0) {
		ksft_print_msg("Not running as root\n");
		return true;
	}

	return false;
}

static bool no_timenamespace(void)
{
	if (not_root())
		return true;

	if (!access("/proc/self/ns/time", F_OK))
		return false;

	ksft_print_msg("Time namespaces are not supported\n");
	return true;
}

static bool have_shadow_stack(void)
{
	if (shadow_stack_supported) {
		ksft_print_msg("Shadow stack supported\n");
		return true;
	}

	return false;
}

static bool no_shadow_stack(void)
{
	if (!shadow_stack_supported) {
		ksft_print_msg("Shadow stack not supported\n");
		return true;
	}

	return false;
}

static size_t page_size_plus_8(void)
{
	return getpagesize() + 8;
}

static const struct test tests[] = {
	{
		.name = "simple clone3()",
		.flags = 0,
		.size = 0,
		.expected = 0,
		.test_mode = CLONE3_ARGS_NO_TEST,
	},
	{
		.name = "clone3() in a new PID_NS",
		.flags = CLONE_NEWPID,
		.size = 0,
		.expected = 0,
		.test_mode = CLONE3_ARGS_NO_TEST,
		.filter = not_root,
	},
	{
		.name = "CLONE_ARGS_SIZE_VER0",
		.flags = 0,
		.size = CLONE_ARGS_SIZE_VER0,
		.expected = 0,
		.test_mode = CLONE3_ARGS_NO_TEST,
	},
	{
		.name = "CLONE_ARGS_SIZE_VER0 - 8",
		.flags = 0,
		.size = CLONE_ARGS_SIZE_VER0 - 8,
		.expected = -EINVAL,
		.test_mode = CLONE3_ARGS_NO_TEST,
	},
	{
		.name = "sizeof(struct clone_args) + 8",
		.flags = 0,
		.size = sizeof(struct __clone_args) + 8,
		.expected = 0,
		.test_mode = CLONE3_ARGS_NO_TEST,
	},
	{
		.name = "exit_signal with highest 32 bits non-zero",
		.flags = 0,
		.size = 0,
		.expected = -EINVAL,
		.test_mode = CLONE3_ARGS_INVAL_EXIT_SIGNAL_BIG,
	},
	{
		.name = "negative 32-bit exit_signal",
		.flags = 0,
		.size = 0,
		.expected = -EINVAL,
		.test_mode = CLONE3_ARGS_INVAL_EXIT_SIGNAL_NEG,
	},
	{
		.name = "exit_signal not fitting into CSIGNAL mask",
		.flags = 0,
		.size = 0,
		.expected = -EINVAL,
		.test_mode = CLONE3_ARGS_INVAL_EXIT_SIGNAL_CSIG,
	},
	{
		.name = "NSIG < exit_signal < CSIG",
		.flags = 0,
		.size = 0,
		.expected = -EINVAL,
		.test_mode = CLONE3_ARGS_INVAL_EXIT_SIGNAL_NSIG,
	},
	{
		.name = "Arguments sizeof(struct clone_args) + 8",
		.flags = 0,
		.size = sizeof(struct __clone_args) + 8,
		.expected = 0,
		.test_mode = CLONE3_ARGS_ALL_0,
	},
	{
		.name = "Arguments sizeof(struct clone_args) + 16",
		.flags = 0,
		.size = sizeof(struct __clone_args) + 16,
		.expected = -E2BIG,
		.test_mode = CLONE3_ARGS_ALL_0,
	},
	{
		.name = "Arguments sizeof(struct clone_arg) * 2",
		.flags = 0,
		.size = sizeof(struct __clone_args) + 16,
		.expected = -E2BIG,
		.test_mode = CLONE3_ARGS_ALL_0,
	},
	{
		.name = "Arguments > page size",
		.flags = 0,
		.size_function = page_size_plus_8,
		.expected = -E2BIG,
		.test_mode = CLONE3_ARGS_NO_TEST,
	},
	{
		.name = "CLONE_ARGS_SIZE_VER0 in a new PID NS",
		.flags = CLONE_NEWPID,
		.size = CLONE_ARGS_SIZE_VER0,
		.expected = 0,
		.test_mode = CLONE3_ARGS_NO_TEST,
		.filter = not_root,
	},
	{
		.name = "CLONE_ARGS_SIZE_VER0 - 8 in a new PID NS",
		.flags = CLONE_NEWPID,
		.size = CLONE_ARGS_SIZE_VER0 - 8,
		.expected = -EINVAL,
		.test_mode = CLONE3_ARGS_NO_TEST,
	},
	{
		.name = "sizeof(struct clone_args) + 8 in a new PID NS",
		.flags = CLONE_NEWPID,
		.size = sizeof(struct __clone_args) + 8,
		.expected = 0,
		.test_mode = CLONE3_ARGS_NO_TEST,
		.filter = not_root,
	},
	{
		.name = "Arguments > page size in a new PID NS",
		.flags = CLONE_NEWPID,
		.size_function = page_size_plus_8,
		.expected = -E2BIG,
		.test_mode = CLONE3_ARGS_NO_TEST,
	},
	{
		.name = "New time NS",
		.flags = CLONE_NEWTIME,
		.size = 0,
		.expected = 0,
		.test_mode = CLONE3_ARGS_NO_TEST,
		.filter = no_timenamespace,
	},
	{
		.name = "exit signal (SIGCHLD) in flags",
		.flags = SIGCHLD,
		.size = 0,
		.expected = -EINVAL,
		.test_mode = CLONE3_ARGS_NO_TEST,
	},
	{
		.name = "Shadow stack on system with shadow stack",
		.size = 0,
		.expected = 0,
		.e2big_valid = true,
		.test_mode = CLONE3_ARGS_SHADOW_STACK,
		.filter = no_shadow_stack,
	},
	{
		.name = "Shadow stack with misaligned address",
		.flags = CLONE_VM,
		.size = 0,
		.expected = -EINVAL,
		.e2big_valid = true,
		.test_mode = CLONE3_ARGS_SHADOW_STACK_MISALIGNED,
		.filter = no_shadow_stack,
	},
	{
		.name = "Shadow stack with normal memory",
		.flags = CLONE_VM,
		.size = 0,
		.expected = -EFAULT,
		.e2big_valid = true,
		.test_mode = CLONE3_ARGS_SHADOW_STACK_NORMAL_MEMORY,
		.filter = no_shadow_stack,
	},
	{
		.name = "Shadow stack with no token",
		.flags = CLONE_VM,
		.size = 0,
		.expected = -EINVAL,
		.e2big_valid = true,
		.test_mode = CLONE3_ARGS_SHADOW_STACK_NO_TOKEN,
		.filter = no_shadow_stack,
	},
	{
		.name = "Shadow stack on system without shadow stack",
		.flags = CLONE_VM,
		.size = 0,
		.expected = -EFAULT,
		.e2big_valid = true,
		.test_mode = CLONE3_ARGS_SHADOW_STACK_NORMAL_MEMORY,
		.filter = have_shadow_stack,
	},
};

int main(int argc, char *argv[])
{
	size_t size;
	int i;

	enable_shadow_stack();

	ksft_print_header();
	ksft_set_plan(ARRAY_SIZE(tests));
	test_clone3_supported();
	test_shadow_stack_supported();

	for (i = 0; i < ARRAY_SIZE(tests); i++)
		test_clone3(&tests[i]);

	ksft_finished();
}
