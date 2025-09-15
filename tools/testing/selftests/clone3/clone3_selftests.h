/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _CLONE3_SELFTESTS_H
#define _CLONE3_SELFTESTS_H

#define _GNU_SOURCE
#include <sched.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <stdint.h>
#include <syscall.h>
#include <sys/wait.h>

#include "../kselftest.h"

#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

struct __clone_args {
	__aligned_u64 flags;
	__aligned_u64 pidfd;
	__aligned_u64 child_tid;
	__aligned_u64 parent_tid;
	__aligned_u64 exit_signal;
	__aligned_u64 stack;
	__aligned_u64 stack_size;
	__aligned_u64 tls;
	__aligned_u64 set_tid;
	__aligned_u64 set_tid_size;
	__aligned_u64 cgroup;
#ifndef CLONE_ARGS_SIZE_VER2
#define CLONE_ARGS_SIZE_VER2 88	/* sizeof third published struct */
#endif
	__aligned_u64 shstk_token;
#ifndef CLONE_ARGS_SIZE_VER3
#define CLONE_ARGS_SIZE_VER3 96 /* sizeof fourth published struct */
#endif
};

/*
 * For architectures with shadow stack support we need to be
 * absolutely sure that the clone3() syscall will be inline and not a
 * function call so we open code.
 */
#ifdef __x86_64__
static __always_inline pid_t sys_clone3(struct __clone_args *args, size_t size)
{
	register long _num  __asm__ ("rax") = __NR_clone3;
	register long _args __asm__ ("rdi") = (long)(args);
	register long _size __asm__ ("rsi") = (long)(size);
	long ret;

	__asm__ volatile (
		"syscall\n"
		: "=a"(ret)
		: "r"(_args), "r"(_size),
		  "0"(_num)
		: "rcx", "r11", "memory", "cc"
	);

	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	return ret;
}
#elif defined(__aarch64__)
static __always_inline pid_t sys_clone3(struct __clone_args *args, size_t size)
{
	register long _num  __asm__ ("x8") = __NR_clone3;
	register long _args __asm__ ("x0") = (long)(args);
	register long _size __asm__ ("x1") = (long)(size);
	register long arg2 __asm__ ("x2") = 0;
	register long arg3 __asm__ ("x3") = 0;
	register long arg4 __asm__ ("x4") = 0;

	__asm__ volatile (
		"svc #0\n"
		: "=r"(_args)
		: "r"(_args), "r"(_size),
		  "r"(_num), "r"(arg2),
		  "r"(arg3), "r"(arg4)
		: "memory", "cc"
	);

	if ((int)_args < 0) {
		errno = -((int)_args);
		return -1;
	}

	return _args;
}
#else
static pid_t sys_clone3(struct __clone_args *args, size_t size)
{
	return syscall(__NR_clone3, args, size);
}
#endif

static inline void test_clone3_supported(void)
{
	pid_t pid;
	struct __clone_args args = {};

	if (__NR_clone3 < 0)
		ksft_exit_skip("clone3() syscall is not supported\n");

	/* Set to something that will always cause EINVAL. */
	args.exit_signal = -1;
	pid = sys_clone3(&args, sizeof(args));
	if (!pid)
		exit(EXIT_SUCCESS);

	if (pid > 0) {
		wait(NULL);
		ksft_exit_fail_msg(
			"Managed to create child process with invalid exit_signal\n");
	}

	if (errno == ENOSYS)
		ksft_exit_skip("clone3() syscall is not supported\n");

	ksft_print_msg("clone3() syscall supported\n");
}

#endif /* _CLONE3_SELFTESTS_H */
