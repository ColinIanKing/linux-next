// SPDX-License-Identifier: GPL-2.0-or-later

#define _GNU_SOURCE
#include "../kselftest_harness.h"
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sched.h>
#include <sys/pidfd.h>
#include "vm_util.h"

#include "../pidfd/pidfd.h"

FIXTURE(process_madvise)
{
	int pidfd;
	int flag;
};

FIXTURE_SETUP(process_madvise)
{
	self->pidfd = PIDFD_SELF;
	self->flag = 0;
	setup_sighandler();
};

FIXTURE_TEARDOWN(process_madvise)
{
	teardown_sighandler();
}

static ssize_t sys_process_madvise(int pidfd, const struct iovec *iovec,
				   size_t vlen, int advice, unsigned int flags)
{
	return syscall(__NR_process_madvise, pidfd, iovec, vlen, advice, flags);
}

/*
 * Enable our signal catcher and try to read the specified buffer. The
 * return value indicates whether the read succeeds without a fatal
 * signal.
 */
static bool try_read_buf(char *ptr)
{
	bool failed;

	/* Tell signal handler to jump back here on fatal signal. */
	signal_jump_set = true;
	/* If a fatal signal arose, we will jump back here and failed is set. */
	failed = sigsetjmp(signal_jmp_buf, 0) != 0;

	if (!failed)
		FORCE_READ(ptr);

	signal_jump_set = false;
	return !failed;
}

TEST_F(process_madvise, basic)
{
	const unsigned long pagesize = (unsigned long)sysconf(_SC_PAGESIZE);
	const int madvise_pages = 4;
	char *map;
	ssize_t ret;
	struct iovec vec[madvise_pages];

	/*
	 * Create a single large mapping. We will pick pages from this
	 * mapping to advise on. This ensures we test non-contiguous iovecs.
	 */
	map = mmap(NULL, pagesize * 10, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map == MAP_FAILED)
		ksft_exit_skip("mmap failed, not enough memory.\n");

	/* Fill the entire region with a known pattern. */
	memset(map, 'A', pagesize * 10);

	/*
	 * Setup the iovec to point to 4 non-contiguous pages
	 * within the mapping.
	 */
	vec[0].iov_base = &map[0 * pagesize];
	vec[0].iov_len = pagesize;
	vec[1].iov_base = &map[3 * pagesize];
	vec[1].iov_len = pagesize;
	vec[2].iov_base = &map[5 * pagesize];
	vec[2].iov_len = pagesize;
	vec[3].iov_base = &map[8 * pagesize];
	vec[3].iov_len = pagesize;

	ret = sys_process_madvise(PIDFD_SELF, vec, madvise_pages, MADV_DONTNEED,
				  0);
	if (ret == -1 && errno == EPERM)
		ksft_exit_skip(
			"process_madvise() unsupported or permission denied, try running as root.\n");
	else if (errno == EINVAL)
		ksft_exit_skip(
			"process_madvise() unsupported or parameter invalid, please check arguments.\n");

	/* The call should succeed and report the total bytes processed. */
	ASSERT_EQ(ret, madvise_pages * pagesize);

	/* Check that advised pages are now zero. */
	for (int i = 0; i < madvise_pages; i++) {
		char *advised_page = (char *)vec[i].iov_base;

		/* Access should be successful (kernel provides a new page). */
		ASSERT_TRUE(try_read_buf(advised_page));
		/* Content must be 0, not 'A'. */
		ASSERT_EQ(*advised_page, 0);
	}

	/* Check that an un-advised page in between is still 'A'. */
	char *unadvised_page = &map[1 * pagesize];

	ASSERT_TRUE(try_read_buf(unadvised_page));
	for (int i = 0; i < pagesize; i++)
		ASSERT_EQ(unadvised_page[i], 'A');

	/* Cleanup. */
	ASSERT_EQ(munmap(map, pagesize * 10), 0);
}

static long get_smaps_anon_huge_pages(pid_t pid, void *addr)
{
	char smaps_path[64];
	char *line = NULL;
	unsigned long start, end;
	long anon_huge_kb;
	size_t len;
	FILE *f;
	bool in_vma;

	in_vma = false;
	snprintf(smaps_path, sizeof(smaps_path), "/proc/%d/smaps", pid);
	f = fopen(smaps_path, "r");
	if (!f)
		return -1;

	while (getline(&line, &len, f) != -1) {
		/* Check if the line describes a VMA range */
		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			if ((unsigned long)addr >= start &&
			    (unsigned long)addr < end)
				in_vma = true;
			else
				in_vma = false;
			continue;
		}

		/* If we are in the correct VMA, look for the AnonHugePages field */
		if (in_vma &&
		    sscanf(line, "AnonHugePages: %ld kB", &anon_huge_kb) == 1)
			break;
	}

	free(line);
	fclose(f);

	return (anon_huge_kb > 0) ? (anon_huge_kb * 1024) : 0;
}

/**
 * TEST_F(process_madvise, remote_collapse)
 *
 * This test deterministically validates process_madvise() with MADV_COLLAPSE
 * on a remote process, other advices are difficult to verify reliably.
 *
 * The test verifies that a memory region in a child process, initially
 * backed by small pages, can be collapsed into a Transparent Huge Page by a
 * request from the parent. The result is verified by parsing the child's
 * /proc/<pid>/smaps file.
 */
TEST_F(process_madvise, remote_collapse)
{
	const unsigned long pagesize = (unsigned long)sysconf(_SC_PAGESIZE);
	pid_t child_pid;
	int pidfd;
	long huge_page_size;
	int pipe_info[2];
	ssize_t ret;
	struct iovec vec;

	struct child_info {
		pid_t pid;
		void *map_addr;
	} info;

	huge_page_size = default_huge_page_size();
	if (huge_page_size <= 0)
		ksft_exit_skip("Could not determine a valid huge page size.\n");

	ASSERT_EQ(pipe(pipe_info), 0);

	child_pid = fork();
	ASSERT_NE(child_pid, -1);

	if (child_pid == 0) {
		char *map;
		size_t map_size = 2 * huge_page_size;

		close(pipe_info[0]);

		map = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		ASSERT_NE(map, MAP_FAILED);

		/* Fault in as small pages */
		for (size_t i = 0; i < map_size; i += pagesize)
			map[i] = 'A';

		/* Send info and pause */
		info.pid = getpid();
		info.map_addr = map;
		ret = write(pipe_info[1], &info, sizeof(info));
		ASSERT_EQ(ret, sizeof(info));
		close(pipe_info[1]);

		pause();
		exit(0);
	}

	close(pipe_info[1]);

	/* Receive child info */
	ret = read(pipe_info[0], &info, sizeof(info));
	if (ret <= 0) {
		waitpid(child_pid, NULL, 0);
		ksft_exit_skip("Failed to read child info from pipe.\n");
	}
	ASSERT_EQ(ret, sizeof(info));
	close(pipe_info[0]);
	child_pid = info.pid;

	pidfd = pidfd_open(child_pid, 0);
	ASSERT_GE(pidfd, 0);

	/* Baseline Check from Parent's perspective */
	ASSERT_EQ(get_smaps_anon_huge_pages(child_pid, info.map_addr), 0);

	vec.iov_base = info.map_addr;
	vec.iov_len = huge_page_size;
	ret = sys_process_madvise(pidfd, &vec, 1, MADV_COLLAPSE, 0);
	if (ret == -1) {
		if (errno == EINVAL)
			ksft_exit_skip(
				"PROCESS_MADV_ADVISE is not supported.\n");
		else if (errno == EPERM)
			ksft_exit_skip(
				"No process_madvise() permissions, try running as root.\n");
		goto cleanup;
	}
	ASSERT_EQ(ret, huge_page_size);

	ASSERT_EQ(get_smaps_anon_huge_pages(child_pid, info.map_addr),
		  huge_page_size);

	ksft_test_result_pass(
		"MADV_COLLAPSE successfully verified via smaps.\n");

cleanup:
	/* Cleanup */
	kill(child_pid, SIGKILL);
	waitpid(child_pid, NULL, 0);
	if (pidfd >= 0)
		close(pidfd);
}

/*
 * Test process_madvise() with various invalid pidfds to ensure correct error
 * handling. This includes negative fds, non-pidfd fds, and pidfds for
 * processes that no longer exist.
 */
TEST_F(process_madvise, invalid_pidfd)
{
	struct iovec vec;
	pid_t child_pid;
	ssize_t ret;
	int pidfd;

	vec.iov_base = (void *)0x1234;
	vec.iov_len = 4096;

	/* Using an invalid fd number (-1) should fail with EBADF. */
	ret = sys_process_madvise(-1, &vec, 1, MADV_DONTNEED, 0);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, EBADF);

	/*
	 * Using a valid fd that is not a pidfd (e.g. stdin) should fail
	 * with EBADF.
	 */
	ret = sys_process_madvise(STDIN_FILENO, &vec, 1, MADV_DONTNEED, 0);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, EBADF);

	/*
	 * Using a pidfd for a process that has already exited should fail
	 * with ESRCH.
	 */
	child_pid = fork();
	ASSERT_NE(child_pid, -1);

	if (child_pid == 0)
		exit(0);

	pidfd = pidfd_open(child_pid, 0);
	ASSERT_GE(pidfd, 0);

	/* Wait for the child to ensure it has terminated. */
	waitpid(child_pid, NULL, 0);

	ret = sys_process_madvise(pidfd, &vec, 1, MADV_DONTNEED, 0);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ESRCH);
	close(pidfd);
}

/*
 * Test process_madvise() with an invalid flag value. Now we only support flag=0
 * future we will use it support sync so reserve this test.
 */
TEST_F(process_madvise, flag)
{
	const unsigned long pagesize = (unsigned long)sysconf(_SC_PAGESIZE);
	unsigned int invalid_flag;
	struct iovec vec;
	char *map;
	ssize_t ret;

	map = mmap(NULL, pagesize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1,
		   0);
	if (map == MAP_FAILED)
		ksft_exit_skip("mmap failed, not enough memory.\n");

	vec.iov_base = map;
	vec.iov_len = pagesize;

	invalid_flag = 0x80000000;

	ret = sys_process_madvise(PIDFD_SELF, &vec, 1, MADV_DONTNEED,
				  invalid_flag);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, EINVAL);

	/* Cleanup. */
	ASSERT_EQ(munmap(map, pagesize), 0);
}

TEST_HARNESS_MAIN
