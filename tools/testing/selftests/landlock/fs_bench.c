// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock filesystem benchmark
 */

#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>

void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s [OPTIONS]\n", argv0);
	printf("\n");
	printf("  Benchmark expensive Landlock checks for D nested dirs\n");
	printf("\n");
	printf("Options:\n");
	printf("  -h	help\n");
	printf("  -L	disable Landlock (as a baseline)\n");
	printf("  -d D	set directory depth to D\n");
	printf("  -n N	set number of benchmark iterations to N\n");
}

/*
 * Build a deep directory, enforce Landlock and return the FD to the
 * deepest dir.  On any failure, exit the process with an error.
 */
int build_directory(size_t depth, bool use_landlock)
{
	const char *path = "d"; /* directory name */
	int abi, ruleset_fd, current, previous;

	if (use_landlock) {
		abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
			      LANDLOCK_CREATE_RULESET_VERSION);
		if (abi < 7)
			err(1, "Landlock ABI too low: got %d, wanted 7+", abi);
	}

	ruleset_fd = -1;
	if (use_landlock) {
		struct landlock_ruleset_attr attr = {
			.handled_access_fs =
				0xffff, /* All FS access rights as of 2026-01 */
		};
		ruleset_fd = syscall(SYS_landlock_create_ruleset, &attr,
				     sizeof(attr), 0U);
		if (ruleset_fd < 0)
			err(1, "landlock_create_ruleset");
	}

	current = open(".", O_PATH);
	if (current < 0)
		err(1, "open(.)");

	while (depth--) {
		if (use_landlock) {
			struct landlock_path_beneath_attr attr = {
				.allowed_access = LANDLOCK_ACCESS_FS_IOCTL_DEV,
				.parent_fd = current,
			};
			if (syscall(SYS_landlock_add_rule, ruleset_fd,
				    LANDLOCK_RULE_PATH_BENEATH, &attr, 0) < 0)
				err(1, "landlock_add_rule");
		}

		if (mkdirat(current, path, 0700) < 0)
			err(1, "mkdirat(%s)", path);

		previous = current;
		current = openat(current, path, O_PATH);
		if (current < 0)
			err(1, "open(%s)", path);

		close(previous);
	}

	if (use_landlock) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
			err(1, "prctl");

		if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0)
			err(1, "landlock_restrict_self");
	}

	close(ruleset_fd);
	return current;
}

int main(int argc, char *argv[])
{
	bool use_landlock = true;
	size_t num_iterations = 100000;
	size_t num_subdirs = 10000;
	int c, current, fd;
	struct tms start_time, end_time;

	setbuf(stdout, NULL);
	while ((c = getopt(argc, argv, "hLd:n:")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;
		case 'L':
			use_landlock = false;
			break;
		case 'd':
			num_subdirs = atoi(optarg);
			break;
		case 'n':
			num_iterations = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	printf("*** Benchmark ***\n");
	printf("%zu dirs, %zu iterations, %s landlock\n", num_subdirs,
	       num_iterations, use_landlock ? "with" : "without");

	if (times(&start_time) == -1)
		err(1, "times");

	current = build_directory(num_subdirs, use_landlock);

	for (int i = 0; i < num_iterations; i++) {
		fd = openat(current, ".", O_DIRECTORY);
		if (fd != -1) {
			if (use_landlock)
				errx(1, "openat succeeded, expected error");

			close(fd);
		}
	}

	if (times(&end_time) == -1)
		err(1, "times");

	printf("*** Benchmark concluded ***\n");
	printf("System: %ld clocks\n",
	       end_time.tms_stime - start_time.tms_stime);
	printf("User  : %ld clocks\n",
	       end_time.tms_utime - start_time.tms_utime);
	printf("Clocks per second: %ld\n", CLOCKS_PER_SEC);

	close(current);
}
