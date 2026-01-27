// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright Collabora Ltd., 2021
 *
 * futex cmp requeue test by André Almeida <andrealmeid@collabora.com>
 */

#include <pthread.h>
#include <limits.h>
#include <stdatomic.h>

#include "futextest.h"
#include "kselftest_harness.h"

#define timeout_s  3 /* 3s */
#define WAKE_WAIT_US (10000 * 100) /* 1s */

volatile futex_t *f1;
static pthread_barrier_t barrier;

void *waiterfn(void *arg)
{
	struct timespec to;
	atomic_int *tid = (atomic_int *)arg;

	to.tv_sec = timeout_s;
	to.tv_nsec = 0;

	atomic_store(tid, gettid());
	pthread_barrier_wait(&barrier);

	if (futex_wait(f1, *f1, &to, 0))
		printf("waiter failed errno %d\n", errno);

	return NULL;
}

static int get_thread_state(pid_t pid)
{
	FILE *fp;
	char buf[80], tag[80];
	char val = 0;

	snprintf(buf, sizeof(buf), "/proc/%d/status", pid);
	fp = fopen(buf, "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp))
		if (sscanf(buf, "%s %c", tag, &val) == 2 && !strcmp(tag, "State:")) {
			fclose(fp);
			return val;
		}

	fclose(fp);
	return -1;
}

TEST(requeue_single)
{
	volatile futex_t _f1 = 0;
	volatile futex_t f2 = 0;
	pthread_t waiter[10];
	atomic_int tid = 0;
	int res, state, retry = 100;

	f1 = &_f1;
	pthread_barrier_init(&barrier, NULL, 2);

	/*
	 * Requeue a waiter from f1 to f2, and wake f2.
	 */
	if (pthread_create(&waiter[0], NULL, waiterfn, &tid))
		ksft_exit_fail_msg("pthread_create failed\n");

	pthread_barrier_wait(&barrier);
	pthread_barrier_destroy(&barrier);
	while ((state = get_thread_state(atomic_load(&tid))) != 'S') {
		usleep(WAKE_WAIT_US / 100);

		if (state < 0 || retry-- <= 0)
			break;
	}

	ksft_print_dbg_msg("Requeuing 1 futex from f1 to f2\n");
	res = futex_cmp_requeue(f1, 0, &f2, 0, 1, 0);
	if (res != 1)
		ksft_test_result_fail("futex_requeue simple returned: %d %s\n",
				      res ? errno : res,
				      res ? strerror(errno) : "");

	ksft_print_dbg_msg("Waking 1 futex at f2\n");
	res = futex_wake(&f2, 1, 0);
	if (res != 1) {
		ksft_test_result_fail("futex_requeue simple returned: %d %s\n",
				      res ? errno : res,
				      res ? strerror(errno) : "");
	} else {
		ksft_test_result_pass("futex_requeue simple succeeds\n");
	}
}

TEST(requeue_multiple)
{
	volatile futex_t _f1 = 0;
	volatile futex_t f2 = 0;
	pthread_t waiter[10];
	atomic_int tids[10] = {0};
	int res, i, state, retry = 0;

	f1 = &_f1;

	/*
	 * Create 10 waiters at f1. At futex_requeue, wake 3 and requeue 7.
	 * At futex_wake, wake INT_MAX (should be exactly 7).
	 */
	for (i = 0; i < 10; i++) {
		pthread_barrier_init(&barrier, NULL, 2);

		if (pthread_create(&waiter[i], NULL, waiterfn, &tids[i]))
			ksft_exit_fail_msg("pthread_create failed\n");

		pthread_barrier_wait(&barrier);
		pthread_barrier_destroy(&barrier);

		retry += 10;
		while ((state = get_thread_state(atomic_load(&tids[i]))) != 'S') {
			usleep(WAKE_WAIT_US / 100);

			if (state < 0 || retry-- <= 0)
				break;
		}
	}

	ksft_print_dbg_msg("Waking 3 futexes at f1 and requeuing 7 futexes from f1 to f2\n");
	res = futex_cmp_requeue(f1, 0, &f2, 3, 7, 0);
	if (res != 10) {
		ksft_test_result_fail("futex_requeue many returned: %d %s\n",
				      res ? errno : res,
				      res ? strerror(errno) : "");
	}

	ksft_print_dbg_msg("Waking INT_MAX futexes at f2\n");
	res = futex_wake(&f2, INT_MAX, 0);
	if (res != 7) {
		ksft_test_result_fail("futex_requeue many returned: %d %s\n",
				      res ? errno : res,
				      res ? strerror(errno) : "");
	} else {
		ksft_test_result_pass("futex_requeue many succeeds\n");
	}
}

TEST_HARNESS_MAIN
