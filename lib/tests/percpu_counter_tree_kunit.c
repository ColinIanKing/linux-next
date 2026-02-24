// SPDX-License-Identifier: GPL-2.0+ OR MIT
// SPDX-FileCopyrightText: 2026 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

#include <kunit/test.h>
#include <linux/percpu_counter_tree.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/random.h>

struct multi_thread_test_data {
	long increment;
	int nr_inc;
	int counter_index;
};

/* Hierarchical per-CPU counter instances. */
static struct percpu_counter_tree counter[2];
static struct percpu_counter_tree_level_item *items[2];

/* Global atomic counters for validation. */
static atomic_long_t global_counter[2];

static struct wait_queue_head kernel_threads_wq;
static atomic_t kernel_threads_to_run;

static void complete_work(void)
{
	if (atomic_dec_and_test(&kernel_threads_to_run))
		wake_up(&kernel_threads_wq);
}

static void hpcc_print_info(struct kunit *test)
{
	kunit_info(test, "Running test with %d CPUs\n", num_online_cpus());
}

static void add_to_counter(int counter_index, unsigned int nr_inc, long increment)
{
	unsigned int i;

	for (i = 0; i < nr_inc; i++) {
		percpu_counter_tree_add(&counter[counter_index], increment);
		atomic_long_add(increment, &global_counter[counter_index]);
	}
}

static void check_counters(struct kunit *test)
{
	int counter_index;

	/* Compare each counter with its global counter. */
	for (counter_index = 0; counter_index < 2; counter_index++) {
		long v = atomic_long_read(&global_counter[counter_index]);
		long approx_sum = percpu_counter_tree_approximate_sum(&counter[counter_index]);
		unsigned long under_accuracy = 0, over_accuracy = 0;
		long precise_min, precise_max;

		/* Precise comparison. */
		KUNIT_EXPECT_EQ(test, percpu_counter_tree_precise_sum(&counter[counter_index]), v);
		KUNIT_EXPECT_EQ(test, 0, percpu_counter_tree_precise_compare_value(&counter[counter_index], v));

		/* Approximate comparison. */
		KUNIT_EXPECT_EQ(test, 0, percpu_counter_tree_approximate_compare_value(&counter[counter_index], v));

		/* Accuracy limits checks. */
		percpu_counter_tree_approximate_accuracy_range(&counter[counter_index], &under_accuracy, &over_accuracy);

		KUNIT_EXPECT_GE(test, (long)(approx_sum - (v - under_accuracy)), 0);
		KUNIT_EXPECT_LE(test, (long)(approx_sum - (v + over_accuracy)), 0);
		KUNIT_EXPECT_GT(test, (long)(approx_sum - (v - under_accuracy - 1)), 0);
		KUNIT_EXPECT_LT(test, (long)(approx_sum - (v + over_accuracy + 1)), 0);

		/* Precise min/max range check. */
		percpu_counter_tree_approximate_min_max_range(approx_sum, under_accuracy, over_accuracy, &precise_min, &precise_max);

		KUNIT_EXPECT_GE(test, v - precise_min, 0);
		KUNIT_EXPECT_LE(test, v - precise_max, 0);
		KUNIT_EXPECT_GT(test, v - (precise_min - 1), 0);
		KUNIT_EXPECT_LT(test, v - (precise_max + 1), 0);
	}
	/* Compare each counter with the second counter. */
	KUNIT_EXPECT_EQ(test, percpu_counter_tree_precise_sum(&counter[0]), percpu_counter_tree_precise_sum(&counter[1]));
	KUNIT_EXPECT_EQ(test, 0, percpu_counter_tree_precise_compare(&counter[0], &counter[1]));
	KUNIT_EXPECT_EQ(test, 0, percpu_counter_tree_approximate_compare(&counter[0], &counter[1]));
}

static int multi_thread_worker_fn(void *data)
{
	struct multi_thread_test_data *td = data;

	add_to_counter(td->counter_index, td->nr_inc, td->increment);
	complete_work();
	kfree(td);
	return 0;
}

static void test_run_on_specific_cpu(struct kunit *test, int target_cpu, int counter_index, unsigned int nr_inc, long increment)
{
	struct task_struct *task;
	struct multi_thread_test_data *td = kzalloc(sizeof(struct multi_thread_test_data), GFP_KERNEL);

	KUNIT_EXPECT_PTR_NE(test, td, NULL);
	td->increment = increment;
	td->nr_inc = nr_inc;
	td->counter_index = counter_index;
	atomic_inc(&kernel_threads_to_run);
	task = kthread_run_on_cpu(multi_thread_worker_fn, td, target_cpu, "kunit_multi_thread_worker");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, task);
}

static void init_kthreads(void)
{
	atomic_set(&kernel_threads_to_run, 1);
	init_waitqueue_head(&kernel_threads_wq);
}

static void fini_kthreads(void)
{
	/* Release our own reference. */
	complete_work();
	/* Wait for all others threads to run. */
	__wait_event(kernel_threads_wq, (atomic_read(&kernel_threads_to_run) == 0));
}

static void test_sync_kthreads(void)
{
	fini_kthreads();
	init_kthreads();
}

static void init_counters(struct kunit *test, unsigned long batch_size)
{
	int i, ret;

	for (i = 0; i < 2; i++) {
		items[i] = kzalloc(percpu_counter_tree_items_size(), GFP_KERNEL);
		KUNIT_EXPECT_PTR_NE(test, items[i], NULL);
		ret = percpu_counter_tree_init(&counter[i], items[i], batch_size, GFP_KERNEL);
		KUNIT_EXPECT_EQ(test, ret, 0);

		atomic_long_set(&global_counter[i], 0);
	}
}

static void fini_counters(void)
{
	int i;

	for (i = 0; i < 2; i++) {
		percpu_counter_tree_destroy(&counter[i]);
		kfree(items[i]);
	}
}

enum up_test_inc_type {
	INC_ONE,
	INC_MINUS_ONE,
	INC_RANDOM,
};

/*
 * Single-threaded tests. Those use many threads to run on various CPUs,
 * but synchronize for completion of each thread before running the
 * next, effectively making sure there are no concurrent updates.
 */
static void do_hpcc_test_single_thread(struct kunit *test, int _cpu0, int _cpu1, enum up_test_inc_type type)
{
	unsigned long batch_size_order = 5;
	int cpu0 = _cpu0;
	int cpu1 = _cpu1;
	int i;

	init_counters(test, 1UL << batch_size_order);
	init_kthreads();
	for (i = 0; i < 10000; i++) {
		long increment;

		switch (type) {
		case INC_ONE:
			increment = 1;
			break;
		case INC_MINUS_ONE:
			increment = -1;
			break;
		case INC_RANDOM:
			increment = (long) get_random_long() % 50000;
			break;
		}
		if (_cpu0 < 0)
			cpu0 = cpumask_any_distribute(cpu_online_mask);
		if (_cpu1 < 0)
			cpu1 = cpumask_any_distribute(cpu_online_mask);
		test_run_on_specific_cpu(test, cpu0, 0, 1, increment);
		test_sync_kthreads();
		test_run_on_specific_cpu(test, cpu1, 1, 1, increment);
		test_sync_kthreads();
		check_counters(test);
	}
	fini_kthreads();
	fini_counters();
}

static void hpcc_test_single_thread_first(struct kunit *test)
{
	int cpu = cpumask_first(cpu_online_mask);

	do_hpcc_test_single_thread(test, cpu, cpu, INC_ONE);
	do_hpcc_test_single_thread(test, cpu, cpu, INC_MINUS_ONE);
	do_hpcc_test_single_thread(test, cpu, cpu, INC_RANDOM);
}

static void hpcc_test_single_thread_first_random(struct kunit *test)
{
	int cpu = cpumask_first(cpu_online_mask);

	do_hpcc_test_single_thread(test, cpu, -1, INC_ONE);
	do_hpcc_test_single_thread(test, cpu, -1, INC_MINUS_ONE);
	do_hpcc_test_single_thread(test, cpu, -1, INC_RANDOM);
}

static void hpcc_test_single_thread_random(struct kunit *test)
{
	do_hpcc_test_single_thread(test, -1, -1, INC_ONE);
	do_hpcc_test_single_thread(test, -1, -1, INC_MINUS_ONE);
	do_hpcc_test_single_thread(test, -1, -1, INC_RANDOM);
}

/* Multi-threaded SMP tests. */

static void do_hpcc_multi_thread_increment_each_cpu(struct kunit *test, unsigned long batch_size, unsigned int nr_inc, long increment)
{
	int cpu;

	init_counters(test, batch_size);
	init_kthreads();
	for_each_online_cpu(cpu) {
		test_run_on_specific_cpu(test, cpu, 0, nr_inc, increment);
		test_run_on_specific_cpu(test, cpu, 1, nr_inc, increment);
	}
	fini_kthreads();
	check_counters(test);
	fini_counters();
}

static void do_hpcc_multi_thread_increment_even_cpus(struct kunit *test, unsigned long batch_size, unsigned int nr_inc, long increment)
{
	int cpu;

	init_counters(test, batch_size);
	init_kthreads();
	for_each_online_cpu(cpu) {
		test_run_on_specific_cpu(test, cpu, 0, nr_inc, increment);
		test_run_on_specific_cpu(test, cpu & ~1, 1, nr_inc, increment); /* even cpus. */
	}
	fini_kthreads();
	check_counters(test);
	fini_counters();
}

static void do_hpcc_multi_thread_increment_single_cpu(struct kunit *test, unsigned long batch_size, unsigned int nr_inc, long increment)
{
	int cpu;

	init_counters(test, batch_size);
	init_kthreads();
	for_each_online_cpu(cpu) {
		test_run_on_specific_cpu(test, cpu, 0, nr_inc, increment);
		test_run_on_specific_cpu(test, cpumask_first(cpu_online_mask), 1, nr_inc, increment);
	}
	fini_kthreads();
	check_counters(test);
	fini_counters();
}

static void do_hpcc_multi_thread_increment_random_cpu(struct kunit *test, unsigned long batch_size, unsigned int nr_inc, long increment)
{
	int cpu;

	init_counters(test, batch_size);
	init_kthreads();
	for_each_online_cpu(cpu) {
		test_run_on_specific_cpu(test, cpu, 0, nr_inc, increment);
		test_run_on_specific_cpu(test, cpumask_any_distribute(cpu_online_mask), 1, nr_inc, increment);
	}
	fini_kthreads();
	check_counters(test);
	fini_counters();
}

static void hpcc_test_multi_thread_batch_increment(struct kunit *test)
{
	unsigned long batch_size_order;

	for (batch_size_order = 2; batch_size_order < 10; batch_size_order++) {
		unsigned int nr_inc;

		for (nr_inc = 1; nr_inc < 1024; nr_inc *= 2) {
			long increment;

			for (increment = 1; increment < 100000; increment *= 10) {
				do_hpcc_multi_thread_increment_each_cpu(test, 1UL << batch_size_order, nr_inc, increment);
				do_hpcc_multi_thread_increment_even_cpus(test, 1UL << batch_size_order, nr_inc, increment);
				do_hpcc_multi_thread_increment_single_cpu(test, 1UL << batch_size_order, nr_inc, increment);
				do_hpcc_multi_thread_increment_random_cpu(test, 1UL << batch_size_order, nr_inc, increment);
			}
		}
	}
}

static void hpcc_test_multi_thread_random_walk(struct kunit *test)
{
	unsigned long batch_size_order = 5;
	int loop;

	for (loop = 0; loop < 100; loop++) {
		int i;

		init_counters(test, 1UL << batch_size_order);
		init_kthreads();
		for (i = 0; i < 1000; i++) {
			long increment = (long) get_random_long() % 512;
			unsigned int nr_inc = ((unsigned long) get_random_long()) % 1024;

			test_run_on_specific_cpu(test, cpumask_any_distribute(cpu_online_mask), 0, nr_inc, increment);
			test_run_on_specific_cpu(test, cpumask_any_distribute(cpu_online_mask), 1, nr_inc, increment);
		}
		fini_kthreads();
		check_counters(test);
		fini_counters();
	}
}

static struct kunit_case hpcc_test_cases[] = {
	KUNIT_CASE(hpcc_print_info),
	KUNIT_CASE(hpcc_test_single_thread_first),
	KUNIT_CASE(hpcc_test_single_thread_first_random),
	KUNIT_CASE(hpcc_test_single_thread_random),
	KUNIT_CASE(hpcc_test_multi_thread_batch_increment),
	KUNIT_CASE(hpcc_test_multi_thread_random_walk),
	{}
};

static struct kunit_suite hpcc_test_suite = {
	.name = "percpu_counter_tree",
	.test_cases = hpcc_test_cases,
};

kunit_test_suite(hpcc_test_suite);

MODULE_DESCRIPTION("Test cases for hierarchical per-CPU counters");
MODULE_LICENSE("Dual MIT/GPL");
