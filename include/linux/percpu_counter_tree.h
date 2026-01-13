/* SPDX-License-Identifier: GPL-2.0+ OR MIT */
/* SPDX-FileCopyrightText: 2025 Mathieu Desnoyers <mathieu.desnoyers@efficios.com> */

#ifndef _PERCPU_COUNTER_TREE_H
#define _PERCPU_COUNTER_TREE_H

#include <linux/preempt.h>
#include <linux/atomic.h>
#include <linux/percpu.h>

#ifdef CONFIG_SMP

#if NR_CPUS == (1U << 0)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	0
#elif NR_CPUS <= (1U << 1)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	1
#elif NR_CPUS <= (1U << 2)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	3
#elif NR_CPUS <= (1U << 3)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	7
#elif NR_CPUS <= (1U << 4)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	7
#elif NR_CPUS <= (1U << 5)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	11
#elif NR_CPUS <= (1U << 6)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	21
#elif NR_CPUS <= (1U << 7)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	21
#elif NR_CPUS <= (1U << 8)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	37
#elif NR_CPUS <= (1U << 9)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	73
#elif NR_CPUS <= (1U << 10)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	149
#elif NR_CPUS <= (1U << 11)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	293
#elif NR_CPUS <= (1U << 12)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	585
#elif NR_CPUS <= (1U << 13)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	1173
#elif NR_CPUS <= (1U << 14)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	2341
#elif NR_CPUS <= (1U << 15)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	4681
#elif NR_CPUS <= (1U << 16)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	4681
#elif NR_CPUS <= (1U << 17)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	8777
#elif NR_CPUS <= (1U << 18)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	17481
#elif NR_CPUS <= (1U << 19)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	34953
#elif NR_CPUS <= (1U << 20)
# define PERCPU_COUNTER_TREE_STATIC_NR_ITEMS	69905
#else
# error "Unsupported number of CPUs."
#endif

struct percpu_counter_tree_level_item {
	atomic_t count;			/*
					 * Count the number of carry fort this tree item.
					 * The carry counter is kept at the order of the
					 * carry accounted for at this tree level.
					 */
} ____cacheline_aligned_in_smp;

#define PERCPU_COUNTER_TREE_ITEMS_STATIC_SIZE	\
	(PERCPU_COUNTER_TREE_STATIC_NR_ITEMS * sizeof(struct percpu_counter_tree_level_item))

struct percpu_counter_tree {
	/* Fast-path fields. */
	unsigned int __percpu *level0;	/* Pointer to per-CPU split counters (tree level 0). */
	unsigned int level0_bit_mask;	/* Bit mask to apply to detect carry propagation from tree level 0. */
	union {
		unsigned int *i;	/* Approximate sum for single-CPU topology. */
		atomic_t *a;		/* Approximate sum for SMP topology.  */
	} approx_sum;
	int bias;			/* Bias to apply to counter precise and approximate values. */

	/* Slow-path fields. */
	struct percpu_counter_tree_level_item *items;	/* Array of tree items for levels 1 to N. */
	unsigned int batch_size;	/*
					 * The batch size is the increment step at level 0 which
					 * triggers a carry propagation. The batch size is required
					 * to be greater than 1, and a power of 2.
					 */
	/*
	 * The tree approximate sum is guaranteed to be within this accuracy range:
	 * (precise_sum - approx_accuracy_range.under) <= approx_sum <= (precise_sum + approx_accuracy_range.over).
	 * This accuracy is derived from the hardware topology and the tree batch_size.
	 * The "under" accuracy is larger than the "over" accuracy because the negative range of a
	 * two's complement signed integer is one unit larger than the positive range. This delta
	 * is summed for each tree item, which leads to a significantly larger "under" accuracy range
	 * compared to the "over" accuracy range.
	 */
	struct {
		unsigned int under;
		unsigned int over;
	} approx_accuracy_range;
};

size_t percpu_counter_tree_items_size(void);
int percpu_counter_tree_init_many(struct percpu_counter_tree *counters, struct percpu_counter_tree_level_item *items,
				  unsigned int nr_counters, unsigned int batch_size, gfp_t gfp_flags);
int percpu_counter_tree_init(struct percpu_counter_tree *counter, struct percpu_counter_tree_level_item *items,
			     unsigned int batch_size, gfp_t gfp_flags);
void percpu_counter_tree_destroy_many(struct percpu_counter_tree *counter, unsigned int nr_counters);
void percpu_counter_tree_destroy(struct percpu_counter_tree *counter);
void percpu_counter_tree_add(struct percpu_counter_tree *counter, int inc);
int percpu_counter_tree_precise_sum(struct percpu_counter_tree *counter);
int percpu_counter_tree_approximate_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b);
int percpu_counter_tree_approximate_compare_value(struct percpu_counter_tree *counter, int v);
int percpu_counter_tree_precise_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b);
int percpu_counter_tree_precise_compare_value(struct percpu_counter_tree *counter, int v);
void percpu_counter_tree_set(struct percpu_counter_tree *counter, int v);
void percpu_counter_tree_approximate_accuracy_range(struct percpu_counter_tree *counter,
						    unsigned int *under, unsigned int *over);
int percpu_counter_tree_subsystem_init(void);

/**
 * percpu_counter_tree_approximate_sum() - Return approximate counter sum.
 * @counter: The counter to sum.
 *
 * Querying the approximate sum is fast, but it is only accurate within
 * the bounds delimited by percpu_counter_tree_approximate_accuracy_range().
 * This is meant to be used when speed is preferred over accuracy.
 *
 * Return: The current approximate counter sum.
 */
static inline
int percpu_counter_tree_approximate_sum(struct percpu_counter_tree *counter)
{
	unsigned int v;

	if (!counter->level0_bit_mask)
		v = READ_ONCE(*counter->approx_sum.i);
	else
		v = atomic_read(counter->approx_sum.a);
	return (int) (v + (unsigned int)READ_ONCE(counter->bias));
}

#else	/* !CONFIG_SMP */

#define PERCPU_COUNTER_TREE_ITEMS_STATIC_SIZE	0

struct percpu_counter_tree_level_item;

struct percpu_counter_tree {
	atomic_t count;
};

static inline
size_t percpu_counter_tree_items_size(void)
{
	return 0;
}

static inline
int percpu_counter_tree_init_many(struct percpu_counter_tree *counters, struct percpu_counter_tree_level_item *items,
				  unsigned int nr_counters, unsigned int batch_size, gfp_t gfp_flags)
{
	for (unsigned int i = 0; i < nr_counters; i++)
		atomic_set(&counters[i].count, 0);
	return 0;
}

static inline
int percpu_counter_tree_init(struct percpu_counter_tree *counter, struct percpu_counter_tree_level_item *items,
			     unsigned int batch_size, gfp_t gfp_flags)
{
	return percpu_counter_tree_init_many(counter, items, 1, batch_size, gfp_flags);
}

static inline
void percpu_counter_tree_destroy_many(struct percpu_counter_tree *counter, unsigned int nr_counters)
{
}

static inline
void percpu_counter_tree_destroy(struct percpu_counter_tree *counter)
{
}

static inline
int percpu_counter_tree_precise_sum(struct percpu_counter_tree *counter)
{
	return atomic_read(&counter->count);
}

static inline
int percpu_counter_tree_precise_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b)
{
	int count_a = percpu_counter_tree_precise_sum(a),
	    count_b = percpu_counter_tree_precise_sum(b);

	if (count_a == count_b)
		return 0;
	if (count_a < count_b)
		return -1;
	return 1;
}

static inline
int percpu_counter_tree_precise_compare_value(struct percpu_counter_tree *counter, int v)
{
	int count = percpu_counter_tree_precise_sum(counter);

	if (count == v)
		return 0;
	if (count < v)
		return -1;
	return 1;
}

static inline
int percpu_counter_tree_approximate_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b)
{
	return percpu_counter_tree_precise_compare(a, b);
}

static inline
int percpu_counter_tree_approximate_compare_value(struct percpu_counter_tree *counter, int v)
{
	return percpu_counter_tree_precise_compare_value(counter, v);
}

static inline
void percpu_counter_tree_set(struct percpu_counter_tree *counter, int v)
{
	atomic_set(&counter->count, v);
}

static inline
void percpu_counter_tree_approximate_accuracy_range(struct percpu_counter_tree *counter,
						    unsigned int *under, unsigned int *over)
{
	*under = 0;
	*over = 0;
}

static inline
void percpu_counter_tree_add(struct percpu_counter_tree *counter, int inc)
{
	atomic_add(inc, &counter->count);
}

static inline
int percpu_counter_tree_approximate_sum(struct percpu_counter_tree *counter)
{
	return percpu_counter_tree_precise_sum(counter);
}

static inline
int percpu_counter_tree_subsystem_init(void)
{
	return 0;
}

#endif	/* CONFIG_SMP */

/**
 * percpu_counter_tree_approximate_sum_positive() - Return a positive approximate counter sum.
 * @counter: The counter to sum.
 *
 * Return an approximate counter sum which is guaranteed to be greater
 * or equal to 0.
 *
 * Return: The current positive approximate counter sum.
 */
static inline
int percpu_counter_tree_approximate_sum_positive(struct percpu_counter_tree *counter)
{
	int v = percpu_counter_tree_approximate_sum(counter);
	return v > 0 ? v : 0;
}

/**
 * percpu_counter_tree_precise_sum_positive() - Return a positive precise counter sum.
 * @counter: The counter to sum.
 *
 * Return a precise counter sum which is guaranteed to be greater
 * or equal to 0.
 *
 * Return: The current positive precise counter sum.
 */
static inline
int percpu_counter_tree_precise_sum_positive(struct percpu_counter_tree *counter)
{
	int v = percpu_counter_tree_precise_sum(counter);
	return v > 0 ? v : 0;
}

#endif  /* _PERCPU_COUNTER_TREE_H */
