// SPDX-License-Identifier: GPL-2.0+ OR MIT
// SPDX-FileCopyrightText: 2025 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

/*
 * Split Counters With Tree Approximation Propagation
 *
 * * Propagation diagram when reaching batch size thresholds (± batch size):
 *
 * Example diagram for 8 CPUs:
 *
 * log2(8) = 3 levels
 *
 * At each level, each pair propagates its values to the next level when
 * reaching the batch size thresholds.
 *
 * Counters at levels 0, 1, 2 can be kept on a single byte ([-128 .. +127] range),
 * although it may be relevant to keep them on 32-bit counters for
 * simplicity. (complexity vs memory footprint tradeoff)
 *
 * Counter at level 3 can be kept on a 32-bit counter.
 *
 * Level 0:  0    1    2    3    4    5    6    7
 *           |   /     |   /     |   /     |   /
 *           |  /      |  /      |  /      |  /
 *           | /       | /       | /       | /
 * Level 1:  0         1         2         3
 *           |       /           |       /
 *           |    /              |    /
 *           | /                 | /
 * Level 2:  0                   1
 *           |               /
 *           |         /
 *           |   /
 * Level 3:  0
 *
 * * Approximation accuracy:
 *
 * BATCH(level N): Level N batch size.
 *
 * Example for BATCH(level 0) = 32.
 *
 * BATCH(level 0) =  32
 * BATCH(level 1) =  64
 * BATCH(level 2) = 128
 * BATCH(level N) = BATCH(level 0) * 2^N
 *
 *            per-counter     global
 *            accuracy        accuracy
 * Level 0:   [ -32 ..  +31]  ±256  (8 * 32)
 * Level 1:   [ -64 ..  +63]  ±256  (4 * 64)
 * Level 2:   [-128 .. +127]  ±256  (2 * 128)
 * Total:      ------         ±768  (log2(nr_cpu_ids) * BATCH(level 0) * nr_cpu_ids)
 *
 * Note that the global accuracy can be calculated more precisely
 * by taking into account that the positive accuracy range is
 * 31 rather than 32.
 *
 * -----
 *
 * Approximate Sum Carry Propagation
 *
 * Let's define a number of counter bits for each level, e.g.:
 *
 * log2(BATCH(level 0)) = log2(32) = 5
 *
 *               nr_bit        value_mask                      range
 * Level 0:      5 bits        v                             0 ..  +31
 * Level 1:      1 bit        (v & ~((1UL << 5) - 1))        0 ..  +63
 * Level 2:      1 bit        (v & ~((1UL << 6) - 1))        0 .. +127
 * Level 3:     25 bits       (v & ~((1UL << 7) - 1))        0 .. 2^32-1
 *
 * Note: Use a full 32-bit per-cpu counter at level 0 to allow precise sum.
 *
 * Note: Use cacheline aligned counters at levels above 0 to prevent false sharing.
 *       If memory footprint is an issue, a specialized allocator could be used
 *       to eliminate padding.
 *
 * Example with expanded values:
 *
 * counter_add(counter, inc):
 *
 *         if (!inc)
 *                 return;
 *
 *         res = percpu_add_return(counter @ Level 0, inc);
 *         orig = res - inc;
 *         if (inc < 0) {
 *                 inc = -(-inc & ~0b00011111);  // Clear used bits
 *                 // xor bit 5: underflow
 *                 if ((inc ^ orig ^ res) & 0b00100000)
 *                         inc -= 0b00100000;
 *         } else {
 *                 inc &= ~0b00011111;           // Clear used bits
 *                 // xor bit 5: overflow
 *                 if ((inc ^ orig ^ res) & 0b00100000)
 *                         inc += 0b00100000;
 *         }
 *         if (!inc)
 *                 return;
 *
 *         res = atomic_add_return(counter @ Level 1, inc);
 *         orig = res - inc;
 *         if (inc < 0) {
 *                 inc = -(-inc & ~0b00111111);  // Clear used bits
 *                 // xor bit 6: underflow
 *                 if ((inc ^ orig ^ res) & 0b01000000)
 *                         inc -= 0b01000000;
 *         } else {
 *                 inc &= ~0b00111111;           // Clear used bits
 *                 // xor bit 6: overflow
 *                 if ((inc ^ orig ^ res) & 0b01000000)
 *                         inc += 0b01000000;
 *         }
 *         if (!inc)
 *                 return;
 *
 *         res = atomic_add_return(counter @ Level 2, inc);
 *         orig = res - inc;
 *         if (inc < 0) {
 *                 inc = -(-inc & ~0b01111111);  // Clear used bits
 *                 // xor bit 7: underflow
 *                 if ((inc ^ orig ^ res) & 0b10000000)
 *                         inc -= 0b10000000;
 *         } else {
 *                 inc &= ~0b01111111;           // Clear used bits
 *                 // xor bit 7: overflow
 *                 if ((inc ^ orig ^ res) & 0b10000000)
 *                         inc += 0b10000000;
 *         }
 *         if (!inc)
 *                 return;
 *
 *         atomic_add(counter @ Level 3, inc);
 */

#include <linux/percpu_counter_tree.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/math.h>

#define MAX_NR_LEVELS 5

/*
 * The counter configuration is selected at boot time based on the
 * hardware topology.
 */
struct counter_config {
	unsigned int nr_items;				/*
							 * nr_items is the number of items in the tree for levels 1
							 * up to and including the final level (approximate sum).
							 * It excludes the level 0 per-CPU counters.
							 */
	unsigned char nr_levels;			/*
							 * nr_levels is the number of hierarchical counter tree levels.
							 * It excludes the final level (approximate sum).
							 */
	unsigned char n_arity_order[MAX_NR_LEVELS];	/*
							 * n-arity of tree nodes for each level from
							 * 0 to (nr_levels - 1).
							 */
};

static const struct counter_config per_nr_cpu_order_config[] = {
	[0] =	{ .nr_items = 0,	.nr_levels = 0,		.n_arity_order = { 0 } },
	[1] =	{ .nr_items = 1,	.nr_levels = 1,		.n_arity_order = { 1 } },
	[2] =	{ .nr_items = 3,	.nr_levels = 2,		.n_arity_order = { 1, 1 } },
	[3] =	{ .nr_items = 7,	.nr_levels = 3,		.n_arity_order = { 1, 1, 1 } },
	[4] =	{ .nr_items = 7,	.nr_levels = 3,		.n_arity_order = { 2, 1, 1 } },
	[5] =	{ .nr_items = 11,	.nr_levels = 3,		.n_arity_order = { 2, 2, 1 } },
	[6] =	{ .nr_items = 21,	.nr_levels = 3,		.n_arity_order = { 2, 2, 2 } },
	[7] =	{ .nr_items = 21,	.nr_levels = 3,		.n_arity_order = { 3, 2, 2 } },
	[8] =	{ .nr_items = 37,	.nr_levels = 3,		.n_arity_order = { 3, 3, 2 } },
	[9] =	{ .nr_items = 73,	.nr_levels = 3,		.n_arity_order = { 3, 3, 3 } },
	[10] =	{ .nr_items = 149,	.nr_levels = 4,		.n_arity_order = { 3, 3, 2, 2 } },
	[11] =	{ .nr_items = 293,	.nr_levels = 4,		.n_arity_order = { 3, 3, 3, 2 } },
	[12] =	{ .nr_items = 585,	.nr_levels = 4,		.n_arity_order = { 3, 3, 3, 3 } },
	[13] =	{ .nr_items = 1173,	.nr_levels = 5,		.n_arity_order = { 3, 3, 3, 2, 2 } },
	[14] =	{ .nr_items = 2341,	.nr_levels = 5,		.n_arity_order = { 3, 3, 3, 3, 2 } },
	[15] =	{ .nr_items = 4681,	.nr_levels = 5,		.n_arity_order = { 3, 3, 3, 3, 3 } },
	[16] =	{ .nr_items = 4681,	.nr_levels = 5,		.n_arity_order = { 4, 3, 3, 3, 3 } },
	[17] =	{ .nr_items = 8777,	.nr_levels = 5,		.n_arity_order = { 4, 4, 3, 3, 3 } },
	[18] =	{ .nr_items = 17481,	.nr_levels = 5,		.n_arity_order = { 4, 4, 4, 3, 3 } },
	[19] =	{ .nr_items = 34953,	.nr_levels = 5,		.n_arity_order = { 4, 4, 4, 4, 3 } },
	[20] =	{ .nr_items = 69905,	.nr_levels = 5,		.n_arity_order = { 4, 4, 4, 4, 4 } },
};

static const struct counter_config *counter_config;	/* Hierarchical counter configuration for the hardware topology. */
static unsigned int nr_cpus_order,			/* Order of nr_cpu_ids. */
		    accuracy_multiplier;		/* Calculate accuracy for a given batch size (multiplication factor). */

static
int __percpu_counter_tree_init(struct percpu_counter_tree *counter,
			       unsigned int batch_size, gfp_t gfp_flags,
			       unsigned int __percpu *level0,
			       struct percpu_counter_tree_level_item *items)
{
	/* Batch size must be greater than 1, and a power of 2. */
	if (WARN_ON(batch_size <= 1 || (batch_size & (batch_size - 1))))
		return -EINVAL;
	counter->batch_size = batch_size;
	counter->bias = 0;
	counter->level0 = level0;
	counter->items = items;
	if (!nr_cpus_order) {
		counter->approx_sum.i = per_cpu_ptr(counter->level0, 0);
		counter->level0_bit_mask = 0;
	} else {
		counter->approx_sum.a = &counter->items[counter_config->nr_items - 1].count;
		counter->level0_bit_mask = 1UL << get_count_order(batch_size);
	}
	/*
	 * Each tree item signed integer has a negative range which is
	 * one unit greater than the positive range.
	 */
	counter->approx_accuracy_range.under = batch_size * accuracy_multiplier;
	counter->approx_accuracy_range.over = (batch_size - 1) * accuracy_multiplier;
	return 0;
}

/**
 * percpu_counter_tree_init_many() - Initialize many per-CPU counter trees.
 * @counters: An array of @nr_counters counters to initialize.
 *	      Their memory is provided by the caller.
 * @items: Pointer to memory area where to store tree items.
 *	   This memory is provided by the caller.
 *	   Its size needs to be at least @nr_counters * percpu_counter_tree_items_size().
 * @nr_counters: The number of counter trees to initialize
 * @batch_size: The batch size is the increment step at level 0 which triggers a
 * 		carry propagation.
 *		The batch size is required to be greater than 1, and a power of 2.
 * @gfp_flags: gfp flags to pass to the per-CPU allocator.
 *
 * Initialize many per-CPU counter trees using a single per-CPU
 * allocator invocation for @nr_counters counters.
 *
 * Return:
 * * %0: Success
 * * %-EINVAL:		- Invalid @batch_size argument
 * * %-ENOMEM:		- Out of memory
 */
int percpu_counter_tree_init_many(struct percpu_counter_tree *counters, struct percpu_counter_tree_level_item *items,
				  unsigned int nr_counters, unsigned int batch_size, gfp_t gfp_flags)
{
	void __percpu *level0, *level0_iter;
	size_t counter_size, items_size = 0;
	void *items_iter;
	unsigned int i;
	int ret;

	counter_size = ALIGN(sizeof(*counters), __alignof__(*counters));
	level0 = __alloc_percpu_gfp(nr_counters * counter_size,
				    __alignof__(*counters), gfp_flags);
	if (!level0)
		return -ENOMEM;
	if (nr_cpus_order) {
		items_size = percpu_counter_tree_items_size();
		memset(items, 0, items_size * nr_counters);
	}
	level0_iter = level0;
	items_iter = items;
	for (i = 0; i < nr_counters; i++) {
		ret = __percpu_counter_tree_init(&counters[i], batch_size, gfp_flags, level0_iter, items_iter);
		if (ret)
			goto free_level0;
		level0_iter += counter_size;
		if (nr_cpus_order)
			items_iter += items_size;
	}
	return 0;

free_level0:
	free_percpu(level0);
	return ret;
}

/**
 * percpu_counter_tree_init() - Initialize one per-CPU counter tree.
 * @counter: Counter to initialize.
 *	     Its memory is provided by the caller.
 * @items: Pointer to memory area where to store tree items.
 *	   This memory is provided by the caller.
 *	   Its size needs to be at least percpu_counter_tree_items_size().
 * @batch_size: The batch size is the increment step at level 0 which triggers a
 * 		carry propagation.
 *		The batch size is required to be greater than 1, and a power of 2.
 * @gfp_flags: gfp flags to pass to the per-CPU allocator.
 *
 * Initialize one per-CPU counter tree.
 *
 * Return:
 * * %0: Success
 * * %-EINVAL:		- Invalid @batch_size argument
 * * %-ENOMEM:		- Out of memory
 */
int percpu_counter_tree_init(struct percpu_counter_tree *counter, struct percpu_counter_tree_level_item *items,
			     unsigned int batch_size, gfp_t gfp_flags)
{
	return percpu_counter_tree_init_many(counter, items, 1, batch_size, gfp_flags);
}

/**
 * percpu_counter_tree_destroy_many() - Destroy many per-CPU counter trees.
 * @counters: Array of counters trees to destroy.
 * @nr_counters: The number of counter trees to destroy.
 *
 * Release internal resources allocated for @nr_counters per-CPU counter trees.
 */

void percpu_counter_tree_destroy_many(struct percpu_counter_tree *counters, unsigned int nr_counters)
{
	free_percpu(counters->level0);
}

/**
 * percpu_counter_tree_destroy() - Destroy one per-CPU counter tree.
 * @counter: Counter to destroy.
 *
 * Release internal resources allocated for one per-CPU counter tree.
 */
void percpu_counter_tree_destroy(struct percpu_counter_tree *counter)
{
	return percpu_counter_tree_destroy_many(counter, 1);
}

static
int percpu_counter_tree_carry(int orig, int res, int inc, unsigned int bit_mask)
{
	if (inc < 0) {
		inc = -(-inc & ~(bit_mask - 1));
		/*
		 * xor bit_mask: underflow.
		 *
		 * If inc has bit set, decrement an additional bit if
		 * there is _no_ bit transition between orig and res.
		 * Else, inc has bit cleared, decrement an additional
		 * bit if there is a bit transition between orig and
		 * res.
		 */
		if ((inc ^ orig ^ res) & bit_mask)
			inc -= bit_mask;
	} else {
		inc &= ~(bit_mask - 1);
		/*
		 * xor bit_mask: overflow.
		 *
		 * If inc has bit set, increment an additional bit if
		 * there is _no_ bit transition between orig and res.
		 * Else, inc has bit cleared, increment an additional
		 * bit if there is a bit transition between orig and
		 * res.
		 */
		if ((inc ^ orig ^ res) & bit_mask)
			inc += bit_mask;
	}
	return inc;
}

/*
 * It does not matter through which path the carry propagates up the
 * tree, therefore there is no need to disable preemption because the
 * cpu number is only used to favor cache locality.
 */
static
void percpu_counter_tree_add_slowpath(struct percpu_counter_tree *counter, int inc)
{
	unsigned int level_items, nr_levels = counter_config->nr_levels,
		     level, n_arity_order, bit_mask;
	struct percpu_counter_tree_level_item *item = counter->items;
	unsigned int cpu = raw_smp_processor_id();

	WARN_ON_ONCE(!nr_cpus_order);	/* Should never be called for 1 cpu. */

	n_arity_order = counter_config->n_arity_order[0];
	bit_mask = counter->level0_bit_mask << n_arity_order;
	level_items = 1U << (nr_cpus_order - n_arity_order);

	for (level = 1; level < nr_levels; level++) {
		atomic_t *count = &item[cpu & (level_items - 1)].count;
		unsigned int orig, res;

		res = atomic_add_return_relaxed(inc, count);
		orig = res - inc;
		inc = percpu_counter_tree_carry(orig, res, inc, bit_mask);
		if (likely(!inc))
			return;
		item += level_items;
		n_arity_order = counter_config->n_arity_order[level];
		level_items >>= n_arity_order;
		bit_mask <<= n_arity_order;
	}
	atomic_add(inc, counter->approx_sum.a);
}

/**
 * percpu_counter_tree_add() - Add to a per-CPU counter tree.
 * @counter: Counter added to.
 * @inc: Increment value (either positive or negative).
 *
 * Add @inc to a per-CPU counter tree. This is a fast-path which will
 * typically increment per-CPU counters as long as there is no carry
 * greater or equal to the counter tree batch size.
 */
void percpu_counter_tree_add(struct percpu_counter_tree *counter, int inc)
{
	unsigned int bit_mask = counter->level0_bit_mask, orig, res;

	res = this_cpu_add_return(*counter->level0, inc);
	orig = res - inc;
	inc = percpu_counter_tree_carry(orig, res, inc, bit_mask);
	if (likely(!inc))
		return;
	percpu_counter_tree_add_slowpath(counter, inc);
}


static
int percpu_counter_tree_precise_sum_unbiased(struct percpu_counter_tree *counter)
{
	unsigned int sum = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		sum += *per_cpu_ptr(counter->level0, cpu);
	return (int) sum;
}

/**
 * percpu_counter_tree_precise_sum() - Return precise counter sum.
 * @counter: The counter to sum.
 *
 * Querying the precise sum is relatively expensive because it needs to
 * iterate over all CPUs.
 * This is meant to be used when accuracy is preferred over speed.
 *
 * Return: The current precise counter sum.
 */
int percpu_counter_tree_precise_sum(struct percpu_counter_tree *counter)
{
	return percpu_counter_tree_precise_sum_unbiased(counter) + READ_ONCE(counter->bias);
}

static
int compare_delta(int delta, unsigned int accuracy_neg, unsigned int accuracy_pos)
{
	if (delta >= 0) {
		if (delta <= accuracy_pos)
			return 0;
		else
			return 1;
	} else {
		if (-delta <= accuracy_neg)
			return 0;
		else
			return -1;
	}
}

/**
 * percpu_counter_tree_approximate_compare - Approximated comparison of two counter trees.
 * @a: First counter to compare.
 * @b: Second counter to compare.
 *
 * Evaluate an approximate comparison of two counter trees.
 * This approximation comparison is fast, and provides an accurate
 * answer if the counters are found to be either less than or greater
 * than the other. However, if the approximated comparison returns
 * 0, the counters respective sums are found to be within the two
 * counters accuracy range.
 *
 * Return:
 * * %0		- Counters @a and @b do not differ by more than the sum of their respective
 *                accuracy ranges.
 * * %-1	- Counter @a less than counter @b.
 * * %1		- Counter @a is greater than counter @b.
 */
int percpu_counter_tree_approximate_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b)
{
	return compare_delta(percpu_counter_tree_approximate_sum(a) - percpu_counter_tree_approximate_sum(b),
			     a->approx_accuracy_range.over + b->approx_accuracy_range.under,
			     a->approx_accuracy_range.under + b->approx_accuracy_range.over);
}

/**
 * percpu_counter_tree_approximate_compare_value - Approximated comparison of a counter tree against a given value.
 * @counter: Counter to compare.
 * @v: Value to compare.
 *
 * Evaluate an approximate comparison of a counter tree against a given value.
 * This approximation comparison is fast, and provides an accurate
 * answer if the counter is found to be either less than or greater
 * than the value. However, if the approximated comparison returns
 * 0, the value is within the counter accuracy range.
 *
 * Return:
 * * %0		- The value @v is within the accuracy range of the counter.
 * * %-1	- The value @v is less than the counter.
 * * %1		- The value @v is greater than the counter.
 */
int percpu_counter_tree_approximate_compare_value(struct percpu_counter_tree *counter, int v)
{
	return compare_delta(v - percpu_counter_tree_approximate_sum(counter),
			     counter->approx_accuracy_range.under,
			     counter->approx_accuracy_range.over);
}

/**
 * percpu_counter_tree_precise_compare - Precise comparison of two counter trees.
 * @a: First counter to compare.
 * @b: Second counter to compare.
 *
 * Evaluate a precise comparison of two counter trees.
 * As an optimization, it uses the approximate counter comparison
 * to quickly compare counters which are far apart. Only cases where
 * counter sums are within the accuracy range require precise counter
 * sums.
 *
 * Return:
 * * %0		- Counters are equal.
 * * %-1	- Counter @a less than counter @b.
 * * %1		- Counter @a is greater than counter @b.
 */
int percpu_counter_tree_precise_compare(struct percpu_counter_tree *a, struct percpu_counter_tree *b)
{
	int count_a = percpu_counter_tree_approximate_sum(a),
	    count_b = percpu_counter_tree_approximate_sum(b);
	unsigned int accuracy_a, accuracy_b;
	int delta = count_a - count_b;
	int res;

	res = compare_delta(delta,
			    a->approx_accuracy_range.over + b->approx_accuracy_range.under,
			    a->approx_accuracy_range.under + b->approx_accuracy_range.over);
	/* The values are distanced enough for an accurate approximated comparison. */
	if (res)
		return res;

	/*
	 * The approximated comparison is within the accuracy range, therefore at least one
	 * precise sum is needed. Sum the counter which has the largest accuracy first.
	 */
	if (delta >= 0) {
		accuracy_a = a->approx_accuracy_range.under;
		accuracy_b = b->approx_accuracy_range.over;
	} else {
		accuracy_a = a->approx_accuracy_range.over;
		accuracy_b = b->approx_accuracy_range.under;
	}
	if (accuracy_b < accuracy_a) {
		count_a = percpu_counter_tree_precise_sum(a);
		res = compare_delta(count_a - count_b,
				    b->approx_accuracy_range.under,
				    b->approx_accuracy_range.over);
		if (res)
			return res;
		/* Precise sum of second counter is required. */
		count_b = percpu_counter_tree_precise_sum(b);
	} else {
		count_b = percpu_counter_tree_precise_sum(b);
		res = compare_delta(count_a - count_b,
				    a->approx_accuracy_range.over,
				    a->approx_accuracy_range.under);
		if (res)
			return res;
		/* Precise sum of second counter is required. */
		count_a = percpu_counter_tree_precise_sum(a);
	}
	if (count_a - count_b < 0)
		return -1;
	if (count_a - count_b > 0)
		return 1;
	return 0;
}

/**
 * percpu_counter_tree_precise_compare_value - Precise comparison of a counter tree against a given value.
 * @counter: Counter to compare.
 * @v: Value to compare.
 *
 * Evaluate a precise comparison of a counter tree against a given value.
 * As an optimization, it uses the approximate counter comparison
 * to quickly identify whether the counter and value are far apart.
 * Only cases where the value is within the counter accuracy range
 * require a precise counter sum.
 *
 * Return:
 * * %0		- The value @v is equal to the counter.
 * * %-1	- The value @v is less than the counter.
 * * %1		- The value @v is greater than the counter.
 */
int percpu_counter_tree_precise_compare_value(struct percpu_counter_tree *counter, int v)
{
	int count = percpu_counter_tree_approximate_sum(counter);
	int res;

	res = compare_delta(v - count,
			    counter->approx_accuracy_range.under,
			    counter->approx_accuracy_range.over);
	/* The values are distanced enough for an accurate approximated comparison. */
	if (res)
		return res;

	/* Precise sum is required. */
	count = percpu_counter_tree_precise_sum(counter);
	if (v - count < 0)
		return -1;
	if (v - count > 0)
		return 1;
	return 0;
}

static
void percpu_counter_tree_set_bias(struct percpu_counter_tree *counter, int bias)
{
	WRITE_ONCE(counter->bias, bias);
}

/**
 * percpu_counter_tree_set - Set the counter tree sum to a given value.
 * @counter: Counter to set.
 * @v: Value to set.
 *
 * Set the counter sum to a given value. It can be useful for instance
 * to reset the counter sum to 0. Note that even after setting the
 * counter sum to a given value, the counter sum approximation can
 * return any value within the accuracy range around that value.
 */
void percpu_counter_tree_set(struct percpu_counter_tree *counter, int v)
{
	percpu_counter_tree_set_bias(counter,
				     v - percpu_counter_tree_precise_sum_unbiased(counter));
}

/**
 * percpu_counter_tree_approximate_accuracy_range - Query the accuracy range for a counter tree.
 * @counter: Counter to query.
 * @under: Pointer where to store the to the accuracy range below the approximation.
 * @over: Pointer where to store the to the accuracy range above the approximation.
 *
 * Query the accuracy range limits for the counter.
 * Because of two's complement binary representation, the "under" range is typically
 * slightly larger than the "over" range.
 * Those values are derived from the hardware topology and the counter tree batch size.
 * They are invariant for a given counter tree.
 * Using this function should not be typically required, see the following functions instead:
 * * percpu_counter_tree_approximate_compare(),
 * * percpu_counter_tree_approximate_compare_value(),
 * * percpu_counter_tree_precise_compare(),
 * * percpu_counter_tree_precise_compare_value().
 */
void percpu_counter_tree_approximate_accuracy_range(struct percpu_counter_tree *counter,
						    unsigned int *under, unsigned int *over)
{
	*under = counter->approx_accuracy_range.under;
	*over = counter->approx_accuracy_range.over;
}

/*
 * percpu_counter_tree_items_size - Query the size required for counter tree items.
 *
 * Query the size of the memory area required to hold the counter tree
 * items. This depends on the hardware topology and is invariant after
 * boot.
 *
 * Return: Size required to hold tree items.
 */
size_t percpu_counter_tree_items_size(void)
{
	if (!nr_cpus_order)
		return 0;
	return counter_config->nr_items * sizeof(struct percpu_counter_tree_level_item);
}

static void __init calculate_accuracy_topology(void)
{
	unsigned int nr_levels = counter_config->nr_levels, level;
	unsigned int level_items = 1U << nr_cpus_order;
	unsigned int batch_size = 1;

	for (level = 0; level < nr_levels; level++) {
		unsigned int n_arity_order = counter_config->n_arity_order[level];

		/*
		 * The accuracy multiplier is derived from a batch size of 1
		 * to speed up calculating the accuracy at tree initialization.
		 */
		accuracy_multiplier += batch_size * level_items;
		batch_size <<= n_arity_order;
		level_items >>= n_arity_order;
	}
}

int __init percpu_counter_tree_subsystem_init(void)
{
	nr_cpus_order = get_count_order(nr_cpu_ids);
	if (WARN_ON_ONCE(nr_cpus_order >= ARRAY_SIZE(per_nr_cpu_order_config))) {
		printk(KERN_ERR "Unsupported number of CPUs (%u)\n", nr_cpu_ids);
		return -1;
	}
	counter_config = &per_nr_cpu_order_config[nr_cpus_order];
	calculate_accuracy_topology();
	return 0;
}
