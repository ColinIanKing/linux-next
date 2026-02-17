========================================
The Hierarchical Per-CPU Counters (HPCC)
========================================

:Author: Mathieu Desnoyers

Introduction
============

Counters come in many varieties, each with their own trade offs:

 * A global atomic counter provides a fast read access to the current
   sum, at the expense of cache-line bouncing on updates. This leads to
   poor performance of frequent updates from various cores on large SMP
   systems.

 * A per-cpu split counter provides fast updates to per-cpu counters,
   at the expense of a slower aggregation (sum). The sum operation needs
   to iterate over all per-cpu counters to calculate the current total.

The hierarchical per-cpu counters attempt to provide the best of both
worlds (fast updates, and fast sum) by relaxing requirements on the sum
accuracy. It allows quickly querying an approximated sum value, along
with the possible min/max ranges of the associated precise sum. The
exact precise sum can still be calculated with an iteration on all
per-cpu counter, but the availability of an approximated sum value with
possible precise sum min/max ranges allows eliminating candidates which
are certainly outside of a known target range without the overhead of
precise sums.

Overview
========

The herarchical per-cpu counters are organized as a tree with the tree
root at the bottom (last level) and the first level of the tree
consisting of per-cpu counters.

The intermediate tree levels contain carry propagation counters. When
reaching a threshold (batch size), the carry is propagated down the
tree.

This allows reading an approximated value at the root, which has a
bounded accuracy (minimum/maximum possible precise sum range) determined
by the tree topology.

Use Cases
=========

Use cases HPCC is meant to handle invove tracking resources which are
used across many CPUs to quickly sum as feedback for decision making to
apply throttling, quota limits, sort tasks, and perform memory or task
migration decisions. When considering approximated sums within the
accuracy range of the decision threshold, the user can either:

 * Be conservative and fast: Consider that the sum has reached the
   limit as soon as the given limit is within the approximation range.

 * Be aggressive and fast: Consider that the sum is over the
   limit only when the approximation range is over the given limit.

 * Be precise and slow: Do a precise comparison with the limit, which
   requires a precise sum when the limit is within the approximated
   range.

One use-case for these hierarchical counters is to implement a two-pass
algorithm to speed up sorting picking a maximum/minimunm sum value from
a set. A first pass compares the approximated values, and then a second
pass only needs the precise sum for counter trees which are within the
possible precise sum range of the counter tree chosen by the first pass.

Functions and structures
========================

.. kernel-doc:: include/linux/percpu_counter_tree.h
.. kernel-doc:: lib/percpu_counter_tree.c
