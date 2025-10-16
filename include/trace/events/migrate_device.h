/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM migrate_device

#if !defined(_TRACE_MIGRATE_DEVICE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MIGRATE_DEVICE_H

#include <linux/tracepoint.h>
#include <linux/migrate.h>

TRACE_EVENT(migrate_vma_setup,

	TP_PROTO(unsigned long start, unsigned long end, unsigned long nr_pages),

	TP_ARGS(start, end, nr_pages),

	TP_STRUCT__entry(
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(unsigned long, nr_pages)
	),

	TP_fast_assign(
		__entry->start = start;
		__entry->end = end;
		__entry->nr_pages = nr_pages;
	),

	TP_printk("start=0x%lx end=0x%lx nr_pages=%lu",
		__entry->start, __entry->end, __entry->nr_pages)
);

TRACE_EVENT(migrate_vma_collect,

	TP_PROTO(unsigned long start, unsigned long end, unsigned long npages),

	TP_ARGS(start, end, npages),

	TP_STRUCT__entry(
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(unsigned long, npages)
	),

	TP_fast_assign(
		__entry->start = start;
		__entry->end = end;
		__entry->npages = npages;
	),

	TP_printk("start=0x%lx end=0x%lx npages=%lu",
		__entry->start, __entry->end, __entry->npages)
);

TRACE_EVENT(migrate_vma_collect_skip,

	TP_PROTO(unsigned long start, unsigned long end),

	TP_ARGS(start, end),

	TP_STRUCT__entry(
		__field(unsigned long, start)
		__field(unsigned long, end)
	),

	TP_fast_assign(
		__entry->start = start;
		__entry->end = end;
	),

	TP_printk("start=0x%lx end=0x%lx", __entry->start, __entry->end)
);

TRACE_EVENT(migrate_vma_collect_hole,

	TP_PROTO(unsigned long start, unsigned long end, unsigned long npages),

	TP_ARGS(start, end, npages),

	TP_STRUCT__entry(
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(unsigned long, npages)
	),

	TP_fast_assign(
		__entry->start = start;
		__entry->end = end;
		__entry->npages = npages;
	),

	TP_printk("start=0x%lx end=0x%lx npages=%lu",
		__entry->start, __entry->end, __entry->npages)
);

TRACE_EVENT(migrate_vma_unmap,

	TP_PROTO(unsigned long npages, unsigned long cpages),

	TP_ARGS(npages, cpages),

	TP_STRUCT__entry(
		__field(unsigned long, npages)
		__field(unsigned long, cpages)
	),

	TP_fast_assign(
		__entry->npages = npages;
		__entry->cpages = cpages;
	),

	TP_printk("npages=%lu cpages=%lu",
		__entry->npages, __entry->cpages)
);

TRACE_EVENT(migrate_device_pages,

	TP_PROTO(unsigned long npages, unsigned long migrated),

	TP_ARGS(npages, migrated),

	TP_STRUCT__entry(
		__field(unsigned long, npages)
		__field(unsigned long, migrated)
	),

	TP_fast_assign(
		__entry->npages = npages;
		__entry->migrated = migrated;
	),

	TP_printk("npages=%lu migrated=%lu",
		__entry->npages, __entry->migrated)
);

TRACE_EVENT(migrate_vma_pages,

	TP_PROTO(unsigned long npages, unsigned long start, unsigned long end),

	TP_ARGS(npages, start, end),

	TP_STRUCT__entry(
		__field(unsigned long, npages)
		__field(unsigned long, start)
		__field(unsigned long, end)
	),

	TP_fast_assign(
		__entry->npages = npages;
		__entry->start = start;
		__entry->end = end;
	),

	TP_printk("npages=%lu start=0x%lx end=0x%lx",
		__entry->npages, __entry->start, __entry->end)
);

TRACE_EVENT(migrate_device_finalize,

	TP_PROTO(unsigned long npages),

	TP_ARGS(npages),

	TP_STRUCT__entry(
		__field(unsigned long, npages)
	),

	TP_fast_assign(
		__entry->npages = npages;
	),

	TP_printk("npages=%lu", __entry->npages)
);

TRACE_EVENT(migrate_vma_finalize,

	TP_PROTO(unsigned long npages),

	TP_ARGS(npages),

	TP_STRUCT__entry(
		__field(unsigned long, npages)
	),

	TP_fast_assign(
		__entry->npages = npages;
	),

	TP_printk("npages=%lu", __entry->npages)
);
#endif /* _TRACE_MIGRATE_DEVICE_H */

#include <trace/define_trace.h>
