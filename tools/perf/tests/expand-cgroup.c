// SPDX-License-Identifier: GPL-2.0
#include "tests.h"
#include "debug.h"
#include "evlist.h"
#include "cgroup.h"
#include "rblist.h"
#include "metricgroup.h"
#include "parse-events.h"
#include "pmu-events/pmu-events.h"
#include "pfm.h"
#include <subcmd/parse-options.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_expand_events(struct evlist *evlist)
{
	int i, ret = TEST_FAIL;
	int nr_events;
	bool was_group_event;
	int nr_members;  /* for the first evsel only */
	const char cgrp_str[] = "A,B,C";
	const char *cgrp_name[] = { "A", "B", "C" };
	int nr_cgrps = ARRAY_SIZE(cgrp_name);
	char **ev_name;
	struct evsel *evsel;

	TEST_ASSERT_VAL("evlist is empty", !evlist__empty(evlist));

	nr_events = evlist->core.nr_entries;
	ev_name = calloc(nr_events, sizeof(*ev_name));
	if (ev_name == NULL) {
		pr_debug("memory allocation failure\n");
		return TEST_FAIL;
	}
	i = 0;
	evlist__for_each_entry(evlist, evsel) {
		ev_name[i] = strdup(evsel->name);
		if (ev_name[i] == NULL) {
			pr_debug("memory allocation failure\n");
			goto out;
		}
		i++;
	}
	/* remember grouping info */
	was_group_event = evsel__is_group_event(evlist__first(evlist));
	nr_members = evlist__first(evlist)->core.nr_members;

	ret = evlist__expand_cgroup(evlist, cgrp_str, false);
	if (ret < 0) {
		pr_debug("failed to expand events for cgroups\n");
		goto out;
	}

	ret = TEST_FAIL;
	if (evlist->core.nr_entries != nr_events * nr_cgrps) {
		pr_debug("event count doesn't match\n");
		goto out;
	}

	i = 0;
	evlist__for_each_entry(evlist, evsel) {
		if (!evsel__name_is(evsel, ev_name[i % nr_events])) {
			pr_debug("event name doesn't match:\n");
			pr_debug("  evsel[%d]: %s\n  expected: %s\n",
				 i, evsel->name, ev_name[i % nr_events]);
			goto out;
		}
		if (strcmp(evsel->cgrp->name, cgrp_name[i / nr_events])) {
			pr_debug("cgroup name doesn't match:\n");
			pr_debug("  evsel[%d]: %s\n  expected: %s\n",
				 i, evsel->cgrp->name, cgrp_name[i / nr_events]);
			goto out;
		}

		if ((i % nr_events) == 0) {
			if (evsel__is_group_event(evsel) != was_group_event) {
				pr_debug("event group doesn't match: got %s, expect %s\n",
					 evsel__is_group_event(evsel) ? "true" : "false",
					 was_group_event ? "true" : "false");
				goto out;
			}
			if (evsel->core.nr_members != nr_members) {
				pr_debug("event group member doesn't match: %d vs %d\n",
					 evsel->core.nr_members, nr_members);
				goto out;
			}
		}
		i++;
	}
	ret = TEST_OK;

out:	for (i = 0; i < nr_events; i++)
		free(ev_name[i]);
	free(ev_name);
	return ret;
}

static int expand_default_events(void)
{
	int ret;
	struct evlist *evlist = evlist__new_default();

	TEST_ASSERT_VAL("failed to get evlist", evlist);

	ret = test_expand_events(evlist);
	evlist__delete(evlist);
	return ret;
}

static int expand_group_events(void)
{
	int ret;
	struct evlist *evlist;
	struct parse_events_error err;
	const char event_str[] = "{cycles,instructions}";

	symbol_conf.event_group = true;

	evlist = evlist__new();
	TEST_ASSERT_VAL("failed to get evlist", evlist);

	parse_events_error__init(&err);
	ret = parse_events(evlist, event_str, &err);
	if (ret < 0) {
		pr_debug("failed to parse event '%s', err %d\n", event_str, ret);
		parse_events_error__print(&err, event_str);
		goto out;
	}

	ret = test_expand_events(evlist);
out:
	parse_events_error__exit(&err);
	evlist__delete(evlist);
	return ret;
}

static int expand_libpfm_events(void)
{
	int ret;
	struct evlist *evlist;
	const char event_str[] = "CYCLES";
	struct option opt = {
		.value = &evlist,
	};

	symbol_conf.event_group = true;

	evlist = evlist__new();
	TEST_ASSERT_VAL("failed to get evlist", evlist);

	ret = parse_libpfm_events_option(&opt, event_str, 0);
	if (ret < 0) {
		pr_debug("failed to parse libpfm event '%s', err %d\n",
			 event_str, ret);
		goto out;
	}
	if (evlist__empty(evlist)) {
		pr_debug("libpfm was not enabled\n");
		goto out;
	}

	ret = test_expand_events(evlist);
out:
	evlist__delete(evlist);
	return ret;
}

static int expand_metric_events(void)
{
	int ret;
	struct evlist *evlist;
	const char metric_str[] = "CPI";
	const struct pmu_metrics_table *pme_test;

	evlist = evlist__new();
	TEST_ASSERT_VAL("failed to get evlist", evlist);

	pme_test = find_core_metrics_table("testarch", "testcpu");
	ret = metricgroup__parse_groups_test(evlist, pme_test, metric_str);
	if (ret < 0) {
		pr_debug("failed to parse '%s' metric\n", metric_str);
		goto out;
	}

	ret = test_expand_events(evlist);

out:
	evlist__delete(evlist);
	return ret;
}

static int test__expand_cgroup_events(struct test_suite *test __maybe_unused,
				      int subtest __maybe_unused)
{
	int ret;

	ret = expand_default_events();
	TEST_ASSERT_EQUAL("failed to expand default events", ret, 0);

	ret = expand_group_events();
	TEST_ASSERT_EQUAL("failed to expand event group", ret, 0);

	ret = expand_libpfm_events();
	TEST_ASSERT_EQUAL("failed to expand event group", ret, 0);

	ret = expand_metric_events();
	TEST_ASSERT_EQUAL("failed to expand metric events", ret, 0);

	return ret;
}

DEFINE_SUITE("Event expansion for cgroups", expand_cgroup_events);
