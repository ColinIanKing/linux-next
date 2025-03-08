// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Audit
 *
 * Copyright © 2024-2025 Microsoft Corporation
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/landlock.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "audit.h"
#include "common.h"

static int matches_log_domain_allocated(struct __test_metadata *const _metadata,
					int audit_fd, __u64 *domain_id)
{
	return audit_match_record(
		audit_fd, AUDIT_LANDLOCK_DOMAIN,
		REGEX_LANDLOCK_PREFIX
		" status=allocated mode=enforcing pid=[0-9]\\+ uid=[0-9]\\+"
		" exe=\"[^\"]\\+\" comm=\"audit_test\"$",
		domain_id);
}

static int
matches_log_domain_deallocated(struct __test_metadata *const _metadata,
			       int audit_fd, unsigned int num_denials,
			       __u64 *domain_id)
{
	static const char log_template[] = REGEX_LANDLOCK_PREFIX
		" status=deallocated denials=%u$";
	char log_match[sizeof(log_template) + 10];
	int log_match_len;

	log_match_len = snprintf(log_match, sizeof(log_match), log_template,
				 num_denials);
	if (log_match_len > sizeof(log_match))
		return -E2BIG;

	return audit_match_record(audit_fd, AUDIT_LANDLOCK_DOMAIN, log_match,
				  domain_id);
}

static int matches_log_signal(struct __test_metadata *const _metadata,
			      int audit_fd, const pid_t opid, __u64 *domain_id)
{
	static const char log_template[] = REGEX_LANDLOCK_PREFIX
		" blockers=scope\\.signal opid=%d ocomm=\"audit_test\"$";
	char log_match[sizeof(log_template) + 10];
	int log_match_len;

	log_match_len =
		snprintf(log_match, sizeof(log_match), log_template, opid);
	if (log_match_len > sizeof(log_match))
		return -E2BIG;

	return audit_match_record(audit_fd, AUDIT_LANDLOCK_ACCESS, log_match,
				  domain_id);
}

FIXTURE(audit_flags)
{
	struct audit_filter audit_filter;
	int audit_fd;
	__u64 *domain_id;
};

FIXTURE_VARIANT(audit_flags)
{
	const int restrict_flags;
};

/* clang-format off */
FIXTURE_VARIANT_ADD(audit_flags, default) {
	/* clang-format on */
	.restrict_flags = 0,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(audit_flags, same_exec_off) {
	/* clang-format on */
	.restrict_flags = LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(audit_flags, subdomains_off) {
	/* clang-format on */
	.restrict_flags = LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF,
};

/* clang-format off */
FIXTURE_VARIANT_ADD(audit_flags, cross_exec_on) {
	/* clang-format on */
	.restrict_flags = LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON,
};

FIXTURE_SETUP(audit_flags)
{
	disable_caps(_metadata);
	set_cap(_metadata, CAP_AUDIT_CONTROL);
	self->audit_fd = audit_init_with_exe_filter(&self->audit_filter);
	EXPECT_LE(0, self->audit_fd)
	{
		const char *error_msg;

		/* kill "$(auditctl -s | sed -ne 's/^pid \([0-9]\+\)$/\1/p')" */
		if (self->audit_fd == -EEXIST)
			error_msg = "socket already in use (e.g. auditd)";
		else
			error_msg = strerror(-self->audit_fd);
		TH_LOG("Failed to initialize audit: %s", error_msg);
	}
	clear_cap(_metadata, CAP_AUDIT_CONTROL);

	self->domain_id = mmap(NULL, sizeof(*self->domain_id),
			       PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(MAP_FAILED, self->domain_id);
	/* Domain IDs are greater or equal to 2^32. */
	*self->domain_id = 1;
}

FIXTURE_TEARDOWN(audit_flags)
{
	EXPECT_EQ(0, munmap(self->domain_id, sizeof(*self->domain_id)));

	set_cap(_metadata, CAP_AUDIT_CONTROL);
	EXPECT_EQ(0, audit_cleanup(self->audit_fd, &self->audit_filter));
	clear_cap(_metadata, CAP_AUDIT_CONTROL);
}

TEST_F(audit_flags, signal)
{
	int status;
	pid_t child;
	struct audit_records records;
	__u64 domain_id_deallocated = 2;

	child = fork();
	ASSERT_LE(0, child);
	if (child == 0) {
		const struct landlock_ruleset_attr ruleset_attr = {
			.scoped = LANDLOCK_SCOPE_SIGNAL,
		};
		int ruleset_fd;

		/* Add filesystem restrictions. */
		ruleset_fd = landlock_create_ruleset(&ruleset_attr,
						     sizeof(ruleset_attr), 0);
		ASSERT_LE(0, ruleset_fd);
		EXPECT_EQ(0, prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
		ASSERT_EQ(0, landlock_restrict_self(ruleset_fd,
						    variant->restrict_flags));
		EXPECT_EQ(0, close(ruleset_fd));

		/* First signal checks to test log entries. */
		EXPECT_EQ(-1, kill(getppid(), 0));
		EXPECT_EQ(EPERM, errno);

		if (variant->restrict_flags &
		    LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF) {
			EXPECT_EQ(-EAGAIN, matches_log_signal(
						   _metadata, self->audit_fd,
						   getppid(), self->domain_id));
			EXPECT_EQ(*self->domain_id, 1);
		} else {
			__u64 domain_id_allocated;

			EXPECT_EQ(0, matches_log_signal(
					     _metadata, self->audit_fd,
					     getppid(), self->domain_id));

			/* Checks domain information records. */
			EXPECT_EQ(0, matches_log_domain_allocated(
					     _metadata, self->audit_fd,
					     &domain_id_allocated));
			EXPECT_NE(*self->domain_id, 1);
			EXPECT_NE(*self->domain_id, 0);
			EXPECT_EQ(*self->domain_id, domain_id_allocated);
		}

		/* Second signal checks to test audit_count_records(). */
		EXPECT_EQ(-1, kill(getppid(), 0));
		EXPECT_EQ(EPERM, errno);

		/* Makes sure there is no superfluous logged records. */
		audit_count_records(self->audit_fd, &records);
		if (variant->restrict_flags &
		    LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF) {
			EXPECT_EQ(0, records.access);
		} else {
			EXPECT_EQ(1, records.access);
		}
		EXPECT_EQ(0, records.domain);

		/* Updates filter rules to match the drop record. */
		set_cap(_metadata, CAP_AUDIT_CONTROL);
		EXPECT_EQ(0, audit_filter_drop(self->audit_fd, AUDIT_ADD_RULE));
		EXPECT_EQ(0,
			  audit_filter_exe(self->audit_fd, &self->audit_filter,
					   AUDIT_DEL_RULE));
		clear_cap(_metadata, CAP_AUDIT_CONTROL);

		_exit(_metadata->exit_code);
		return;
	}

	ASSERT_EQ(child, waitpid(child, &status, 0));
	if (WIFSIGNALED(status) || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != EXIT_SUCCESS)
		_metadata->exit_code = KSFT_FAIL;

	if (variant->restrict_flags &
	    LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF) {
		EXPECT_EQ(-EAGAIN, matches_log_domain_deallocated(
					   _metadata, self->audit_fd, 0,
					   &domain_id_deallocated));
		EXPECT_EQ(domain_id_deallocated, 2);
	} else {
		// FIXME: Even if we waited for the child, the following call always
		// return -EAGAIN on some environments unless we call sleep(1).
		// Any idea how to avoid that?
		EXPECT_EQ(0, matches_log_domain_deallocated(
				     _metadata, self->audit_fd, 2,
				     &domain_id_deallocated));
		EXPECT_NE(domain_id_deallocated, 2);
		EXPECT_NE(domain_id_deallocated, 0);
		EXPECT_EQ(domain_id_deallocated, *self->domain_id);
	}
}

TEST_HARNESS_MAIN
