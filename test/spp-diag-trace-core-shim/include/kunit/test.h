/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef SPP_DIAG_TRACE_CORE_SHIM_KUNIT_TEST_H
#define SPP_DIAG_TRACE_CORE_SHIM_KUNIT_TEST_H

#include <stdio.h>

struct kunit {
	unsigned int failures;
};

struct kunit_case {
	void (*run_case)(struct kunit *test);
};

struct kunit_suite {
	const char *name;
	struct kunit_case *test_cases;
};

#define KUNIT_CASE(fn) { .run_case = fn }
#define kunit_test_suite(suite)

#define KUNIT_EXPECT_TRUE(test, condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "KUnit expectation failed: %s\\n", #condition); \
		(test)->failures++; \
	} \
} while (0)

#define KUNIT_EXPECT_EQ(test, left, right) do { \
	if ((left) != (right)) { \
		fprintf(stderr, "KUnit equality failed: %s == %s\\n", #left, #right); \
		(test)->failures++; \
	} \
} while (0)

#define KUNIT_ASSERT_EQ(test, left, right) do { \
	if ((left) != (right)) { \
		fprintf(stderr, "KUnit assertion failed: %s == %s\\n", #left, #right); \
		(test)->failures++; \
		return; \
	} \
} while (0)

#endif
