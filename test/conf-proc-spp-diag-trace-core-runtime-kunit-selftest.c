/* SPDX-License-Identifier: GPL-2.0-only */

#include <kunit/test.h>

#include "../spp-diag-trace-core-src/security/spp_diag_trace_core/runtime_kunit.c"

int main(void)
{
	struct kunit_case *test_case;
	struct kunit test = { 0 };

	for (test_case = spp_diag_trace_core_runtime_suite.test_cases;
	     test_case->run_case; test_case++)
		test_case->run_case(&test);
	return test.failures ? 1 : 0;
}
