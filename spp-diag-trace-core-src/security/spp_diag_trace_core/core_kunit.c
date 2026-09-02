/* SPDX-License-Identifier: GPL-2.0-only */

#include <kunit/test.h>
#include <linux/irqflags.h>
#include <linux/string.h>

#include "core.h"

static const u8 k_zero_id[32];

static void init_process_context(struct kunit *test)
{
	u8 ident[32];
	int i;

	spp_diag_trace_core_reset();
	for (i = 0; i < 32; i++)
		ident[i] = (u8)i;
	KUNIT_ASSERT_EQ(test,
			spp_diag_trace_core_init(ident, ident, ident, ident),
			WIRE_OK);
	KUNIT_EXPECT_EQ(test, spp_diag_trace_core_is_green(), 1);
}

static void append_and_query_irqs_disabled(struct kunit *test)
{
	unsigned long flags;
	u8 ident[32];
	int green;
	int rc;

	spp_diag_trace_core_reset();
	memset(ident, 0xa5, sizeof(ident));
	KUNIT_ASSERT_EQ(test,
			spp_diag_trace_core_init(ident, ident, ident, ident),
			WIRE_OK);
	local_irq_save(flags);
	green = spp_diag_trace_core_is_green();
	rc = spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0, 0,
					0, SPP_DIAG_TRACE_PHASE_SEALED, NULL,
					0);
	local_irq_restore(flags);
	KUNIT_EXPECT_EQ(test, green, 1);
	KUNIT_EXPECT_EQ(test, rc, WIRE_OK);
}

static void mark_failure_irqs_disabled(struct kunit *test)
{
	unsigned long flags;
	int rc;
	int green;
	int append_rc;

	spp_diag_trace_core_reset();
	KUNIT_ASSERT_EQ(test,
			spp_diag_trace_core_init(k_zero_id, k_zero_id,
						 k_zero_id, k_zero_id),
			WIRE_OK);
	local_irq_save(flags);
	rc = spp_diag_trace_core_mark_failure(WIRE_CAP);
	green = spp_diag_trace_core_is_green();
	append_rc = spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0,
					       0, 0, 0,
					       SPP_DIAG_TRACE_PHASE_SEALED,
					       NULL, 0);
	local_irq_restore(flags);
	KUNIT_EXPECT_EQ(test, rc, WIRE_CAP);
	KUNIT_EXPECT_EQ(test, green, 0);
	KUNIT_EXPECT_EQ(test, append_rc, WIRE_CAP);
}

static struct kunit_case spp_diag_trace_core_cases[] = {
	KUNIT_CASE(init_process_context),
	KUNIT_CASE(append_and_query_irqs_disabled),
	KUNIT_CASE(mark_failure_irqs_disabled),
	{}
};

static struct kunit_suite spp_diag_trace_core_suite = {
	.name = "spp_diag_trace_core",
	.test_cases = spp_diag_trace_core_cases,
};

kunit_test_suite(spp_diag_trace_core_suite);
