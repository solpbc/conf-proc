/* SPDX-License-Identifier: GPL-2.0-only */

#include <kunit/test.h>
#include <linux/irqflags.h>
#include <linux/string.h>

#include "core.h"

static const u8 k_zero_id[32];

static void init_with_irqs_disabled(struct kunit *test)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	unsigned long flags;
	u8 ident[32];
	int i;

	memset(&core, 0, sizeof(core));
	for (i = 0; i < 32; i++)
		ident[i] = (u8)i;
	local_irq_save(flags);
	KUNIT_ASSERT_EQ(test,
			spp_diag_trace_core_init(&core, ident, ident, ident, ident),
			WIRE_OK);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_snapshot(&core, &snap), WIRE_OK);
	local_irq_restore(flags);
	KUNIT_EXPECT_EQ(test, snap.initialized, 1);
	KUNIT_EXPECT_EQ(test, snap.failed, 0);
	KUNIT_EXPECT_EQ(test, snap.frame_count, 1ull);
	KUNIT_EXPECT_EQ(test, snap.sequence, 1ull);
}

static void append_and_query_irqs_disabled(struct kunit *test)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	unsigned long flags;
	u8 ident[32];
	int rc;

	memset(&core, 0, sizeof(core));
	memset(ident, 0xa5, sizeof(ident));
	KUNIT_ASSERT_EQ(test,
			spp_diag_trace_core_init(&core, ident, ident, ident, ident),
			WIRE_OK);
	local_irq_save(flags);
	rc = spp_diag_trace_core_append(&core,
					SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0, 0, 0,
					SPP_DIAG_TRACE_PHASE_SEALED, NULL, 0);
	KUNIT_EXPECT_EQ(test, rc, WIRE_OK);
	KUNIT_EXPECT_EQ(test, spp_diag_trace_core_snapshot(&core, &snap), WIRE_OK);
	local_irq_restore(flags);
	KUNIT_EXPECT_EQ(test, snap.frame_count, 2ull);
	KUNIT_EXPECT_EQ(test, snap.failed, 0);
}

static void mark_failure_irqs_disabled(struct kunit *test)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	unsigned long flags;
	int rc;

	memset(&core, 0, sizeof(core));
	KUNIT_ASSERT_EQ(test,
			spp_diag_trace_core_init(&core, k_zero_id, k_zero_id,
						 k_zero_id, k_zero_id),
			WIRE_OK);
	local_irq_save(flags);
	rc = spp_diag_trace_core_mark_failure(&core, WIRE_CAP);
	KUNIT_EXPECT_EQ(test, rc, WIRE_CAP);
	KUNIT_EXPECT_EQ(test, spp_diag_trace_core_snapshot(&core, &snap), WIRE_OK);
	rc = spp_diag_trace_core_append(&core,
					SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0, 0, 0,
					SPP_DIAG_TRACE_PHASE_SEALED, NULL, 0);
	local_irq_restore(flags);
	KUNIT_EXPECT_EQ(test, rc, WIRE_CAP);
	KUNIT_EXPECT_EQ(test, snap.failed, 1);
	KUNIT_EXPECT_EQ(test, snap.reason, WIRE_CAP);
	KUNIT_EXPECT_EQ(test, snap.initialized, 1);
}

static struct kunit_case spp_diag_trace_core_cases[] = {
	KUNIT_CASE(init_with_irqs_disabled),
	KUNIT_CASE(append_and_query_irqs_disabled),
	KUNIT_CASE(mark_failure_irqs_disabled),
	{}
};

static struct kunit_suite spp_diag_trace_core_suite = {
	.name = "spp_diag_trace_core",
	.test_cases = spp_diag_trace_core_cases,
};

kunit_test_suite(spp_diag_trace_core_suite);
