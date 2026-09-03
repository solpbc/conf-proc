/* SPDX-License-Identifier: GPL-2.0-only */

#include <kunit/test.h>

#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/spp_diag_trace_bootstrap.h>

#include "core.h"

static const char valid_command_line[] =
	"ima_policy=critical_data "
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static void parser_contract(struct kunit *test)
{
	u8 challenge[32], run[32], control[32];
	const char invalid[] =
		"ima_policy=critical_data ima_policy=critical_data "
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
		"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
		"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

	KUNIT_EXPECT_EQ(test,
		spp_diag_trace_bootstrap_test_parse(valid_command_line,
						    strlen(valid_command_line),
						    challenge, run, control),
		0);
	KUNIT_EXPECT_TRUE(test,
		spp_diag_trace_bootstrap_test_parse(invalid, strlen(invalid),
						    challenge, run, control) != 0);
}

static void production_gate_transitions(struct kunit *test)
{
	u8 ids[32] = { 0 };
	struct spp_diag_trace_core_snapshot first;
	struct spp_diag_trace_core_snapshot second;
	u8 snapshot_buffer[8192];
	size_t required;

	spp_diag_trace_core_reset();
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_init(ids, ids, ids, ids), 0);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_bootstrap_ima_available(), 0);
	KUNIT_EXPECT_EQ(test,
		spp_diag_trace_core_bootstrap_gate(
			SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH,
			strlen(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH), 41, 41),
		-EACCES);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_snapshot(snapshot_buffer,
						       sizeof(snapshot_buffer),
						       &required), 0);
	memcpy(&first, snapshot_buffer, sizeof(first));
	KUNIT_EXPECT_EQ(test, first.frame_count, 2ULL);
	KUNIT_EXPECT_EQ(test, first.bootstrap_denial_count, 1ULL);
	KUNIT_EXPECT_EQ(test,
		spp_diag_trace_core_bootstrap_gate(
			SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH,
			strlen(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH), 41, 41),
		-EACCES);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_snapshot(snapshot_buffer,
						       sizeof(snapshot_buffer),
						       &required), 0);
	memcpy(&second, snapshot_buffer, sizeof(second));
	KUNIT_EXPECT_TRUE(test, second.failed);
	KUNIT_EXPECT_EQ(test, second.frame_count, first.frame_count);
}

static void checkpoint_transitions(struct kunit *test)
{
	u8 ids[32] = { 0 };
	u8 ready[SPP_DIAG_TRACE_IMA_SIZE];
	u8 released[SPP_DIAG_TRACE_IMA_SIZE];

	spp_diag_trace_core_reset();
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_init(ids, ids, ids, ids), 0);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_bootstrap_ima_available(), 0);
	KUNIT_EXPECT_EQ(test,
		spp_diag_trace_core_bootstrap_gate(
			SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH,
			strlen(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH), 41, 41),
		-EACCES);
	KUNIT_ASSERT_EQ(test,
		spp_diag_trace_core_bootstrap_prepare_ready(ready), 0);
	KUNIT_EXPECT_TRUE(test, !memcmp(ready, "SPPIMA1\0", 8));
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_bootstrap_ready_measured(), 0);
	KUNIT_ASSERT_EQ(test,
		spp_diag_trace_core_bootstrap_prepare_release(1, 1, released), 0);
	KUNIT_EXPECT_TRUE(test, memcmp(ready + 188, released + 188, 32) != 0);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_bootstrap_release_measured(), 0);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_bootstrap_publish(), 0);
	KUNIT_EXPECT_EQ(test,
		spp_diag_trace_core_bootstrap_gate("/after", 6, 1, 1), 0);
}

static struct kunit_case spp_diag_trace_core_bootstrap_cases[] = {
	KUNIT_CASE(parser_contract),
	KUNIT_CASE(production_gate_transitions),
	KUNIT_CASE(checkpoint_transitions),
	{}
};

static struct kunit_suite spp_diag_trace_core_bootstrap_suite = {
	.name = "spp_diag_trace_core_bootstrap",
	.test_cases = spp_diag_trace_core_bootstrap_cases,
};

kunit_test_suite(spp_diag_trace_core_bootstrap_suite);
