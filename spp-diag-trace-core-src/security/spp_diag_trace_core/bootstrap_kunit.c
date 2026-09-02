/* SPDX-License-Identifier: GPL-2.0-only */

#include <kunit/test.h>

#include <linux/string.h>
#include <linux/spp_diag_trace_bootstrap.h>

#include "core.h"

#ifdef SPP_DIAG_TRACE_CORE_HOST_TEST
#include <setjmp.h>

#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/panic.h>
#include <linux/sched.h>
static const char valid_command_line[] =
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static void reset_bootstrap_test(void)
{
	spp_diag_trace_core_reset();
	spp_diag_trace_bootstrap_test_reset();
	spp_diag_trace_bootstrap_gate_test_reset();
	host_current_task.pid = 101;
	host_current_task.tgid = 101;
	host_saved_command_line_set(valid_command_line);
}

static void parser_rejects_invalid_identity(struct kunit *test)
{
	static const char *const invalid[] = {
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1A sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"sol_spp_diag.unknown=00 sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"-- sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
	};
	size_t i;

	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		jmp_buf panic_env;

		reset_bootstrap_test();
		host_saved_command_line_set(invalid[i]);
		host_panic_arm(&panic_env);
		if (!setjmp(panic_env)) {
			spp_diag_trace_bootstrap_init();
			KUNIT_EXPECT_TRUE(test, false);
		}
		host_panic_disarm();
		KUNIT_EXPECT_TRUE(test, host_panic_message() != NULL);
	}
	reset_bootstrap_test();
	spp_diag_trace_bootstrap_init();
	KUNIT_EXPECT_EQ(test, spp_diag_trace_core_is_green(), 1);
}

static void gate_denies_before_release(struct kunit *test)
{
	struct linux_binprm bprm = { .filename = "/kunit-gate" };
	struct spp_diag_trace_core_snapshot first;
	struct spp_diag_trace_core_snapshot second;
	u8 snapshot_buffer[8192];
	size_t required;

	reset_bootstrap_test();
	spp_diag_trace_bootstrap_init();
	KUNIT_EXPECT_EQ(test, spp_diag_trace_bootstrap_bprm_check(&bprm), -EACCES);
	KUNIT_EXPECT_EQ(test, spp_diag_trace_bootstrap_denial_count(), 1L);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_snapshot(snapshot_buffer,
						       sizeof(snapshot_buffer),
						       &required), 0);
	memcpy(&first, snapshot_buffer, sizeof(first));
	KUNIT_EXPECT_EQ(test, first.frame_count, 2ULL);
	KUNIT_EXPECT_EQ(test, spp_diag_trace_bootstrap_bprm_check(&bprm), -EACCES);
	KUNIT_EXPECT_EQ(test, spp_diag_trace_bootstrap_denial_count(), 2L);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_snapshot(snapshot_buffer,
						       sizeof(snapshot_buffer),
						       &required), 0);
	memcpy(&second, snapshot_buffer, sizeof(second));
	KUNIT_EXPECT_EQ(test, second.frame_count, first.frame_count);
}

static void ima_record_matches_state(struct kunit *test)
{
	u8 record[256];
	struct linux_binprm bprm = { .filename = "/kunit-record" };

	reset_bootstrap_test();
	spp_diag_trace_bootstrap_init();
	KUNIT_ASSERT_EQ(test, spp_diag_trace_bootstrap_bprm_check(&bprm), -EACCES);
	spp_diag_trace_bootstrap_ima_record(SPP_DIAG_TRACE_IMA_KIND_READY, 1, record);
	KUNIT_EXPECT_TRUE(test, !memcmp(record, "SPPIMA1\0", 8));
	KUNIT_EXPECT_EQ(test, record[10], 0);
	KUNIT_EXPECT_EQ(test, record[11], SPP_DIAG_TRACE_IMA_KIND_READY);
	KUNIT_EXPECT_EQ(test, record[12], 0);
	KUNIT_EXPECT_EQ(test, record[13], 0);
	KUNIT_EXPECT_EQ(test, record[14], 1);
	KUNIT_EXPECT_EQ(test, record[15], 0);
	KUNIT_EXPECT_EQ(test, record[236], 0);
	KUNIT_EXPECT_EQ(test, record[243], 1);
}

#else

static void parser_rejects_invalid_identity(struct kunit *test)
{
	u8 record[SPP_DIAG_TRACE_IMA_SIZE];

	spp_diag_trace_bootstrap_ima_record(SPP_DIAG_TRACE_IMA_KIND_READY, 0,
					    record);
	KUNIT_EXPECT_EQ(test, record[0], 'S');
}

static void gate_denies_before_release(struct kunit *test)
{
	u8 record[SPP_DIAG_TRACE_IMA_SIZE];

	spp_diag_trace_bootstrap_ima_record(SPP_DIAG_TRACE_IMA_KIND_READY, 0,
					    record);
	KUNIT_EXPECT_EQ(test, record[10], 0);
}

static void ima_record_matches_state(struct kunit *test)
{
	u8 record[SPP_DIAG_TRACE_IMA_SIZE];

	spp_diag_trace_bootstrap_ima_record(SPP_DIAG_TRACE_IMA_KIND_READY, 1,
					    record);
	KUNIT_EXPECT_EQ(test, record[243], 1);
}

#endif

static struct kunit_case spp_diag_trace_core_bootstrap_cases[] = {
	KUNIT_CASE(parser_rejects_invalid_identity),
	KUNIT_CASE(gate_denies_before_release),
	KUNIT_CASE(ima_record_matches_state),
	{}
};

static struct kunit_suite spp_diag_trace_core_bootstrap_suite = {
	.name = "spp_diag_trace_core_bootstrap",
	.test_cases = spp_diag_trace_core_bootstrap_cases,
};

kunit_test_suite(spp_diag_trace_core_bootstrap_suite);
