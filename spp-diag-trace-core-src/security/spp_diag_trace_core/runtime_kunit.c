/* SPDX-License-Identifier: GPL-2.0-only */

#include <kunit/test.h>

#include <linux/errno.h>
#include <linux/ima.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/spp_diag_trace_bootstrap.h>
#include <linux/spp_diag_trace_runtime.h>

#include "core.h"
#include "protocol_constants.h"

static const char valid_command_line[] =
	"ima_policy=critical_data "
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static const u8 expected_challenge[32] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static const u8 expected_run_id[32] = {
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
	0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
};

static const u8 expected_control_plan[32] = {
	0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
	0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
};

static void init_and_publish_runtime(void)
{
	spp_diag_trace_core_reset();
	spp_diag_trace_core_set_op_caps(SPP_DIAG_TRACE_MAX_FRAMES, SPP_DIAG_TRACE_MAX_STREAM_BYTES);
	host_kmod_reset();
	host_ima_reset();
	host_securityfs_reset();
	host_current_task.pid = 1;
	host_current_task.tgid = 1;
	host_current_task.flags = 0;
	host_current_task_ptr = NULL;
	host_saved_command_line_set(valid_command_line);

	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();
	spp_diag_trace_runtime_init();
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_release();
}

static void build_command(u8 *buf, u16 kind, u16 requested_phase)
{
	static const u8 magic[8] = { SPP_DIAG_TRACE_MAGIC_COMMAND_BYTES };

	memset(buf, 0, SPP_DIAG_TRACE_COMMAND_SIZE);
	memcpy(buf + 0, magic, 8);
	buf[8] = 0; buf[9] = 1; /* version = 1 */
	buf[10] = (u8)(kind >> 8); buf[11] = (u8)(kind & 0xff); /* kind */
	buf[12] = 0; buf[13] = 0; buf[14] = 0; buf[15] = 128; /* length = 128 */
	memcpy(buf + 16, expected_challenge, 32);
	memcpy(buf + 48, expected_run_id, 32);
	memcpy(buf + 80, expected_control_plan, 32);
	buf[112] = (u8)(requested_phase >> 8); buf[113] = (u8)(requested_phase & 0xff);
}

static void runtime_root_binding(struct kunit *test)
{
	struct spp_diag_trace_task_record tr;

	init_and_publish_runtime();
	KUNIT_ASSERT_EQ(test, spp_diag_trace_core_test_get_task_record(0, &tr), 0);
	KUNIT_EXPECT_EQ(test, tr.task_ordinal, (u64)1);
	KUNIT_EXPECT_EQ(test, tr.mint_phase, (u16)SPP_DIAG_TRACE_PHASE_INIT);
	KUNIT_EXPECT_TRUE(test, spp_diag_trace_core_is_green() != 0);
}

static void runtime_task_lifecycle(struct kunit *test)
{
	struct task_struct child_task = { .flags = 0 };
	struct spp_diag_trace_fact_task_alloc alloc_fact = { .clone_flags = 0 };
	struct spp_diag_trace_fact_task_created created_fact = {
		.pid = 10,
		.tgid = 10,
		.clone_flags = 0,
	};

	init_and_publish_runtime();
	KUNIT_ASSERT_EQ(test, spp_diag_trace_runtime_task_alloc_attempt(&host_current_task, &alloc_fact), 0);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_runtime_task_created(&host_current_task, &child_task, &created_fact), 0);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_runtime_task_exit(&child_task, 0), 0);
	KUNIT_EXPECT_TRUE(test, spp_diag_trace_core_is_green() != 0);
}

static void runtime_exec_lifecycle(struct kunit *test)
{
	struct spp_diag_trace_fact_exec_attempt attempt_fact = {
		.path = "/bin/init",
		.path_len = 9,
		.pid = 1,
		.tgid = 1,
	};
	struct spp_diag_trace_fact_exec_commit commit_fact = {
		.pid = 1,
		.tgid = 1,
	};

	init_and_publish_runtime();
	KUNIT_ASSERT_EQ(test, spp_diag_trace_runtime_exec_attempt(&host_current_task, &attempt_fact), 0);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_runtime_exec_commit(&host_current_task, &commit_fact), 0);
	KUNIT_ASSERT_EQ(test, spp_diag_trace_runtime_operation_return(&host_current_task, 2, 0), 0);
	KUNIT_EXPECT_TRUE(test, spp_diag_trace_core_is_green() != 0);
}

static void runtime_securityfs_control(struct kunit *test)
{
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	u16 phase;

	init_and_publish_runtime();
	for (phase = 2; phase <= 14; phase++) {
		build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, phase);
		KUNIT_ASSERT_EQ(test, spp_diag_trace_core_runtime_handle_command(cmd, sizeof(cmd)), 0);
	}
	KUNIT_EXPECT_EQ(test, spp_diag_trace_core_runtime_is_sealed(), 0);
}

static void kthread_exit_sealing_hook(const struct host_ima_call *call)
{
	struct task_struct untracked_kthread = { .flags = PF_KTHREAD, .pid = 60, .tgid = 60 };
	(void)call;
	(void)spp_diag_trace_runtime_task_exit(&untracked_kthread, 0);
}

static void runtime_sealing_kthread_race(struct kunit *test)
{
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	u16 phase;
	int ret;

	init_and_publish_runtime();
	for (phase = 2; phase <= 14; phase++) {
		build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, phase);
		KUNIT_ASSERT_EQ(test, spp_diag_trace_core_runtime_handle_command(cmd, sizeof(cmd)), 0);
	}

	host_ima_set_hook(kthread_exit_sealing_hook);

	build_command(cmd, SPP_DIAG_TRACE_CMD_SEAL, 15);
	ret = spp_diag_trace_core_runtime_handle_command(cmd, sizeof(cmd));
	host_ima_set_hook(NULL);

	KUNIT_EXPECT_TRUE(test, ret < 0);
	KUNIT_EXPECT_EQ(test, spp_diag_trace_core_is_green(), 0);
	KUNIT_EXPECT_EQ(test, spp_diag_trace_core_runtime_is_sealed(), 0);
}

static struct kunit_case spp_diag_trace_core_runtime_cases[] = {
	KUNIT_CASE(runtime_root_binding),
	KUNIT_CASE(runtime_task_lifecycle),
	KUNIT_CASE(runtime_exec_lifecycle),
	KUNIT_CASE(runtime_securityfs_control),
	KUNIT_CASE(runtime_sealing_kthread_race),
	{}
};

static struct kunit_suite spp_diag_trace_core_runtime_suite = {
	.name = "spp_diag_trace_core_runtime",
	.test_cases = spp_diag_trace_core_runtime_cases,
};

kunit_test_suite(spp_diag_trace_core_runtime_suite);
