/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/ima.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/panic.h>
#include <linux/sched.h>
#include <linux/spp_diag_trace_bootstrap.h>
#include <linux/spp_diag_trace_runtime.h>
#include "protocol_constants.h"
#include "runtime_types.h"
#include "core.h"

#define ASSERT(cond, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL: %s (%s:%d): %s\n", __func__, __FILE__, __LINE__, msg); \
			exit(1); \
		} \
	} while (0)

static const char valid_command_line[] =
	"ima_policy=critical_data "
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static void setup_published_runtime(struct task_struct **out_root)
{
	spp_diag_trace_core_reset();
	host_kmod_reset();
	host_ima_reset();
	host_current_task.pid = 1;
	host_current_task.tgid = 1;
	host_current_task.flags = 0;
	host_saved_command_line_set(valid_command_line);

	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();
	ASSERT(spp_diag_trace_runtime_init() == 0, "runtime init");
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_release();
	ASSERT(spp_diag_trace_runtime_ready() == 1, "runtime ready");
	ASSERT(spp_diag_trace_core_is_green() == 1, "green after release");
	if (out_root)
		*out_root = &host_current_task;
}

static struct task_struct g_child_ts[4096];

static void test_task_capacity_boundary(void)
{
	struct task_struct *root_ts = NULL;
	struct spp_diag_trace_fact_task_alloc alloc_fact = { .clone_flags = 0x11 };
	struct spp_diag_trace_fact_task_created created_fact;
	size_t needed = 0;
	int rc;

	setup_published_runtime(&root_ts);
	ASSERT(root_ts != NULL, "root task initialized");

	/* Create 4095 children: brings total live tasks to exactly 4096 (root + 4095) */
	for (size_t i = 0; i < 4095; i++) {
		memset(&g_child_ts[i], 0, sizeof(g_child_ts[i]));
		g_child_ts[i].pid = (u32)(2000 + i);
		g_child_ts[i].tgid = (u32)(2000 + i);

		rc = spp_diag_trace_runtime_task_alloc_attempt(root_ts, &alloc_fact);
		ASSERT(rc == 0, "child task alloc attempt");

		created_fact.pid = g_child_ts[i].pid;
		created_fact.tgid = g_child_ts[i].tgid;
		created_fact.clone_flags = 0x11;

		rc = spp_diag_trace_runtime_task_created(root_ts, &g_child_ts[i], &created_fact);
		ASSERT(rc == 0, "child task created");
	}

	ASSERT(spp_diag_trace_core_is_green() == 1, "core remains green with exactly 4096 live tasks");

	/* Attempt to allocate 4097th task: must fail with WIRE_CAP */
	rc = spp_diag_trace_runtime_task_alloc_attempt(root_ts, &alloc_fact);
	ASSERT(rc == WIRE_CAP, "4097th task allocation returns WIRE_CAP");
	ASSERT(spp_diag_trace_core_is_green() == 0, "core transitions to sticky red after task overflow");

	/* Confirm stream snapshot length queries properly report preserved stream */
	rc = spp_diag_trace_core_snapshot(NULL, 0, &needed);
	ASSERT(rc == WIRE_NULL, "snapshot length query returns WIRE_NULL");
	ASSERT(needed > sizeof(struct spp_diag_trace_core_snapshot), "stream data preserved across breach");

	printf("PASS: test_task_capacity_boundary (4096 live tasks admitted, 4097th rejected with WIRE_CAP)\n");
}

static void test_operation_capacity_boundary(void)
{
	struct task_struct *root_ts = NULL;
	u64 op_ord = 0;
	size_t needed = 0;
	int rc;

	setup_published_runtime(&root_ts);
	ASSERT(root_ts != NULL, "root task initialized");

	/* Next op ordinal starts at 2 (op 1 was pre-release denied) */
	/* We open and close 32,768 operations on root_ts (slots 0..32767) */
	for (size_t j = 0; j < 32768; j++) {
		rc = spp_diag_trace_core_runtime_open_operation(1, SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN, &op_ord);
		ASSERT(rc == 0, "operation open within capacity");
		ASSERT(op_ord == 2 + j, "op_ord matches expected sequence");

		rc = spp_diag_trace_core_runtime_close_operation(1, op_ord, SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN);
		ASSERT(rc == 0, "operation close within capacity");
	}

	ASSERT(spp_diag_trace_core_is_green() == 1, "core remains green with exactly 32768 operations recorded");

	/* Attempt 32,769th operation: must fail with WIRE_CAP */
	rc = spp_diag_trace_core_runtime_open_operation(1, SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN, &op_ord);
	ASSERT(rc == WIRE_CAP, "32769th operation open returns WIRE_CAP");
	ASSERT(spp_diag_trace_core_is_green() == 0, "core transitions to sticky red after op overflow");

	/* Confirm stream snapshot length query preserves earlier data */
	rc = spp_diag_trace_core_snapshot(NULL, 0, &needed);
	ASSERT(rc == WIRE_NULL, "snapshot length query returns WIRE_NULL");
	ASSERT(needed > sizeof(struct spp_diag_trace_core_snapshot), "stream data preserved across breach");

	printf("PASS: test_operation_capacity_boundary (32768 operations admitted, 32769th rejected with WIRE_CAP)\n");
}

static void test_custom_capacity_boundary_twin(void)
{
	static struct spp_diag_trace_task_record small_tasks[4];
	static struct spp_diag_trace_operation_record small_ops[8];
	u8 ready_buf[SPP_DIAG_TRACE_IMA_SIZE];
	u8 release_buf[SPP_DIAG_TRACE_IMA_SIZE];
	struct task_struct root_ts = { .pid = 1, .tgid = 1 };
	struct task_struct c1 = { .pid = 2, .tgid = 2 };
	struct task_struct c2 = { .pid = 3, .tgid = 3 };
	struct task_struct c3 = { .pid = 4, .tgid = 4 };
	int rc;

	spp_diag_trace_core_reset();
	memset(small_tasks, 0, sizeof(small_tasks));
	memset(small_ops, 0, sizeof(small_ops));

	ASSERT(spp_diag_trace_core_init((const u8 *)"12345678901234567890123456789012",
					(const u8 *)"12345678901234567890123456789012",
					(const u8 *)"12345678901234567890123456789012",
					(const u8 *)"12345678901234567890123456789012") == 0, "core init");
	ASSERT(spp_diag_trace_core_runtime_install_arrays(small_tasks, 4, small_ops, 8) == 0, "install small arrays");
	ASSERT(spp_diag_trace_core_bootstrap_ima_available() == 0, "ima available");
	ASSERT(spp_diag_trace_core_bootstrap_gate(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH,
						  strlen(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH),
						  1, 1) == -EACCES, "canary");
	ASSERT(spp_diag_trace_core_bootstrap_prepare_ready(ready_buf) == 0, "ready");
	ASSERT(spp_diag_trace_core_bootstrap_ready_measured() == 0, "ready measured");
	ASSERT(spp_diag_trace_core_bootstrap_prepare_release(1, 1, release_buf) == 0, "release");
	ASSERT(spp_diag_trace_core_bootstrap_release_measured() == 0, "release measured");
	ASSERT(spp_diag_trace_core_bootstrap_publish() == 0, "publish");
	ASSERT(spp_diag_trace_core_runtime_bind_root(&root_ts) == 0, "bind root");

	/* Task 2 */
	ASSERT(spp_diag_trace_core_runtime_task_alloc_attempt(&root_ts, 0) == 0, "alloc c1");
	ASSERT(spp_diag_trace_core_runtime_task_created(&root_ts, &c1, 2, 2, 0) == 0, "created c1");

	/* Task 3 */
	ASSERT(spp_diag_trace_core_runtime_task_alloc_attempt(&root_ts, 0) == 0, "alloc c2");
	ASSERT(spp_diag_trace_core_runtime_task_created(&root_ts, &c2, 3, 3, 0) == 0, "created c2");

	/* Task 4 (exactly 4 live tasks) */
	ASSERT(spp_diag_trace_core_runtime_task_alloc_attempt(&root_ts, 0) == 0, "alloc c3");
	ASSERT(spp_diag_trace_core_runtime_task_created(&root_ts, &c3, 4, 4, 0) == 0, "created c3");

	ASSERT(spp_diag_trace_core_is_green() == 1, "green with 4/4 tasks");

	/* Task 5 (exceeds cap=4) */
	rc = spp_diag_trace_core_runtime_task_alloc_attempt(&root_ts, 0);
	ASSERT(rc == WIRE_CAP, "5th task allocation returns WIRE_CAP on cap=4");
	ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red on custom cap overflow");

	printf("PASS: test_custom_capacity_boundary_twin\n");
}

int main(void)
{
	test_task_capacity_boundary();
	test_operation_capacity_boundary();
	test_custom_capacity_boundary_twin();
	printf("All runtime capacity boundary tests passed successfully.\n");
	return 0;
}
