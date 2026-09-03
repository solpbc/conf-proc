/* SPDX-License-Identifier: GPL-2.0-only */

#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/ima.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/panic.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/spp_diag_trace_bootstrap.h>
#include <linux/spp_diag_trace_runtime.h>
#include <linux/vmalloc.h>

#include "core.h"
#include "runtime_types.h"

static const char valid_command_line[] =
	"ima_policy=critical_data "
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static int failures;

#define CHECK(condition, name) do { \
	if (!(condition)) { \
		fprintf(stderr, "FAIL %s\n", name); \
		failures++; \
	} \
} while (0)

static void reset_all(void)
{
	spp_diag_trace_core_reset();
	host_kmod_reset();
	host_ima_reset();
	host_current_task.pid = 1;
	host_current_task.tgid = 1;
	host_current_task.flags = 0;
	host_saved_command_line_set(valid_command_line);
}

static void test_target_sizes(void)
{
	size_t task_sz = sizeof(struct spp_diag_trace_task_record);
	size_t op_sz = sizeof(struct spp_diag_trace_operation_record);
	size_t total_tasks_bytes = (size_t)SPP_DIAG_TRACE_RUNTIME_MAX_TASKS * task_sz;
	size_t total_ops_bytes = (size_t)SPP_DIAG_TRACE_RUNTIME_MAX_OPERATIONS * op_sz;
	size_t total_bookkeeping = total_tasks_bytes + total_ops_bytes;
	size_t limit_16mib = 16 * 1024 * 1024;

	printf("Target sizes:\n");
	printf("  task record: %zu bytes (total %zu tasks = %zu bytes / %.2f KiB)\n",
	       task_sz, (size_t)SPP_DIAG_TRACE_RUNTIME_MAX_TASKS,
	       total_tasks_bytes, (double)total_tasks_bytes / 1024.0);
	printf("  operation record: %zu bytes (total %zu ops = %zu bytes / %.2f KiB)\n",
	       op_sz, (size_t)SPP_DIAG_TRACE_RUNTIME_MAX_OPERATIONS,
	       total_ops_bytes, (double)total_ops_bytes / 1024.0);
	printf("  total bookkeeping: %zu bytes (%.2f KiB / %.2f MiB)\n",
	       total_bookkeeping, (double)total_bookkeeping / 1024.0,
	       (double)total_bookkeeping / (1024.0 * 1024.0));

	CHECK(total_bookkeeping <= limit_16mib, "bookkeeping fits within 16 MiB");
}

static void test_runtime_bootstrap_and_root_bind(void)
{
	reset_all();

	/* 1. Core init and IMA ready */
	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();

	/* 2. Runtime init (allocates bookkeeping arrays) */
	CHECK(spp_diag_trace_runtime_init() == 0, "runtime init succeeds");
	CHECK(spp_diag_trace_runtime_ready(), "runtime is ready after init");

	/* 3. Release sequence */
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_release();

	/* Core must be green after successful release and root bind */
	CHECK(spp_diag_trace_core_is_green() == 1, "core is green after release + root bind");
}

static void test_runtime_not_ready_fails_release(void)
{
	jmp_buf panic_env;

	reset_all();

	/* 1. Core init and IMA ready without runtime init */
	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();

	/* Ensure runtime is NOT ready */
	CHECK(!spp_diag_trace_runtime_ready(), "runtime is not ready");

	/* 2. Release sequence should fail because runtime is not ready */
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_release();
		CHECK(0, "runtime not ready release panics");
	}
	host_panic_disarm();

	/* Core must have latched failure */
	CHECK(spp_diag_trace_core_is_green() == 0, "core failed when runtime not ready");
}

static void test_runtime_registration_failure_is_not_ready(void)
{
	reset_all();
	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();
	host_securityfs_set_fail_dir(1);

	CHECK(spp_diag_trace_runtime_init() != 0, "runtime registration failure returns error");
	CHECK(!spp_diag_trace_runtime_ready(), "registration failure leaves runtime not ready");
	CHECK(spp_diag_trace_core_is_green() == 0, "registration failure is sticky red");
}

int main(void)
{
	printf("=== Running conf-proc SPP diagnostic trace core runtime selftest ===\n");
	test_target_sizes();
	test_runtime_bootstrap_and_root_bind();
	test_runtime_not_ready_fails_release();
	test_runtime_registration_failure_is_not_ready();

	if (failures == 0) {
		printf("All runtime selftest checks passed successfully.\n");
		return 0;
	}
	fprintf(stderr, "%d checks failed.\n", failures);
	return 1;
}
