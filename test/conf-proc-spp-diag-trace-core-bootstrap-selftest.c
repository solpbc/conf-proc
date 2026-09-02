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
#include <linux/spp_diag_trace_bootstrap.h>

#include "core.h"

static const char valid_command_line[] =
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static int failures;

static int inject_ready_append(struct linux_binprm *bprm)
{
	int result = spp_diag_trace_bootstrap_bprm_check(bprm);

	spp_diag_trace_core_inject_fault(WIRE_STATE);
	return result;
}

#define CHECK(condition, name) do { \
	if (!(condition)) { \
		fprintf(stderr, "FAIL %s\\n", name); \
		failures++; \
	} \
} while (0)

static void reset_all(void)
{
	spp_diag_trace_core_reset();
	spp_diag_trace_bootstrap_test_reset();
	spp_diag_trace_bootstrap_gate_test_reset();
	host_kmod_reset();
	host_ima_reset();
	host_current_task.pid = 101;
	host_current_task.tgid = 101;
	host_saved_command_line_set(valid_command_line);
}

static u64 load_u64be(const u8 *value)
{
	return ((u64)value[0] << 56) | ((u64)value[1] << 48) |
		((u64)value[2] << 40) | ((u64)value[3] << 32) |
		((u64)value[4] << 24) | ((u64)value[5] << 16) |
		((u64)value[6] << 8) | value[7];
}

static int snapshot_now(struct spp_diag_trace_core_snapshot *snapshot)
{
	u8 buffer[4096];
	size_t size;

	if (spp_diag_trace_core_snapshot(buffer, sizeof(buffer), &size) ||
	    size < sizeof(*snapshot))
		return -1;
	memcpy(snapshot, buffer, sizeof(*snapshot));
	return 0;
}

static void check_ima_snapshot(const struct host_ima_call *ima,
			       const struct spp_diag_trace_core_snapshot *snapshot,
			       const char *name)
{
	CHECK(load_u64be(ima->record + 172) == snapshot->frame_count, name);
	CHECK(load_u64be(ima->record + 180) == snapshot->stream_byte_count, name);
	CHECK(!memcmp(ima->record + 188, snapshot->chain, 32), name);
}

static void test_happy_path(void)
{
	struct spp_diag_trace_core_snapshot snapshot;
	u8 snapshot_buffer[4096];
	size_t snapshot_size;
	const struct host_kmod_call *kmod;
	const struct host_ima_call *ima;
	u8 ready_record[256];

	reset_all();
	spp_diag_trace_bootstrap_init();
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_ima_ready();
	kmod = host_kmod_last_call();
	ima = host_ima_last_call();
	CHECK(kmod->calls == 1 && kmod->wait == UMH_WAIT_EXEC, "canary wait");
	CHECK(!strcmp(kmod->path, "/usr/local/libexec/solstone/pre-release-denied"),
	      "canary path");
	CHECK(ima->calls == 1 && ima->buf_len == 256 && !ima->hash &&
	      ima->digest == NULL && ima->digest_len == 0, "ready ima shape");
	CHECK(!strcmp(ima->event_label, "sol_spp_diag_trace") &&
	      !strcmp(ima->event_name, "sol-spp-diag-ready-v1"), "ready ima names");
	CHECK(!snapshot_now(&snapshot), "ready snapshot");
	check_ima_snapshot(ima, &snapshot, "ready IMA mirrors core snapshot");
	memcpy(ready_record, ima->record, sizeof(ready_record));
	spp_diag_trace_bootstrap_release();
	ima = host_ima_last_call();
	CHECK(ima->calls == 2 && !strcmp(ima->event_name, "sol-spp-diag-release-v1"),
	      "release ima");
	CHECK(spp_diag_trace_bootstrap_bprm_check(&(struct linux_binprm) {
		.filename = "/after-release" }) == 0, "release opens gate");
	CHECK(!spp_diag_trace_core_snapshot(snapshot_buffer, sizeof(snapshot_buffer),
				      &snapshot_size) &&
	      (memcpy(&snapshot, snapshot_buffer, sizeof(snapshot)), 1) &&
	      snapshot.frame_count == 4 && snapshot.sequence == 4, "four frame sequence");
	check_ima_snapshot(ima, &snapshot, "release IMA mirrors core snapshot");
	CHECK(memcmp(ready_record + 188, ima->record + 188, 32),
	      "ready and release chain differ");
}

static void test_parser_failure(void)
{
	static const char *const invalid[] = {
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
		"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
		"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
		"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1A "
		"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
		"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"sol_spp_diag.unknown=00 "
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
		"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
		"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"-- "
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
		"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
		"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
	};
	size_t i;
	jmp_buf panic_env;

	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		reset_all();
		host_saved_command_line_set(invalid[i]);
		host_panic_arm(&panic_env);
		if (!setjmp(panic_env)) {
			spp_diag_trace_bootstrap_init();
			CHECK(0, "invalid identity panics");
		}
		host_panic_disarm();
		CHECK(host_panic_message() != NULL, "parser panic captured");
	}
}

static void test_sticky_red(void)
{
	struct linux_binprm bprm = { .filename = "/first" };
	jmp_buf panic_env;

	reset_all();
	spp_diag_trace_bootstrap_init();
	CHECK(spp_diag_trace_bootstrap_bprm_check(&bprm) == -EACCES, "first deny");
	CHECK(spp_diag_trace_bootstrap_bprm_check(&bprm) == -EACCES, "second deny");
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_ima_ready();
		CHECK(0, "sticky red blocks publication");
	}
	host_panic_disarm();
	CHECK(spp_diag_trace_bootstrap_bprm_check(&bprm) == -EACCES,
	      "gate remains closed after failure");
}

static void test_measure_failure_keeps_gate_closed(void)
{
	struct linux_binprm bprm = { .filename = "/after-failed-measure" };
	jmp_buf panic_env;

	reset_all();
	spp_diag_trace_bootstrap_init();
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_ima_ready();
	host_ima_set_result(-1);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_release();
		CHECK(0, "release measurement failure panics");
	}
	host_panic_disarm();
	CHECK(spp_diag_trace_bootstrap_bprm_check(&bprm) == -EACCES,
	      "measurement failure does not publish");
}

static void test_wrong_canary_result_keeps_gate_closed(void)
{
	struct linux_binprm bprm = { .filename = "/after-bypass" };
	jmp_buf panic_env;

	reset_all();
	spp_diag_trace_bootstrap_init();
	host_kmod_set_result(0, 1);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_ima_ready();
		CHECK(0, "bypassed canary panics");
	}
	host_panic_disarm();
	CHECK(spp_diag_trace_bootstrap_denial_count() == 0, "bypass did not count denial");
	CHECK(spp_diag_trace_bootstrap_bprm_check(&bprm) == -EACCES,
	      "bypassed canary leaves gate closed");
}

static void test_core_init_failure_keeps_gate_closed(void)
{
	struct linux_binprm bprm = { .filename = "/after-init-failure" };
	struct spp_diag_trace_core_snapshot snapshot;
	jmp_buf panic_env;

	reset_all();
	spp_diag_trace_core_inject_init_fault(
		SPP_DIAG_TRACE_CORE_INIT_FAULT_PRE_PUBLICATION);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_init();
		CHECK(0, "core init failure panics");
	}
	host_panic_disarm();
	CHECK(!snapshot_now(&snapshot) && snapshot.frame_count == 0,
	      "core init failure appends no frame");
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_bprm_check(&bprm);
		CHECK(0, "init failure leaves exec closed");
	}
	host_panic_disarm();
}

static void test_first_denial_append_failure_keeps_gate_closed(void)
{
	struct linux_binprm bprm = { .filename = "/denial-append-failure" };
	jmp_buf panic_env;

	reset_all();
	spp_diag_trace_bootstrap_init();
	spp_diag_trace_core_inject_fault(WIRE_STATE);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_bprm_check(&bprm);
		CHECK(0, "first denial append failure panics");
	}
	host_panic_disarm();
	CHECK(spp_diag_trace_bootstrap_denial_count() == 1,
	      "first denial was counted before fail-stop");
	CHECK(spp_diag_trace_bootstrap_bprm_check(&bprm) == -EACCES,
	      "denial append failure leaves exec closed");
}

static void test_ready_append_failure_keeps_gate_closed(void)
{
	struct linux_binprm bprm = { .filename = "/ready-append-failure" };
	jmp_buf panic_env;

	reset_all();
	spp_diag_trace_bootstrap_init();
	host_kmod_set_gate(inject_ready_append);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_ima_ready();
		CHECK(0, "ready append failure panics");
	}
	host_panic_disarm();
	CHECK(host_ima_last_call()->calls == 0, "ready append fails before measurement");
	CHECK(spp_diag_trace_bootstrap_bprm_check(&bprm) == -EACCES,
	      "ready append failure leaves exec closed");
}

static void test_ready_measure_failure_keeps_gate_closed(void)
{
	struct linux_binprm bprm = { .filename = "/ready-measure-failure" };
	jmp_buf panic_env;

	reset_all();
	spp_diag_trace_bootstrap_init();
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	host_ima_set_result(-1);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_ima_ready();
		CHECK(0, "ready measurement failure panics");
	}
	host_panic_disarm();
	CHECK(spp_diag_trace_bootstrap_bprm_check(&bprm) == -EACCES,
	      "ready measurement failure leaves exec closed");
}

static void test_release_append_failure_keeps_gate_closed(void)
{
	struct linux_binprm bprm = { .filename = "/release-append-failure" };
	jmp_buf panic_env;

	reset_all();
	spp_diag_trace_bootstrap_init();
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_ima_ready();
	spp_diag_trace_core_inject_fault(WIRE_STATE);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_release();
		CHECK(0, "release append failure panics");
	}
	host_panic_disarm();
	CHECK(spp_diag_trace_bootstrap_bprm_check(&bprm) == -EACCES,
	      "release append failure leaves exec closed");
}

static void test_early_publish_negative_control(void)
{
	struct spp_diag_trace_core_snapshot snapshot;

	reset_all();
	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_publish_release();
	CHECK(spp_diag_trace_bootstrap_bprm_check(&(struct linux_binprm) {
		.filename = "/early-publish" }) == 0, "early publish opens gate");
	CHECK(!snapshot_now(&snapshot) && snapshot.frame_count != 4 &&
	      host_ima_last_call()->calls != 2,
	      "early publish is distinguishable from the release contract");
}

int main(void)
{
	test_happy_path();
	test_parser_failure();
	test_sticky_red();
	test_core_init_failure_keeps_gate_closed();
	test_first_denial_append_failure_keeps_gate_closed();
	test_ready_append_failure_keeps_gate_closed();
	test_ready_measure_failure_keeps_gate_closed();
	test_release_append_failure_keeps_gate_closed();
	test_measure_failure_keeps_gate_closed();
	test_wrong_canary_result_keeps_gate_closed();
	test_early_publish_negative_control();
	return failures ? 1 : 0;
}
