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
	host_saved_command_line_set(valid_command_line);
}

static int snapshot_now(struct spp_diag_trace_core_snapshot *snapshot)
{
	u8 buffer[8192];
	size_t required;

	if (spp_diag_trace_core_snapshot(buffer, sizeof(buffer), &required) ||
	    required < sizeof(*snapshot))
		return -1;
	memcpy(snapshot, buffer, sizeof(*snapshot));
	return 0;
}

static u64 load_u64be(const u8 *value)
{
	return ((u64)value[0] << 56) | ((u64)value[1] << 48) |
		((u64)value[2] << 40) | ((u64)value[3] << 32) |
		((u64)value[4] << 24) | ((u64)value[5] << 16) |
		((u64)value[6] << 8) | value[7];
}

static void boot_to_ima_available(void)
{
	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();
}

static void test_command_line_is_raw_and_detached(void)
{
	char mutable_command_line[sizeof(valid_command_line)];
	struct spp_diag_trace_core_snapshot before;
	struct spp_diag_trace_core_snapshot after;

	reset_all();
	memcpy(mutable_command_line, valid_command_line, sizeof(valid_command_line));
	host_saved_command_line_set(mutable_command_line);
	spp_diag_trace_bootstrap_init();
	CHECK(!snapshot_now(&before), "command line snapshot");
	mutable_command_line[0] ^= 1;
	CHECK(!snapshot_now(&after) &&
	      !memcmp(before.header, after.header, sizeof(before.header)),
	      "published command line inputs are detached");
	CHECK(memcmp(before.header + 148, mutable_command_line, 32),
	      "header stores SHA-256 rather than command-line prefix");
}

static void test_happy_path(void)
{
	struct spp_diag_trace_core_snapshot snapshot;
	const struct host_kmod_call *kmod;
	const struct host_ima_call *ima;

	reset_all();
	boot_to_ima_available();
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_release();
	kmod = host_kmod_last_call();
	ima = host_ima_last_call();
	CHECK(kmod->calls == 1 && kmod->wait == UMH_WAIT_EXEC,
	      "canary uses UMH_WAIT_EXEC once");
	CHECK(!strcmp(kmod->path, SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH),
	      "exact canary path");
	CHECK(ima->calls == 2 && ima->buf_len == 256 && !ima->hash &&
	      ima->digest == NULL && ima->digest_len == 0,
	      "exact IMA call tuple");
	CHECK(!strcmp(ima->event_label, "sol_spp_diag_trace") &&
	      !strcmp(ima->event_name, "sol-spp-diag-release-v1"),
	      "release IMA vocabulary");
	CHECK(!snapshot_now(&snapshot) && snapshot.frame_count == 4 &&
	      snapshot.sequence == 4 && snapshot.bootstrap_denial_count == 1 &&
	      snapshot.bootstrap_stage == SPP_DIAG_TRACE_BOOTSTRAP_RELEASED &&
	      snapshot.bootstrap_released && !snapshot.failed,
	      "four-frame released state");
	CHECK(load_u64be(ima->record + 172) == snapshot.frame_count &&
	      load_u64be(ima->record + 180) == snapshot.stream_byte_count &&
	      !memcmp(ima->record + 188, snapshot.chain, 32),
	      "release record is locked core snapshot");
	CHECK(spp_diag_trace_bootstrap_bprm_check(&(struct linux_binprm) {
		.filename = "/after-release" }) == 0, "only final state opens gate");
}

static void test_parser_contract(void)
{
	static const char *const invalid[] = {
		"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"ima_policy=critical_data ima_policy=critical_data sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"ima_policy=Critical_data sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"ima_policy=critical_data sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1A sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"ima_policy=critical_data sol_spp_diag.challenge=00 sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"ima_policy=critical_data sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00 sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"ima_policy=critical_data sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		"-- ima_policy=critical_data sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
	};
	u8 challenge[32], run[32], control[32];
	size_t i;

	CHECK(!spp_diag_trace_bootstrap_test_parse(valid_command_line,
						   strlen(valid_command_line),
						   challenge, run, control),
	      "exact command line accepted");
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
		CHECK(spp_diag_trace_bootstrap_test_parse(invalid[i], strlen(invalid[i]),
						      challenge, run, control) != 0,
		      "invalid command line rejected");
}

static void test_parser_failure_stays_unpublished(void)
{
	struct spp_diag_trace_core_snapshot snapshot;
	jmp_buf panic_env;

	reset_all();
	host_saved_command_line_set("ima_policy=critical_data");
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_init();
		CHECK(0, "invalid command line panics");
	}
	host_panic_disarm();
	CHECK(!snapshot_now(&snapshot) && !snapshot.initialized &&
	      snapshot.frame_count == 0, "parse failure publishes nothing");
}

static void test_gate_failures_are_sticky(void)
{
	struct spp_diag_trace_core_snapshot first;
	struct spp_diag_trace_core_snapshot second;
	struct linux_binprm exact = {
		.filename = SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH,
	};

	reset_all();
	boot_to_ima_available();
	CHECK(spp_diag_trace_bootstrap_bprm_check(&exact) == -EACCES,
	      "first exact canary denied");
	CHECK(!snapshot_now(&first) && first.frame_count == 2 && !first.failed &&
	      first.bootstrap_denial_count == 1,
	      "first denial appended once");
	CHECK(spp_diag_trace_bootstrap_bprm_check(&exact) == -EACCES,
	      "second canary denied");
	CHECK(!snapshot_now(&second) && second.failed &&
	      second.frame_count == first.frame_count &&
	      second.bootstrap_denial_count == 1,
	      "second denial is sticky without append");

	reset_all();
	boot_to_ima_available();
	CHECK(spp_diag_trace_bootstrap_bprm_check(&(struct linux_binprm) {
		.filename = "/wrong" }) == -EACCES, "wrong path denied");
	CHECK(!snapshot_now(&second) && second.failed && second.frame_count == 1 &&
	      second.bootstrap_denial_count == 0,
	      "wrong path turns red without append");
}

static void test_release_failures_stay_closed(void)
{
	struct spp_diag_trace_core_snapshot snapshot;
	jmp_buf panic_env;

	reset_all();
	boot_to_ima_available();
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	host_ima_set_result(-1);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_release();
		CHECK(0, "IMA failure panics");
	}
	host_panic_disarm();
	CHECK(!snapshot_now(&snapshot) && snapshot.failed &&
	      !snapshot.bootstrap_released, "IMA failure is sticky and closed");

	reset_all();
	boot_to_ima_available();
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	host_current_task.pid = 2;
	host_current_task.tgid = 2;
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_release();
		CHECK(0, "non-PID-1 release panics");
	}
	host_panic_disarm();
	CHECK(!snapshot_now(&snapshot) && snapshot.failed &&
	      !snapshot.bootstrap_released, "non-PID-1 release stays closed");

	reset_all();
	boot_to_ima_available();
	host_kmod_set_result(0, 1);
	host_panic_arm(&panic_env);
	if (!setjmp(panic_env)) {
		spp_diag_trace_bootstrap_release();
		CHECK(0, "canary bypass panics");
	}
	host_panic_disarm();
	CHECK(!snapshot_now(&snapshot) && snapshot.failed &&
	      snapshot.frame_count == 1 && !snapshot.bootstrap_released,
	      "canary bypass is sticky before READY");
}

static void test_every_intermediate_state_stays_closed(void)
{
	u8 ids[32] = { 0 };
	u8 record[256];
	struct spp_diag_trace_core_snapshot snapshot;

	reset_all();
	CHECK(!spp_diag_trace_core_init(ids, ids, ids, ids), "direct core init");
	CHECK(!spp_diag_trace_core_bootstrap_ima_available(), "IMA available");
	CHECK(spp_diag_trace_core_bootstrap_gate(
		SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH,
		strlen(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH), 41, 41) == -EACCES,
	      "direct canary denial");
	CHECK(!spp_diag_trace_core_bootstrap_prepare_ready(record), "READY append");
	CHECK(!spp_diag_trace_core_bootstrap_ready_measured(), "READY measured");
	CHECK(!spp_diag_trace_core_bootstrap_prepare_release(1, 1, record),
	      "RELEASE append");
	CHECK(!spp_diag_trace_core_bootstrap_release_measured(), "RELEASE measured");
	CHECK(spp_diag_trace_core_bootstrap_gate("/racer", 6, 9, 9) == -EACCES,
	      "pre-publication racer denied");
	CHECK(spp_diag_trace_core_bootstrap_publish() != 0,
	      "red state cannot publish");
	CHECK(!snapshot_now(&snapshot) && snapshot.failed &&
	      !snapshot.bootstrap_released && snapshot.frame_count == 4,
	      "racer preserves four-frame prefix and closes gate");
}

static void advance_to_stage(u32 stage)
{
	u8 ids[32] = { 0 };
	u8 record[256];

	spp_diag_trace_core_init(ids, ids, ids, ids);
	if (stage == SPP_DIAG_TRACE_BOOTSTRAP_CORE_READY)
		return;
	spp_diag_trace_core_bootstrap_ima_available();
	if (stage == SPP_DIAG_TRACE_BOOTSTRAP_IMA_AVAILABLE)
		return;
	spp_diag_trace_core_bootstrap_gate(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH,
		strlen(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH), 41, 41);
	if (stage == SPP_DIAG_TRACE_BOOTSTRAP_DENIED)
		return;
	spp_diag_trace_core_bootstrap_prepare_ready(record);
	if (stage == SPP_DIAG_TRACE_BOOTSTRAP_READY_APPENDED)
		return;
	spp_diag_trace_core_bootstrap_ready_measured();
	if (stage == SPP_DIAG_TRACE_BOOTSTRAP_READY_MEASURED)
		return;
	spp_diag_trace_core_bootstrap_prepare_release(1, 1, record);
	if (stage == SPP_DIAG_TRACE_BOOTSTRAP_RELEASE_APPENDED)
		return;
	spp_diag_trace_core_bootstrap_release_measured();
}

static void test_all_publication_barriers(void)
{
	static const u32 stages[] = {
		SPP_DIAG_TRACE_BOOTSTRAP_CORE_READY,
		SPP_DIAG_TRACE_BOOTSTRAP_IMA_AVAILABLE,
		SPP_DIAG_TRACE_BOOTSTRAP_DENIED,
		SPP_DIAG_TRACE_BOOTSTRAP_READY_APPENDED,
		SPP_DIAG_TRACE_BOOTSTRAP_READY_MEASURED,
		SPP_DIAG_TRACE_BOOTSTRAP_RELEASE_APPENDED,
		SPP_DIAG_TRACE_BOOTSTRAP_RELEASE_MEASURED,
	};
	struct spp_diag_trace_core_snapshot snapshot;
	size_t i;

	for (i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
		reset_all();
		advance_to_stage(stages[i]);
		CHECK(spp_diag_trace_core_bootstrap_gate("/racer", 6, 9, 9) ==
		      -EACCES, "pre-publication barrier denies exec");
		CHECK(!snapshot_now(&snapshot) && !snapshot.bootstrap_released,
		      "pre-publication barrier remains closed");
		CHECK(spp_diag_trace_core_bootstrap_publish() != 0,
		      "pre-publication barrier cannot publish");
	}
}

int main(void)
{
	test_happy_path();
	test_command_line_is_raw_and_detached();
	test_parser_contract();
	test_parser_failure_stays_unpublished();
	test_gate_failures_are_sticky();
	test_release_failures_stay_closed();
	test_every_intermediate_state_stays_closed();
	test_all_publication_barriers();
	return failures ? 1 : 0;
}
