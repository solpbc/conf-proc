/* SPDX-License-Identifier: GPL-2.0-only */

#include "core.h"

#include <stdio.h>
#include <string.h>

static int g_fails;

static void expect_eq(const char *name, int actual, int expected)
{
	if (actual != expected) {
		fprintf(stderr, "FAIL %s: got %d want %d\n", name, actual, expected);
		g_fails++;
	}
}

static void expect_u64(const char *name, unsigned long long actual,
		       unsigned long long expected)
{
	if (actual != expected) {
		fprintf(stderr, "FAIL %s: got %llu want %llu\n", name, actual,
			expected);
		g_fails++;
	}
}

static int init_core(struct spp_diag_trace_core *core)
{
	u8 id[32];

	memset(core, 0, sizeof(*core));
	memset(id, 0x5a, sizeof(id));
	return spp_diag_trace_core_init(core, id, id, id, id);
}

int main(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	int i;
	int rc;

	if (!IS_ENABLED(CONFIG_KUNIT)) {
		fputs("caps selftest requires CONFIG_KUNIT=1\n", stderr);
		return 2;
	}
	expect_eq("op-frames", (int)SPP_DIAG_TRACE_CORE_OP_MAX_FRAMES, 8);
	expect_u64("op-bytes", SPP_DIAG_TRACE_CORE_OP_MAX_STREAM_BYTES, 1024);

	expect_eq("init", init_core(&core), WIRE_OK);
	spp_diag_trace_core_snapshot(&core, &snap);
	expect_eq("snap-op-frames", (int)snap.max_frames_op, 8);
	expect_u64("snap-op-bytes", snap.max_stream_bytes_op, 1024);
	expect_u64("after-init-frames", snap.frame_count, 1);
	expect_u64("after-init-bytes", snap.stream_byte_count, 244);

	for (i = 0; i < 7; i++) {
		rc = spp_diag_trace_core_append(
			&core, SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0, 0, 0,
			SPP_DIAG_TRACE_PHASE_SEALED, NULL, 0);
		expect_eq("fill-append", rc, WIRE_OK);
	}
	spp_diag_trace_core_snapshot(&core, &snap);
	expect_u64("full-frames", snap.frame_count, 8);
	expect_eq("not-failed-at-cap-boundary", snap.failed, 0);

	rc = spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_TERMINAL, 0,
					0, 0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					NULL, 0);
	expect_eq("over-frame-cap", rc, WIRE_CAP);
	spp_diag_trace_core_snapshot(&core, &snap);
	expect_eq("frame-cap-failed", snap.failed, 1);
	expect_u64("frame-cap-count", snap.frame_count, 8);

	expect_eq("reinit-after-cap", init_core(&core), WIRE_OK);
	for (i = 0; i < 7; i++) {
		u8 payload[8];

		memset(payload, (u8)i, sizeof(payload));
		rc = spp_diag_trace_core_append(
			&core, SPP_DIAG_TRACE_EVENT_IMA_READY, 0, 0, 0, 0, 0,
			payload, 8);
		expect_eq("byte-fill", rc, WIRE_OK);
	}
	spp_diag_trace_core_snapshot(&core, &snap);
	/*
	 * CORE_INIT uses 244 stream bytes. Each IMA_READY frame is
	 * 4 + 44 + 8 = 56 stream bytes. 244 + 7*56 = 636, still under 1024.
	 * One more 56-byte frame is 692. Keep appending TERMINAL (48 stream
	 * bytes) until the next would exceed 1024.
	 */
	while (snap.stream_byte_count + 48 <= 1024 &&
	       snap.frame_count < SPP_DIAG_TRACE_CORE_OP_MAX_FRAMES) {
		rc = spp_diag_trace_core_append(
			&core, SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0, 0, 0,
			SPP_DIAG_TRACE_PHASE_SEALED, NULL, 0);
		expect_eq("byte-terminal", rc, WIRE_OK);
		spp_diag_trace_core_snapshot(&core, &snap);
	}
	if (snap.frame_count < SPP_DIAG_TRACE_CORE_OP_MAX_FRAMES) {
		rc = spp_diag_trace_core_append(
			&core, SPP_DIAG_TRACE_EVENT_IMA_READY, 0, 0, 0, 0, 0,
			(const u8 *)"xxxxxxxx", 8);
		expect_eq("over-byte-cap", rc, WIRE_CAP);
		spp_diag_trace_core_snapshot(&core, &snap);
		expect_eq("byte-cap-failed", snap.failed, 1);
	}

	if (g_fails) {
		fprintf(stderr, "%d failure(s)\n", g_fails);
		return 1;
	}
	puts("ok   spp-diag-trace-core-caps-selftest");
	return 0;
}
