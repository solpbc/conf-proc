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

static void expect_mem(const char *name, const void *actual, const void *expected,
		       size_t n)
{
	if (memcmp(actual, expected, n) != 0) {
		fprintf(stderr, "FAIL %s: byte mismatch\n", name);
		g_fails++;
	}
}

static void fill_id(u8 *out, u8 seed)
{
	int i;

	for (i = 0; i < 32; i++)
		out[i] = (u8)(seed + i);
}

static int init_ok(struct spp_diag_trace_core *core)
{
	u8 a[32], b[32], c[32], d[32];

	memset(core, 0, sizeof(*core));
	fill_id(a, 0);
	fill_id(b, 32);
	fill_id(c, 64);
	fill_id(d, 96);
	return spp_diag_trace_core_init(core, a, b, c, d);
}

static void test_snapshot_null(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;

	memset(&core, 0, sizeof(core));
	expect_eq("snap-null-core", spp_diag_trace_core_snapshot(NULL, &snap),
		  WIRE_NULL);
	expect_eq("snap-null-out", spp_diag_trace_core_snapshot(&core, NULL),
		  WIRE_NULL);
}

static void test_snapshot_uninitialized_green(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;

	memset(&core, 0, sizeof(core));
	expect_eq("snap-uninit", spp_diag_trace_core_snapshot(&core, &snap),
		  WIRE_OK);
	expect_eq("uninit-initialized", snap.initialized, 0);
	expect_eq("uninit-failed", snap.failed, 0);
	expect_eq("uninit-reason", snap.reason, 0);
	expect_u64("uninit-frames", snap.frame_count, 0);
}

static void test_init_and_core_init_frame(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	u8 a[32], b[32], c[32], d[32];

	memset(&core, 0, sizeof(core));
	fill_id(a, 0);
	fill_id(b, 32);
	fill_id(c, 64);
	fill_id(d, 96);
	expect_eq("init", spp_diag_trace_core_init(&core, a, b, c, d), WIRE_OK);
	expect_eq("snap-after-init", spp_diag_trace_core_snapshot(&core, &snap),
		  WIRE_OK);
	expect_eq("init-initialized", snap.initialized, 1);
	expect_eq("init-failed", snap.failed, 0);
	expect_u64("init-frames", snap.frame_count, 1);
	expect_u64("init-bytes", snap.stream_byte_count, 244);
	expect_u64("init-seq", snap.sequence, 1);
	expect_eq("core-init-event",
		  (snap.core_init_frame[0] << 8) | snap.core_init_frame[1],
		  (int)SPP_DIAG_TRACE_EVENT_CORE_INIT);
	expect_eq("core-init-len", snap.last_frame_len, 44);
	expect_mem("core-init-last", snap.last_frame, snap.core_init_frame, 44);
	expect_mem("header-challenge", snap.header + 52, a, 32);
	expect_mem("header-commit", snap.header + 32,
		   (const u8[]){ SPP_DIAG_TRACE_SOURCE_COMMIT_BYTES }, 20);
}

static void test_distinct_identities(void)
{
	struct spp_diag_trace_core left;
	struct spp_diag_trace_core right;
	struct spp_diag_trace_core_snapshot a, b;
	u8 z[32];
	u8 one[32];

	memset(&left, 0, sizeof(left));
	memset(&right, 0, sizeof(right));
	memset(z, 0, sizeof(z));
	memset(one, 1, sizeof(one));
	expect_eq("init-left", spp_diag_trace_core_init(&left, z, z, z, z),
		  WIRE_OK);
	expect_eq("init-right", spp_diag_trace_core_init(&right, one, one, one, one),
		  WIRE_OK);
	spp_diag_trace_core_snapshot(&left, &a);
	spp_diag_trace_core_snapshot(&right, &b);
	if (memcmp(a.header, b.header, 192) == 0) {
		fprintf(stderr, "FAIL identities produced identical headers\n");
		g_fails++;
	}
	if (memcmp(a.header_chain, b.header_chain, 32) == 0) {
		fprintf(stderr, "FAIL identities produced identical header_chain\n");
		g_fails++;
	}
	if (memcmp(a.chain, b.chain, 32) == 0) {
		fprintf(stderr, "FAIL identities produced identical chain\n");
		g_fails++;
	}
	expect_mem("core-init-same", a.core_init_frame, b.core_init_frame, 44);
}

static void test_null_identity(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	u8 id[32];

	memset(&core, 0, sizeof(core));
	memset(id, 2, sizeof(id));
	expect_eq("null-challenge",
		  spp_diag_trace_core_init(&core, NULL, id, id, id), WIRE_NULL);
	expect_eq("snap-null-id", spp_diag_trace_core_snapshot(&core, &snap),
		  WIRE_OK);
	expect_eq("null-id-initialized", snap.initialized, 0);
	expect_eq("null-id-failed", snap.failed, 1);
	expect_eq("null-id-reason", snap.reason, WIRE_NULL);
	expect_u64("null-id-frames", snap.frame_count, 0);
	expect_eq("null-run", spp_diag_trace_core_init(&core, id, NULL, id, id),
		  WIRE_NULL);
}

static void test_reinit_sticky(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot before, after;
	u8 chain[32];
	u8 a[32], b[32], c[32], d[32];

	expect_eq("reinit-setup", init_ok(&core), WIRE_OK);
	spp_diag_trace_core_snapshot(&core, &before);
	memcpy(chain, before.chain, 32);
	fill_id(a, 1);
	fill_id(b, 2);
	fill_id(c, 3);
	fill_id(d, 4);
	expect_eq("reinit", spp_diag_trace_core_init(&core, a, b, c, d),
		  WIRE_STATE);
	expect_eq("reinit-snap", spp_diag_trace_core_snapshot(&core, &after),
		  WIRE_OK);
	expect_eq("reinit-failed", after.failed, 1);
	expect_eq("reinit-reason", after.reason, WIRE_STATE);
	expect_eq("reinit-still-init", after.initialized, 1);
	expect_mem("reinit-header", after.header, before.header, 192);
	expect_mem("reinit-chain", after.chain, chain, 32);
	expect_u64("reinit-frames", after.frame_count, 1);
}

static void test_caller_core_init_rejected(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;

	expect_eq("setup-core-init", init_ok(&core), WIRE_OK);
	expect_eq("caller-core-init",
		  spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_CORE_INIT,
					     0, 0, 0, 0, 0, NULL, 0),
		  WIRE_EVENT);
	spp_diag_trace_core_snapshot(&core, &snap);
	expect_eq("caller-core-init-failed", snap.failed, 1);
	expect_u64("caller-core-init-frames", snap.frame_count, 1);
}

static void test_null_payload_rules(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	u8 eight[8];

	memset(eight, 0, sizeof(eight));
	expect_eq("setup-null-payload", init_ok(&core), WIRE_OK);
	expect_eq("null-positive",
		  spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_IMA_READY,
					     0, 0, 0, 0, 0, NULL, 8),
		  WIRE_NULL);
	spp_diag_trace_core_snapshot(&core, &snap);
	expect_u64("null-positive-frames", snap.frame_count, 1);

	expect_eq("setup-null-zero-ready", init_ok(&core), WIRE_OK);
	expect_eq("null-zero-ima-ready",
		  spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_IMA_READY,
					     0, 0, 0, 0, 0, NULL, 0),
		  WIRE_LENGTH);

	expect_eq("setup-null-zero-terminal", init_ok(&core), WIRE_OK);
	expect_eq("null-zero-terminal",
		  spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_TERMINAL,
					     0, 0, 0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					     NULL, 0),
		  WIRE_OK);
	expect_eq("ima-ready-ok", init_ok(&core), WIRE_OK);
	expect_eq("ima-ready-bytes",
		  spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_IMA_READY,
					     0, 0, 0, 0, 0, eight, 8),
		  WIRE_OK);
}

static void test_one_field_invalid(void)
{
	struct spp_diag_trace_core core;
	u8 eight[8];

	memset(eight, 1, sizeof(eight));
	expect_eq("setup-bad-event", init_ok(&core), WIRE_OK);
	expect_eq("bad-event",
		  spp_diag_trace_core_append(&core, 0, 0, 0, 0, 0, 0, NULL, 0),
		  WIRE_EVENT);

	expect_eq("setup-bad-flags", init_ok(&core), WIRE_OK);
	expect_eq("bad-flags",
		  spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_TERMINAL,
					     1, 0, 0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					     NULL, 0),
		  WIRE_FLAGS);

	expect_eq("setup-bad-phase", init_ok(&core), WIRE_OK);
	expect_eq("bad-phase",
		  spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_TERMINAL,
					     0, 0, 0, 0, 0, NULL, 0),
		  WIRE_STATE);

	expect_eq("setup-bad-task", init_ok(&core), WIRE_OK);
	expect_eq("bad-task",
		  spp_diag_trace_core_append(
			  &core, SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE, 0, 0, 0,
			  0, 0, eight, 16),
		  WIRE_VALUE);
}

static void test_post_success_mutation(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	u8 a[32], b[32], c[32], d[32];
	u8 payload[8];

	memset(&core, 0, sizeof(core));
	fill_id(a, 0);
	fill_id(b, 32);
	fill_id(c, 64);
	fill_id(d, 96);
	expect_eq("mut-init", spp_diag_trace_core_init(&core, a, b, c, d),
		  WIRE_OK);
	memset(a, 0xff, sizeof(a));
	memset(b, 0xff, sizeof(b));
	memset(c, 0xff, sizeof(c));
	memset(d, 0xff, sizeof(d));
	spp_diag_trace_core_snapshot(&core, &snap);
	fill_id(a, 0);
	expect_mem("captured-challenge", snap.header + 52, a, 32);

	memset(payload, 0x11, sizeof(payload));
	expect_eq("mut-append",
		  spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_IMA_READY,
					     0, 0, 0, 0, 0, payload, 8),
		  WIRE_OK);
	memset(payload, 0x22, sizeof(payload));
	spp_diag_trace_core_snapshot(&core, &snap);
	memset(payload, 0x11, sizeof(payload));
	expect_mem("captured-payload", snap.last_frame + 44, payload, 8);
}

static void test_mark_failure_and_snapshot_green(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;

	expect_eq("mark-setup", init_ok(&core), WIRE_OK);
	expect_eq("mark", spp_diag_trace_core_mark_failure(&core, WIRE_CAP),
		  WIRE_CAP);
	expect_eq("snap-after-mark", spp_diag_trace_core_snapshot(&core, &snap),
		  WIRE_OK);
	expect_eq("mark-failed", snap.failed, 1);
	expect_eq("mark-reason", snap.reason, WIRE_CAP);
	expect_eq("append-after-mark",
		  spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_TERMINAL,
					     0, 0, 0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					     NULL, 0),
		  WIRE_CAP);
	expect_eq("second-mark", spp_diag_trace_core_mark_failure(&core, WIRE_EVENT),
		  WIRE_CAP);
}

static void test_append_before_init(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;

	memset(&core, 0, sizeof(core));
	expect_eq("append-before-init",
		  spp_diag_trace_core_append(&core, SPP_DIAG_TRACE_EVENT_TERMINAL,
					     0, 0, 0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					     NULL, 0),
		  WIRE_STATE);
	spp_diag_trace_core_snapshot(&core, &snap);
	expect_eq("before-init-initialized", snap.initialized, 0);
	expect_eq("before-init-failed", snap.failed, 1);
}

int main(void)
{
	test_snapshot_null();
	test_snapshot_uninitialized_green();
	test_init_and_core_init_frame();
	test_distinct_identities();
	test_null_identity();
	test_reinit_sticky();
	test_caller_core_init_rejected();
	test_null_payload_rules();
	test_one_field_invalid();
	test_post_success_mutation();
	test_mark_failure_and_snapshot_green();
	test_append_before_init();
	if (g_fails) {
		fprintf(stderr, "%d failure(s)\n", g_fails);
		return 1;
	}
	puts("ok   spp-diag-trace-core-selftest");
	return 0;
}
