/* SPDX-License-Identifier: GPL-2.0-only */

#include "core.h"

#include <linux/vmalloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fails;

#define SNAP_BUF_CAP (sizeof(struct spp_diag_trace_core_snapshot) + 4096)

static void expect_eq(const char *name, int actual, int expected)
{
	if (actual != expected) {
		fprintf(stderr, "FAIL %s: got %d want %d\n", name, actual,
			expected);
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

static int take_snap(struct spp_diag_trace_core_snapshot *snap)
{
	unsigned char buf[SNAP_BUF_CAP];
	size_t need = 0;
	int rc;

	rc = spp_diag_trace_core_snapshot(buf, sizeof(buf), &need);
	if (rc != WIRE_OK)
		return rc;
	if (need < sizeof(*snap))
		return WIRE_LENGTH;
	memcpy(snap, buf, sizeof(*snap));
	return WIRE_OK;
}

static int init_ok(void)
{
	u8 a[32], b[32], c[32], d[32];

	spp_diag_trace_core_reset();
	fill_id(a, 0);
	fill_id(b, 32);
	fill_id(c, 64);
	fill_id(d, 96);
	return spp_diag_trace_core_init(a, b, c, d);
}

static void test_snapshot_null(void)
{
	unsigned char buf[16];
	size_t need = 0;

	spp_diag_trace_core_reset();
	expect_eq("snap-null-core",
		  spp_diag_trace_core_snapshot(NULL, sizeof(buf), &need),
		  WIRE_NULL);
	expect_u64("snap-null-core-need", need,
		   sizeof(struct spp_diag_trace_core_snapshot));
	expect_eq("snap-null-out",
		  spp_diag_trace_core_snapshot(buf, sizeof(buf), NULL),
		  WIRE_NULL);
}

static void test_snapshot_uninitialized_green(void)
{
	struct spp_diag_trace_core_snapshot snap;

	spp_diag_trace_core_reset();
	expect_eq("snap-uninit", take_snap(&snap), WIRE_OK);
	expect_eq("uninit-initialized", snap.initialized, 0);
	expect_eq("uninit-failed", snap.failed, 0);
	expect_eq("uninit-reason", snap.reason, 0);
	expect_u64("uninit-frames", snap.frame_count, 0);
}

static void test_init_and_core_init_frame(void)
{
	struct spp_diag_trace_core_snapshot snap;
	u8 a[32], b[32], c[32], d[32];

	spp_diag_trace_core_reset();
	fill_id(a, 0);
	fill_id(b, 32);
	fill_id(c, 64);
	fill_id(d, 96);
	expect_eq("init", spp_diag_trace_core_init(a, b, c, d), WIRE_OK);
	expect_eq("snap-after-init", take_snap(&snap), WIRE_OK);
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
	expect_eq("is-green", spp_diag_trace_core_is_green(), 1);
}

static void test_distinct_identities(void)
{
	/* Two simultaneous cores cannot exist once there is exactly one kernel-owned singleton. */
	struct spp_diag_trace_core_snapshot a, b;
	u8 z[32];
	u8 one[32];

	memset(z, 0, sizeof(z));
	memset(one, 1, sizeof(one));
	spp_diag_trace_core_reset();
	expect_eq("init-left", spp_diag_trace_core_init(z, z, z, z), WIRE_OK);
	expect_eq("snap-left", take_snap(&a), WIRE_OK);
	spp_diag_trace_core_reset();
	expect_eq("init-right", spp_diag_trace_core_init(one, one, one, one),
		  WIRE_OK);
	expect_eq("snap-right", take_snap(&b), WIRE_OK);
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

static int init_valid(void)
{
	u8 a[32], b[32], c[32], d[32];

	fill_id(a, 0);
	fill_id(b, 32);
	fill_id(c, 64);
	fill_id(d, 96);
	return spp_diag_trace_core_init(a, b, c, d);
}

static void test_null_identity(void)
{
	struct spp_diag_trace_core_snapshot snap;
	struct host_vmalloc_record rec;
	u8 id[32];

	spp_diag_trace_core_reset();
	host_vmalloc_reset_instrumentation();
	memset(id, 2, sizeof(id));
	expect_eq("null-challenge", spp_diag_trace_core_init(NULL, id, id, id),
		  WIRE_NULL);
	expect_eq("snap-null-id", take_snap(&snap), WIRE_OK);
	expect_eq("null-id-initialized", snap.initialized, 0);
	expect_eq("null-id-failed", snap.failed, 1);
	expect_eq("null-id-reason", snap.reason, WIRE_NULL);
	expect_u64("null-id-frames", snap.frame_count, 0);
	expect_u64("null-id-stream", snap.stream_len, 0);
	expect_eq("is-green-null", spp_diag_trace_core_is_green(), 0);
	rec = host_vmalloc_record();
	expect_eq("null-id-alloc", (int)rec.alloc_count, 0);
	expect_eq("null-run", spp_diag_trace_core_init(id, NULL, id, id),
		  WIRE_NULL);
}

static void test_init_fault_stages(void)
{
	static const struct {
		int stage;
		int wire;
		int allocates;
		const char *name;
	} cases[] = {
		{ SPP_DIAG_TRACE_CORE_INIT_FAULT_ALLOCATION, WIRE_CAP, 0,
		  "allocation" },
		{ SPP_DIAG_TRACE_CORE_INIT_FAULT_HEADER_ENCODING, WIRE_MAGIC, 1,
		  "header-encoding" },
		{ SPP_DIAG_TRACE_CORE_INIT_FAULT_HEADER_INVARIANT, WIRE_RESERVED,
		  1, "header-invariant" },
		{ SPP_DIAG_TRACE_CORE_INIT_FAULT_CORE_INIT_ENCODING, WIRE_LENGTH,
		  1, "core-init-encoding" },
		{ SPP_DIAG_TRACE_CORE_INIT_FAULT_CORE_INIT_INVARIANT,
		  WIRE_SEQUENCE, 1, "core-init-invariant" },
		{ SPP_DIAG_TRACE_CORE_INIT_FAULT_INITIAL_ARITHMETIC,
		  WIRE_ARITHMETIC, 1, "initial-arithmetic" },
		{ SPP_DIAG_TRACE_CORE_INIT_FAULT_PRE_PUBLICATION, WIRE_STATE, 1,
		  "pre-publication" },
	};
	struct spp_diag_trace_core_snapshot snap;
	struct host_vmalloc_record rec;
	unsigned i;
	int checked = 0;
	int rc;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		spp_diag_trace_core_reset();
		host_vmalloc_reset_instrumentation();
		spp_diag_trace_core_inject_init_fault(cases[i].stage);
		rc = init_valid();
		expect_eq(cases[i].name, rc, cases[i].wire);
		expect_eq("stage-green", spp_diag_trace_core_is_green(), 0);
		expect_eq("stage-snap", take_snap(&snap), WIRE_OK);
		expect_u64("stage-stream", snap.stream_len, 0);
		expect_u64("stage-frames", snap.frame_count, 0);
		expect_eq("stage-reason", snap.reason, cases[i].wire);
		rec = host_vmalloc_record();
		if (cases[i].allocates) {
			expect_eq("stage-alloc", (int)rec.alloc_count, 1);
			expect_eq("stage-free", (int)rec.free_count, 1);
			expect_eq("stage-free-irqs", rec.last_free_irqs_disabled,
				  0);
			expect_eq("stage-free-lock", rec.last_free_lock_held, 0);
		} else {
			expect_eq("stage-no-alloc", (int)rec.alloc_count, 0);
			expect_eq("stage-no-free", (int)rec.free_count, 0);
		}
		rc = init_valid();
		expect_eq("stage-sticky-reinit", rc, cases[i].wire);
		expect_eq("stage-still-not-green", spp_diag_trace_core_is_green(),
			  0);
		expect_eq("stage-sticky-snap", take_snap(&snap), WIRE_OK);
		expect_eq("stage-sticky-reason", snap.reason, cases[i].wire);
		expect_u64("stage-sticky-stream", snap.stream_len, 0);
		if (g_fails == 0)
			checked++;
	}
	printf("ok   init-fault-stages checked=%d/7\n", checked);
	expect_eq("init-fault-stage-count", checked, 7);
}

static void test_reinit_sticky(void)
{
	struct spp_diag_trace_core_snapshot before, after;
	u8 chain[32];
	u8 a[32], b[32], c[32], d[32];

	expect_eq("reinit-setup", init_ok(), WIRE_OK);
	take_snap(&before);
	memcpy(chain, before.chain, 32);
	fill_id(a, 1);
	fill_id(b, 2);
	fill_id(c, 3);
	fill_id(d, 4);
	expect_eq("reinit", spp_diag_trace_core_init(a, b, c, d), WIRE_STATE);
	expect_eq("reinit-snap", take_snap(&after), WIRE_OK);
	expect_eq("reinit-failed", after.failed, 1);
	expect_eq("reinit-reason", after.reason, WIRE_STATE);
	expect_eq("reinit-still-init", after.initialized, 1);
	expect_mem("reinit-header", after.header, before.header, 192);
	expect_mem("reinit-chain", after.chain, chain, 32);
	expect_u64("reinit-frames", after.frame_count, 1);
	expect_eq("is-green-reinit", spp_diag_trace_core_is_green(), 0);
}

static void test_caller_core_init_rejected(void)
{
	struct spp_diag_trace_core_snapshot snap;

	expect_eq("setup-core-init", init_ok(), WIRE_OK);
	expect_eq("caller-core-init",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_CORE_INIT, 0,
					     0, 0, 0, 0, NULL, 0),
		  WIRE_EVENT);
	take_snap(&snap);
	expect_eq("caller-core-init-failed", snap.failed, 1);
	expect_u64("caller-core-init-frames", snap.frame_count, 1);
}

static void test_null_payload_rules(void)
{
	struct spp_diag_trace_core_snapshot snap;
	u8 eight[8];

	memset(eight, 0, sizeof(eight));
	expect_eq("setup-null-payload", init_ok(), WIRE_OK);
	expect_eq("null-positive",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_IMA_READY, 0,
					     0, 0, 0, 0, NULL, 8),
		  WIRE_NULL);
	take_snap(&snap);
	expect_u64("null-positive-frames", snap.frame_count, 1);

	expect_eq("setup-null-zero-ready", init_ok(), WIRE_OK);
	expect_eq("null-zero-ima-ready",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_IMA_READY, 0,
					     0, 0, 0, 0, NULL, 0),
		  WIRE_LENGTH);

	expect_eq("setup-null-zero-terminal", init_ok(), WIRE_OK);
	expect_eq("null-zero-terminal",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0,
					     0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					     NULL, 0),
		  WIRE_OK);
	expect_eq("ima-ready-ok", init_ok(), WIRE_OK);
	expect_eq("ima-ready-bytes",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_IMA_READY, 0,
					     0, 0, 0, 0, eight, 8),
		  WIRE_OK);
}

static void test_one_field_invalid(void)
{
	u8 sixteen[16];

	memset(sixteen, 1, sizeof(sixteen));
	expect_eq("setup-bad-event", init_ok(), WIRE_OK);
	expect_eq("bad-event",
		  spp_diag_trace_core_append(0, 0, 0, 0, 0, 0, NULL, 0),
		  WIRE_EVENT);

	expect_eq("setup-bad-flags", init_ok(), WIRE_OK);
	expect_eq("bad-flags",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 1, 0,
					     0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					     NULL, 0),
		  WIRE_FLAGS);

	expect_eq("setup-bad-phase", init_ok(), WIRE_OK);
	expect_eq("bad-phase",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0,
					     0, 0, 0, NULL, 0),
		  WIRE_STATE);

	expect_eq("setup-bad-task", init_ok(), WIRE_OK);
	expect_eq("bad-task",
		  spp_diag_trace_core_append(
			  SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE, 0, 0, 0, 0, 0,
			  sixteen, 16),
		  WIRE_VALUE);
}

static void test_post_success_mutation(void)
{
	struct spp_diag_trace_core_snapshot snap;
	u8 a[32], b[32], c[32], d[32];
	u8 payload[8];

	spp_diag_trace_core_reset();
	fill_id(a, 0);
	fill_id(b, 32);
	fill_id(c, 64);
	fill_id(d, 96);
	expect_eq("mut-init", spp_diag_trace_core_init(a, b, c, d), WIRE_OK);
	memset(a, 0xff, sizeof(a));
	memset(b, 0xff, sizeof(b));
	memset(c, 0xff, sizeof(c));
	memset(d, 0xff, sizeof(d));
	take_snap(&snap);
	fill_id(a, 0);
	expect_mem("captured-challenge", snap.header + 52, a, 32);

	memset(payload, 0x11, sizeof(payload));
	expect_eq("mut-append",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_IMA_READY, 0,
					     0, 0, 0, 0, payload, 8),
		  WIRE_OK);
	memset(payload, 0x22, sizeof(payload));
	take_snap(&snap);
	memset(payload, 0x11, sizeof(payload));
	expect_mem("captured-payload", snap.last_frame + 44, payload, 8);
}

static void test_mark_failure_and_snapshot_green(void)
{
	struct spp_diag_trace_core_snapshot snap;

	expect_eq("mark-setup", init_ok(), WIRE_OK);
	expect_eq("mark", spp_diag_trace_core_mark_failure(WIRE_CAP), WIRE_CAP);
	expect_eq("snap-after-mark", take_snap(&snap), WIRE_OK);
	expect_eq("mark-failed", snap.failed, 1);
	expect_eq("mark-reason", snap.reason, WIRE_CAP);
	expect_eq("is-green-mark", spp_diag_trace_core_is_green(), 0);
	expect_eq("append-after-mark",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0,
					     0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					     NULL, 0),
		  WIRE_CAP);
	expect_eq("second-mark", spp_diag_trace_core_mark_failure(WIRE_EVENT),
		  WIRE_CAP);
}

static void test_append_before_init(void)
{
	struct spp_diag_trace_core_snapshot snap;

	spp_diag_trace_core_reset();
	expect_eq("append-before-init",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0,
					     0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					     NULL, 0),
		  WIRE_STATE);
	take_snap(&snap);
	expect_eq("before-init-initialized", snap.initialized, 0);
	expect_eq("before-init-failed", snap.failed, 1);
	expect_eq("is-green-before", spp_diag_trace_core_is_green(), 0);
}

static void test_mark_failure_domain(void)
{
	struct spp_diag_trace_core_snapshot snap;

	expect_eq("mark-zero-setup", init_ok(), WIRE_OK);
	expect_eq("mark-zero", spp_diag_trace_core_mark_failure(0), WIRE_VALUE);
	expect_eq("mark-zero-snap", take_snap(&snap), WIRE_OK);
	expect_eq("mark-zero-reason", snap.reason, WIRE_VALUE);
	expect_eq("mark-zero-then-cap", spp_diag_trace_core_mark_failure(WIRE_CAP),
		  WIRE_VALUE);
	expect_eq("mark-zero-sticky", take_snap(&snap), WIRE_OK);
	expect_eq("mark-zero-kept", snap.reason, WIRE_VALUE);

	expect_eq("mark-14-setup", init_ok(), WIRE_OK);
	expect_eq("mark-14", spp_diag_trace_core_mark_failure(14), WIRE_VALUE);
	expect_eq("mark-14-then-cap", spp_diag_trace_core_mark_failure(WIRE_CAP),
		  WIRE_VALUE);
	expect_eq("mark-14-snap", take_snap(&snap), WIRE_OK);
	expect_eq("mark-14-kept", snap.reason, WIRE_VALUE);

	expect_eq("mark-neg-setup", init_ok(), WIRE_OK);
	expect_eq("mark-neg", spp_diag_trace_core_mark_failure(-1), WIRE_VALUE);
	expect_eq("mark-neg-then-cap", spp_diag_trace_core_mark_failure(WIRE_CAP),
		  WIRE_VALUE);
	expect_eq("mark-neg-snap", take_snap(&snap), WIRE_OK);
	expect_eq("mark-neg-kept", snap.reason, WIRE_VALUE);

	expect_eq("mark-valid-first-setup", init_ok(), WIRE_OK);
	expect_eq("mark-valid-first", spp_diag_trace_core_mark_failure(WIRE_CAP),
		  WIRE_CAP);
	expect_eq("mark-valid-then-zero", spp_diag_trace_core_mark_failure(0),
		  WIRE_CAP);
	expect_eq("mark-valid-sticky-snap", take_snap(&snap), WIRE_OK);
	expect_eq("mark-valid-kept", snap.reason, WIRE_CAP);
}

static void test_snapshot_capacity(void)
{
	unsigned char stack[SNAP_BUF_CAP];
	unsigned char *short_buf;
	unsigned char exact[SNAP_BUF_CAP];
	unsigned char after[SNAP_BUF_CAP];
	size_t need = 0;
	size_t need2 = 0;
	size_t i;
	int rc;

	expect_eq("cap-setup", init_ok(), WIRE_OK);
	expect_eq("snap-null-out",
		  spp_diag_trace_core_snapshot(NULL, 0, &need), WIRE_NULL);
	expect_u64("snap-null-out-need", need,
		   sizeof(struct spp_diag_trace_core_snapshot) + 244);
	expect_eq("snap-null-need",
		  spp_diag_trace_core_snapshot(stack, 0, NULL), WIRE_NULL);

	need = 0;
	expect_eq("snap-probe",
		  spp_diag_trace_core_snapshot(stack, sizeof(stack), &need),
		  WIRE_OK);
	if (need < sizeof(struct spp_diag_trace_core_snapshot) + 244) {
		fprintf(stderr, "FAIL snap-need too small: %zu\n", need);
		g_fails++;
		return;
	}
	short_buf = malloc(need);
	if (short_buf == NULL) {
		fprintf(stderr, "FAIL snap-short malloc\n");
		g_fails++;
		return;
	}
	memset(short_buf, 0xcc, need);
	need2 = 0;
	rc = spp_diag_trace_core_snapshot(short_buf, need - 1, &need2);
	expect_eq("snap-short", rc, WIRE_BUFFER_TOO_SMALL);
	expect_u64("snap-short-need", need2, need);
	for (i = 0; i < need; i++) {
		if (short_buf[i] != 0xcc) {
			fprintf(stderr, "FAIL snap-short wrote byte %zu\n", i);
			g_fails++;
			break;
		}
	}
	free(short_buf);

	memset(exact, 0xcc, sizeof(exact));
	need2 = 0;
	expect_eq("snap-exact",
		  spp_diag_trace_core_snapshot(exact, need, &need2), WIRE_OK);
	expect_u64("snap-exact-need", need2, need);
	memcpy(stack, exact, need);
	expect_eq("snap-exact-append",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0,
					     0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					     NULL, 0),
		  WIRE_OK);
	need2 = 0;
	expect_eq("snap-after",
		  spp_diag_trace_core_snapshot(after, sizeof(after), &need2),
		  WIRE_OK);
	if (need2 <= need) {
		fprintf(stderr, "FAIL live stream did not grow after append\n");
		g_fails++;
	}
	if (memcmp(exact, stack, need) != 0) {
		fprintf(stderr, "FAIL exact snapshot mutated after live append\n");
		g_fails++;
	}
	if (memcmp(exact, after, need) == 0) {
		fprintf(stderr, "FAIL exact snapshot matched post-append live copy\n");
		g_fails++;
	}
}

static void mutate_payload(void *arg)
{
	u8 *payload = arg;

	memset(payload, 0x22, 8);
}

static void test_payload_single_fetch(void)
{
	struct spp_diag_trace_core_snapshot snap;
	u8 payload[8];
	u8 original[8];

	expect_eq("fetch-setup", init_ok(), WIRE_OK);
	memset(payload, 0x11, sizeof(payload));
	memcpy(original, payload, sizeof(original));
	spp_diag_trace_core_set_pre_lock_barrier(mutate_payload, payload);
	expect_eq("fetch-append",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_IMA_READY, 0,
					     0, 0, 0, 0, payload, 8),
		  WIRE_OK);
	spp_diag_trace_core_set_pre_lock_barrier(NULL, NULL);
	expect_eq("fetch-snap", take_snap(&snap), WIRE_OK);
	expect_mem("fetch-published", snap.last_frame + 44, original, 8);
	if (memcmp(payload, original, 8) == 0) {
		fprintf(stderr, "FAIL barrier did not mutate caller payload\n");
		g_fails++;
	}
}

static void test_checked_add_u64(void)
{
	u64 out;
	u64 sentinel = 0x1111111111111111ull;

	out = sentinel;
	expect_eq("add-overflow",
		  spp_diag_trace_core_test_checked_add_u64(~0ull, 1ull, &out),
		  WIRE_ARITHMETIC);
	expect_u64("add-overflow-unwritten", out, sentinel);

	out = sentinel;
	expect_eq("add-zero",
		  spp_diag_trace_core_test_checked_add_u64(0, 0, &out), WIRE_OK);
	expect_u64("add-zero-out", out, 0);

	out = sentinel;
	expect_eq("add-max-plus-zero",
		  spp_diag_trace_core_test_checked_add_u64(~0ull, 0, &out),
		  WIRE_OK);
	expect_u64("add-max-plus-zero-out", out, ~0ull);

	out = sentinel;
	expect_eq("add-in-range",
		  spp_diag_trace_core_test_checked_add_u64(1, 2, &out), WIRE_OK);
	expect_u64("add-in-range-out", out, 3);
}

int main(void)
{
	test_snapshot_null();
	test_snapshot_uninitialized_green();
	test_init_and_core_init_frame();
	test_distinct_identities();
	test_null_identity();
	test_init_fault_stages();
	test_reinit_sticky();
	test_caller_core_init_rejected();
	test_null_payload_rules();
	test_one_field_invalid();
	test_post_success_mutation();
	test_mark_failure_and_snapshot_green();
	test_mark_failure_domain();
	test_snapshot_capacity();
	test_payload_single_fetch();
	test_checked_add_u64();
	test_append_before_init();
	if (g_fails) {
		fprintf(stderr, "%d failure(s)\n", g_fails);
		return 1;
	}
	puts("ok   spp-diag-trace-core-selftest");
	return 0;
}
