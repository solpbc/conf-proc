/* SPDX-License-Identifier: GPL-2.0-only */

#include "core.h"

#include <stdio.h>
#include <string.h>

static int g_fails;

#define SNAP_BUF_CAP (sizeof(struct spp_diag_trace_core_snapshot) + 8192)

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

static int capture_blob(unsigned char *buf, size_t cap, size_t *need)
{
	return spp_diag_trace_core_snapshot(buf, cap, need);
}

static int stream_preserved(const unsigned char *before, size_t before_need,
			    const unsigned char *after, size_t after_need)
{
	struct spp_diag_trace_core_snapshot a;
	struct spp_diag_trace_core_snapshot b;

	if (before_need < sizeof(a) || after_need < sizeof(b))
		return 0;
	memcpy(&a, before, sizeof(a));
	memcpy(&b, after, sizeof(b));
	if (a.stream_len != b.stream_len || a.frame_count != b.frame_count ||
	    a.stream_byte_count != b.stream_byte_count || a.sequence != b.sequence ||
	    a.last_frame_len != b.last_frame_len)
		return 0;
	if (memcmp(a.header, b.header, sizeof(a.header)) != 0 ||
	    memcmp(a.core_init_frame, b.core_init_frame,
		   sizeof(a.core_init_frame)) != 0 ||
	    memcmp(a.header_chain, b.header_chain, sizeof(a.header_chain)) != 0 ||
	    memcmp(a.chain, b.chain, sizeof(a.chain)) != 0 ||
	    memcmp(a.last_frame, b.last_frame, a.last_frame_len) != 0)
		return 0;
	if (before_need != sizeof(a) + (size_t)a.stream_len ||
	    after_need != sizeof(b) + (size_t)b.stream_len)
		return 0;
	return memcmp(before + sizeof(a), after + sizeof(b),
		      (size_t)a.stream_len) == 0;
}

static int init_ids(void)
{
	u8 id[32];

	memset(id, 0x5a, sizeof(id));
	return spp_diag_trace_core_init(id, id, id, id);
}

static int append_terminal(void)
{
	return spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0, 0,
					  0, SPP_DIAG_TRACE_PHASE_SEALED, NULL,
					  0);
}

static int append_pre_release(const u8 *payload, size_t n)
{
	return spp_diag_trace_core_append(
		SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED, 0, 0, 0, 1, 0,
		payload, n);
}

static void fill_pre_release(u8 *payload, size_t n)
{
	size_t i;

	memset(payload, 0xab, n);
	payload[0] = 0;
	payload[1] = 13;
	payload[2] = (u8)((n - 20) >> 8);
	payload[3] = (u8)(n - 20);
	payload[4] = 0;
	payload[5] = 0;
	payload[6] = 0;
	payload[7] = 1;
	payload[8] = 0;
	payload[9] = 0;
	payload[10] = 0;
	payload[11] = 1;
	for (i = 20; i < n; i++)
		payload[i] = 'a';
}

static void test_frame_cap(void)
{
	struct spp_diag_trace_core_snapshot snap;
	unsigned char before[SNAP_BUF_CAP];
	unsigned char after[SNAP_BUF_CAP];
	size_t before_need = 0;
	size_t after_need = 0;
	int i;
	int rc;
	int admitted = 0;
	int rejected = 0;

	spp_diag_trace_core_reset();
	spp_diag_trace_core_set_op_caps(8, 65536);
	expect_eq("frame-cap-init", init_ids(), WIRE_OK);
	for (i = 0; i < 7; i++) {
		rc = append_terminal();
		expect_eq("frame-cap-fill", rc, WIRE_OK);
		if (rc == WIRE_OK)
			admitted++;
	}
	take_snap(&snap);
	expect_u64("frame-cap-full-frames", snap.frame_count, 8);
	expect_eq("frame-cap-not-failed", snap.failed, 0);
	expect_eq("frame-cap-capture",
		  capture_blob(before, sizeof(before), &before_need), WIRE_OK);

	rc = append_terminal();
	expect_eq("frame-cap-over", rc, WIRE_CAP);
	if (rc != WIRE_OK)
		rejected++;
	take_snap(&snap);
	expect_eq("frame-cap-failed", snap.failed, 1);
	expect_u64("frame-cap-count", snap.frame_count, 8);
	expect_eq("frame-cap-after",
		  capture_blob(after, sizeof(after), &after_need), WIRE_OK);
	if (!stream_preserved(before, before_need, after, after_need)) {
		fprintf(stderr, "FAIL frame-cap stream mutated on reject\n");
		g_fails++;
	}
	printf("ok   caps-frame-limit max_frames=8 admitted=%d rejected=%d frames=%llu\n",
	       admitted, rejected, (unsigned long long)snap.frame_count);
}

static void test_byte_cap_before_frame_cap(void)
{
	struct spp_diag_trace_core_snapshot snap;
	unsigned char before[SNAP_BUF_CAP];
	unsigned char after[SNAP_BUF_CAP];
	size_t before_need = 0;
	size_t after_need = 0;
	u8 payload[200];
	const u64 max_frames = 64;
	const u64 max_bytes = 244ull + 248ull + 248ull;
	int rc;
	int admitted = 0;
	int rejected = 0;

	fill_pre_release(payload, sizeof(payload));
	spp_diag_trace_core_reset();
	spp_diag_trace_core_set_op_caps((u32)max_frames, max_bytes);
	expect_eq("byte-cap-init", init_ids(), WIRE_OK);

	rc = append_pre_release(payload, sizeof(payload));
	expect_eq("byte-cap-first", rc, WIRE_OK);
	if (rc == WIRE_OK)
		admitted++;
	rc = append_pre_release(payload, sizeof(payload));
	expect_eq("byte-cap-exact", rc, WIRE_OK);
	if (rc == WIRE_OK)
		admitted++;
	take_snap(&snap);
	expect_u64("byte-cap-exact-frames", snap.frame_count, 3);
	expect_u64("byte-cap-exact-bytes", snap.stream_byte_count, max_bytes);
	expect_eq("byte-cap-exact-green", snap.failed, 0);
	expect_eq("byte-cap-capture",
		  capture_blob(before, sizeof(before), &before_need), WIRE_OK);

	rc = append_pre_release(payload, sizeof(payload));
	expect_eq("byte-cap-over", rc, WIRE_CAP);
	if (rc != WIRE_OK)
		rejected++;
	take_snap(&snap);
	expect_eq("byte-cap-failed", snap.failed, 1);
	expect_u64("byte-cap-reject-frames", snap.frame_count, 3);
	expect_u64("byte-cap-reject-bytes", snap.stream_byte_count, max_bytes);
	if (snap.frame_count >= max_frames) {
		fprintf(stderr, "FAIL byte-cap hit frame cap first\n");
		g_fails++;
	}
	expect_eq("byte-cap-after",
		  capture_blob(after, sizeof(after), &after_need), WIRE_OK);
	if (!stream_preserved(before, before_need, after, after_need)) {
		fprintf(stderr, "FAIL byte-cap stream mutated on reject\n");
		g_fails++;
	}
	printf("ok   caps-byte-limit max_bytes=%llu admitted=%d rejected=%d frames=%llu bytes=%llu\n",
	       (unsigned long long)max_bytes, admitted, rejected,
	       (unsigned long long)snap.frame_count,
	       (unsigned long long)snap.stream_byte_count);
}

static void test_exact_frame_limit(void)
{
	struct spp_diag_trace_core_snapshot snap;
	unsigned char before[SNAP_BUF_CAP];
	unsigned char after[SNAP_BUF_CAP];
	size_t before_need = 0;
	size_t after_need = 0;
	int i;
	int rc;
	int admitted = 0;
	int rejected = 0;

	spp_diag_trace_core_reset();
	spp_diag_trace_core_set_op_caps(4, 65536);
	expect_eq("exact-frame-init", init_ids(), WIRE_OK);
	for (i = 0; i < 3; i++) {
		rc = append_terminal();
		expect_eq("exact-frame-fill", rc, WIRE_OK);
		if (rc == WIRE_OK)
			admitted++;
	}
	take_snap(&snap);
	expect_u64("exact-frame-count", snap.frame_count, 4);
	expect_eq("exact-frame-green", snap.failed, 0);
	expect_eq("exact-frame-capture",
		  capture_blob(before, sizeof(before), &before_need), WIRE_OK);
	rc = append_terminal();
	expect_eq("exact-frame-over", rc, WIRE_CAP);
	if (rc != WIRE_OK)
		rejected++;
	take_snap(&snap);
	expect_u64("exact-frame-kept", snap.frame_count, 4);
	expect_eq("exact-frame-after",
		  capture_blob(after, sizeof(after), &after_need), WIRE_OK);
	if (!stream_preserved(before, before_need, after, after_need)) {
		fprintf(stderr, "FAIL exact-frame stream mutated on reject\n");
		g_fails++;
	}
	printf("ok   caps-exact-frame max_frames=4 admitted=%d rejected=%d frames=%llu\n",
	       admitted, rejected, (unsigned long long)snap.frame_count);
}

static void test_checked_add(void)
{
	u64 out;
	u64 sentinel = 0x1111111111111111ull;
	int cases = 0;

	out = sentinel;
	expect_eq("add-overflow",
		  spp_diag_trace_core_test_checked_add_u64(~0ull, 1ull, &out),
		  WIRE_ARITHMETIC);
	expect_u64("add-overflow-unwritten", out, sentinel);
	cases++;

	out = sentinel;
	expect_eq("add-zero",
		  spp_diag_trace_core_test_checked_add_u64(0, 0, &out), WIRE_OK);
	expect_u64("add-zero-out", out, 0);
	cases++;

	out = sentinel;
	expect_eq("add-max-plus-zero",
		  spp_diag_trace_core_test_checked_add_u64(~0ull, 0, &out),
		  WIRE_OK);
	expect_u64("add-max-plus-zero-out", out, ~0ull);
	cases++;

	out = sentinel;
	expect_eq("add-in-range",
		  spp_diag_trace_core_test_checked_add_u64(196, 48, &out),
		  WIRE_OK);
	expect_u64("add-in-range-out", out, 244);
	cases++;

	printf("ok   caps-checked-add cases=%d\n", cases);
	expect_eq("checked-add-count", cases, 4);
}

int main(void)
{
	if (!IS_ENABLED(CONFIG_KUNIT)) {
		fputs("caps selftest requires CONFIG_KUNIT=1\n", stderr);
		return 2;
	}
	expect_eq("op-frames", (int)SPP_DIAG_TRACE_CORE_OP_MAX_FRAMES, 8);
	expect_u64("op-bytes", SPP_DIAG_TRACE_CORE_OP_MAX_STREAM_BYTES, 1024);
	test_frame_cap();
	test_byte_cap_before_frame_cap();
	test_exact_frame_limit();
	test_checked_add();
	if (g_fails) {
		fprintf(stderr, "%d failure(s)\n", g_fails);
		return 1;
	}
	puts("ok   spp-diag-trace-core-caps-selftest");
	return 0;
}
