/* SPDX-License-Identifier: GPL-2.0-only */

#include "core.h"

#include <crypto/sha2.h>
#include <linux/irqflags.h>
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

static int init_seed(u8 seed)
{
	u8 id[32];

	memset(id, seed, sizeof(id));
	return spp_diag_trace_core_init(id, id, id, id);
}

static int contains_bytes(const u8 *hay, unsigned hay_n, const u8 *needle,
			  unsigned needle_n)
{
	unsigned i;

	if (needle_n > hay_n)
		return 0;
	for (i = 0; i + needle_n <= hay_n; i++) {
		if (memcmp(hay + i, needle, needle_n) == 0)
			return 1;
	}
	return 0;
}

static void test_production_alloc(void)
{
	struct host_vmalloc_record rec;
	int rc;

	spp_diag_trace_core_reset();
	host_vmalloc_reset_instrumentation();
	/*
	 * CONFIG_KUNIT defaults max_stream_bytes_op to 1024. Request the
	 * production cap once so the shim records the real size, then reset.
	 */
	spp_diag_trace_core_set_op_caps(SPP_DIAG_TRACE_MAX_FRAMES,
					SPP_DIAG_TRACE_MAX_STREAM_BYTES);
	rc = init_seed(0x5a);
	expect_eq("prod-init", rc, WIRE_OK);
	rec = host_vmalloc_record();
	expect_u64("prod-alloc-size", rec.last_alloc_size,
		   SPP_DIAG_TRACE_MAX_STREAM_BYTES);
	expect_eq("prod-alloc-irqs", rec.last_alloc_irqs_disabled, 0);
	expect_eq("prod-alloc-lock", rec.last_alloc_lock_held, 0);
	spp_diag_trace_core_reset();
	printf("ok   context-production-alloc size=%lu\n", rec.last_alloc_size);
}

static void test_reset_free_path(void)
{
	struct host_vmalloc_record rec;

	spp_diag_trace_core_reset();
	host_vmalloc_reset_instrumentation();
	expect_eq("reset-free-init", init_seed(0x61), WIRE_OK);
	rec = host_vmalloc_record();
	expect_eq("reset-free-alloc", (int)rec.alloc_count, 1);
	spp_diag_trace_core_reset();
	rec = host_vmalloc_record();
	expect_eq("reset-free-count", (int)rec.free_count, 1);
	expect_eq("reset-free-irqs", rec.last_free_irqs_disabled, 0);
	expect_eq("reset-free-lock", rec.last_free_lock_held, 0);
	printf("ok   context-reset-free irqs=%d lock=%d\n",
	       rec.last_free_irqs_disabled, rec.last_free_lock_held);
}

static void test_irq_disabled_ops(void)
{
	unsigned long flags;
	int green;
	int append_rc;
	int mark_rc;
	unsigned alloc_before;
	struct host_vmalloc_record rec;

	spp_diag_trace_core_reset();
	expect_eq("irq-init", init_seed(0x71), WIRE_OK);
	host_vmalloc_reset_instrumentation();
	alloc_before = host_vmalloc_record().alloc_count;
	local_irq_save(flags);
	green = spp_diag_trace_core_is_green();
	append_rc = spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0,
					       0, 0, 0,
					       SPP_DIAG_TRACE_PHASE_SEALED,
					       NULL, 0);
	mark_rc = spp_diag_trace_core_mark_failure(WIRE_CAP);
	local_irq_restore(flags);
	expect_eq("irq-green", green, 1);
	expect_eq("irq-append", append_rc, WIRE_OK);
	expect_eq("irq-mark", mark_rc, WIRE_CAP);
	rec = host_vmalloc_record();
	expect_eq("irq-no-alloc", (int)rec.alloc_count, (int)alloc_before);
	printf("ok   context-irq-ops green=%d append=%d mark=%d\n", green,
	       append_rc, mark_rc);
}

static void test_sha_sentinels(void)
{
	struct spp_diag_trace_core_snapshot snap;
	u8 sentinel0[32];
	u8 sentinel1[32];
	u8 sentinel2[32];
	u8 preimage[1151];
	unsigned pre_len = 0;
	unsigned calls;

	memset(sentinel0, 0xa1, sizeof(sentinel0));
	memset(sentinel1, 0xb2, sizeof(sentinel1));
	memset(sentinel2, 0xc3, sizeof(sentinel2));
	spp_diag_trace_core_reset();
	host_sha256_reset_instrumentation();
	host_sha256_push_sentinel(sentinel0);
	host_sha256_push_sentinel(sentinel1);
	host_sha256_push_sentinel(sentinel2);
	expect_eq("sha-init", init_seed(0x81), WIRE_OK);
	calls = host_sha256_call_count();
	expect_eq("sha-init-calls", (int)calls, 2);
	expect_eq("sha-snap", take_snap(&snap), WIRE_OK);
	expect_mem("sha-header-chain", snap.header_chain, sentinel0, 32);
	expect_mem("sha-core-init-chain", snap.chain, sentinel1, 32);
	expect_eq("sha-append",
		  spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0,
					     0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
					     NULL, 0),
		  WIRE_OK);
	calls = host_sha256_call_count();
	expect_eq("sha-append-calls", (int)calls, 3);
	if (!host_sha256_get_preimage(2, preimage, &pre_len)) {
		fprintf(stderr, "FAIL sha-preimage missing\n");
		g_fails++;
	} else if (!contains_bytes(preimage, pre_len, sentinel1, 32)) {
		fprintf(stderr, "FAIL sha-preimage missing prior sentinel\n");
		g_fails++;
	}
	expect_eq("sha-snap-append", take_snap(&snap), WIRE_OK);
	expect_mem("sha-final-chain", snap.chain, sentinel2, 32);
	host_sha256_reset_instrumentation();
	printf("ok   context-sha-sentinels calls=%u preimage=%u\n", calls,
	       pre_len);
}

int main(void)
{
	{
		const char *forced = getenv("SPP_DIAG_TRACE_CORE_FORCE_FAIL");

		if (forced != NULL && forced[0] == '1') {
			fputs("FAIL context-selftest forced\n", stderr);
			return 1;
		}
	}
	if (!IS_ENABLED(CONFIG_KUNIT)) {
		fputs("context selftest requires CONFIG_KUNIT=1\n", stderr);
		return 2;
	}
	test_production_alloc();
	test_reset_free_path();
	test_sha_sentinels();
	test_irq_disabled_ops();
	if (g_fails) {
		fputs("FAIL spp-diag-trace-core-context-selftest\n", stderr);
		return 1;
	}
	puts("ok   spp-diag-trace-core-context-selftest alloc_bytes=268435456 sha_calls=3 irq_ops=3");
	return 0;
}
