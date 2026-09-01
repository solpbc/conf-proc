/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../conf_proc_spp_diag_trace.h"

/* Same-lode native vectors: baseline regression, not an independent oracle.
 * Overlap of caller-owned ranges is a non-detected precondition. */

#define CANARY ((uint8_t)0xa5)
#define CANARY2 ((uint8_t)0x3c)

#define EXPECT(cond)                                                          \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "%s:%d: EXPECT(%s) failed\n", __FILE__, __LINE__, \
                    #cond);                                                   \
            return 1;                                                         \
        }                                                                     \
    } while (0)

#define EXPECT_EQ(a, b)                                                       \
    do {                                                                      \
        long long _ea = (long long)(a);                                       \
        long long _eb = (long long)(b);                                       \
        if (_ea != _eb) {                                                     \
            fprintf(stderr, "%s:%d: EXPECT_EQ(%s=%lld, %s=%lld) failed\n",    \
                    __FILE__, __LINE__, #a, _ea, #b, _eb);                    \
            return 1;                                                         \
        }                                                                     \
    } while (0)

#define EXPECT_MEM_EQ(a, b, n)                                                \
    do {                                                                      \
        if (memcmp((a), (b), (n)) != 0) {                                     \
            fprintf(stderr, "%s:%d: EXPECT_MEM_EQ(%s, %s, %zu) failed\n",     \
                    __FILE__, __LINE__, #a, #b, (size_t)(n));                 \
            return 1;                                                         \
        }                                                                     \
    } while (0)

#define CALL(fn)                                                              \
    do {                                                                      \
        if ((fn) != 0) {                                                      \
            return 1;                                                         \
        }                                                                     \
    } while (0)

#if defined(__SANITIZE_ADDRESS__)
#define TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define TEST_ASAN 1
#endif
#endif
#ifndef TEST_ASAN
#define TEST_ASAN 0
#endif
#if TEST_ASAN
#include <sanitizer/asan_interface.h>
#endif

#if TEST_ASAN
#define EXPECT_ASAN_POISONED(p, n)                                            \
    EXPECT(__asan_region_is_poisoned((void *)(p), (n)) != NULL)
#else
#define EXPECT_ASAN_POISONED(p, n) ((void)(p), (void)(n))
#endif

static void test_asan_poison(void *ptr, size_t len)
{
#if TEST_ASAN
    if (len > 0) {
        __asan_poison_memory_region(ptr, len);
    }
#else
    (void)ptr;
    (void)len;
#endif
}

static void test_asan_unpoison(void *ptr, size_t len)
{
#if TEST_ASAN
    if (len > 0) {
        __asan_unpoison_memory_region(ptr, len);
    }
#else
    (void)ptr;
    (void)len;
#endif
}

_Static_assert(WIRE_OK == 0, "WIRE_OK");
_Static_assert(WIRE_NULL == 1, "WIRE_NULL");
_Static_assert(WIRE_BUFFER_TOO_SMALL == 2, "WIRE_BUFFER_TOO_SMALL");
_Static_assert(WIRE_MAGIC == 3, "WIRE_MAGIC");
_Static_assert(WIRE_VERSION == 4, "WIRE_VERSION");
_Static_assert(WIRE_LENGTH == 5, "WIRE_LENGTH");
_Static_assert(WIRE_VALUE == 6, "WIRE_VALUE");
_Static_assert(WIRE_RESERVED == 7, "WIRE_RESERVED");
_Static_assert(WIRE_CAP == 8, "WIRE_CAP");
_Static_assert(WIRE_EVENT == 10, "WIRE_EVENT");
_Static_assert(WIRE_FLAGS == 11, "WIRE_FLAGS");
_Static_assert(WIRE_STATE == 12, "WIRE_STATE");
_Static_assert(WIRE_SEQUENCE == 13, "WIRE_SEQUENCE");
_Static_assert(SPP_DIAG_TRACE_STREAM_PREFIX_SIZE == 4, "STREAM_PREFIX_SIZE");
_Static_assert(SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE == 196,
               "STREAM_HEADER_ENTRY_SIZE");

static const uint8_t k_commit[20] = {
    0x91, 0xa8, 0xe8, 0x26, 0x01, 0x2f, 0xbb, 0x1c, 0x7f, 0x5c,
    0xb2, 0xa3, 0x26, 0xc0, 0x8b, 0x13, 0xe3, 0x90, 0xf4, 0x69};

static void store16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void store32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void store64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

static void fill_path(uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        p[i] = (uint8_t)((i % 255) + 1);
    }
}

static void fill_header_body(uint8_t *w)
{
    memset(w, 0, 192);
    w[0] = 0x53;
    w[1] = 0x50;
    w[2] = 0x50;
    w[3] = 0x54;
    w[4] = 0x52;
    w[5] = 0x43;
    w[6] = 0x31;
    w[7] = 0x00;
    store16(w + 8, 1);
    store16(w + 10, 192);
    store16(w + 12, 1);
    store16(w + 14, 1);
    store32(w + 16, 524288u);
    store64(w + 20, 268435456ull);
    store32(w + 28, 1088u);
    memcpy(w + 32, k_commit, 20);
    store64(w + 180, 15ull);
}

static void write_header_entry(uint8_t *p)
{
    store32(p, 192);
    fill_header_body(p + 4);
}

static void layout_frame_header(uint8_t *w, uint16_t event, uint16_t flags,
                                uint32_t plen, uint64_t seq, uint64_t task,
                                uint64_t parent, uint64_t op, uint16_t phase,
                                uint16_t reserved)
{
    store16(w + 0, event);
    store16(w + 2, flags);
    store32(w + 4, plen);
    store64(w + 8, seq);
    store64(w + 16, task);
    store64(w + 24, parent);
    store64(w + 32, op);
    store16(w + 40, phase);
    store16(w + 42, reserved);
}

static size_t layout_denied(uint8_t *w, uint64_t seq, uint16_t path_len)
{
    uint32_t plen = 20u + (uint32_t)path_len;

    layout_frame_header(w, 2, 0, plen, seq, 0, 0, 1, 0, 0);
    store16(w + 44, 13);
    store16(w + 46, path_len);
    store32(w + 48, 1);
    store32(w + 52, 1);
    store64(w + 56, 0);
    fill_path(w + 64, path_len);
    return 44u + plen;
}

static size_t layout_attempt(uint8_t *w, uint64_t seq, uint16_t path_len,
                             uint16_t flags, uint16_t phase)
{
    uint32_t plen = 16u + (uint32_t)path_len;

    layout_frame_header(w, 5, flags, plen, seq, 1, 0, 1, phase, 0);
    store32(w + 44, 1);
    store16(w + 48, path_len);
    store16(w + 50, 0);
    store32(w + 52, 1);
    store32(w + 56, 1);
    fill_path(w + 60, path_len);
    return 44u + plen;
}

static size_t layout_valid_frame(uint8_t *w, uint16_t event, uint64_t seq)
{
    switch (event) {
    case 1:
        layout_frame_header(w, 1, 0, 0, seq, 0, 0, 0, 0, 0);
        return 44;
    case 2:
        return layout_denied(w, seq, 1);
    case 3:
        layout_frame_header(w, 3, 0, 8, seq, 0, 0, 0, 0, 0);
        memset(w + 44, 0, 8);
        return 52;
    case 4:
        layout_frame_header(w, 4, 0, 16, seq, 1, 0, 0, 0, 0);
        memset(w + 44, 0, 16);
        store32(w + 44, 1);
        store32(w + 48, 1);
        return 60;
    case 5:
        return layout_attempt(w, seq, 1, 1, 0);
    case 6:
        layout_frame_header(w, 6, 0, 16, seq, 1, 0, 1, 1, 0);
        store32(w + 44, 1);
        store32(w + 48, 1);
        store32(w + 52, 1);
        store32(w + 56, 0);
        return 60;
    case 7:
        layout_frame_header(w, 7, 0, 8, seq, 1, 2, 1, 1, 0);
        memset(w + 44, 0, 8);
        return 52;
    case 8:
        layout_frame_header(w, 8, 0, 16, seq, 1, 2, 1, 1, 0);
        memset(w + 44, 0, 16);
        store32(w + 44, 1);
        store32(w + 48, 1);
        return 60;
    case 9:
        layout_frame_header(w, 9, 0, 8, seq, 1, 0, 0, 2, 0);
        store16(w + 44, 1);
        store16(w + 46, 2);
        store32(w + 48, 0);
        return 52;
    case 10:
        layout_frame_header(w, 10, 0, 0, seq, 0, 0, 0, 15, 0);
        return 44;
    default:
        return 0;
    }
}

static size_t write_frame_entry(uint8_t *p, uint16_t event, uint64_t seq)
{
    size_t body = layout_valid_frame(p + 4, event, seq);
    store32(p, (uint32_t)body);
    return 4 + body;
}

static int call_ok(const uint8_t *in, size_t len, uint64_t frames,
                   uint64_t bytes)
{
    struct spp_diag_trace_stream_summary out;
    struct spp_diag_trace_stream_summary snap;
    size_t consumed;

    memset(&out, CANARY2, sizeof out);
    snap = out;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_stream_validate(in, len, &out, &consumed), WIRE_OK);
    EXPECT_EQ(consumed, len);
    EXPECT_EQ(out.frame_count, frames);
    EXPECT_EQ(out.stream_byte_count, bytes);
    EXPECT(memcmp(&out, &snap, sizeof out) != 0 || (frames == 0 && bytes == 0));
    return 0;
}

static int call_fail(const uint8_t *in, size_t len, int expected)
{
    struct spp_diag_trace_stream_summary out;
    struct spp_diag_trace_stream_summary snap;
    size_t consumed;

    memset(&out, CANARY2, sizeof out);
    snap = out;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_stream_validate(in, len, &out, &consumed),
              expected);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&out, &snap, sizeof out) == 0);
    return 0;
}

static int call_fail_poisoned(uint8_t *buf, size_t len, size_t cap, int expected)
{
    if (len < cap) {
        test_asan_poison(buf + len, cap - len);
        EXPECT_ASAN_POISONED(buf + len, 1);
        EXPECT_ASAN_POISONED(buf + cap - 1, 1);
    }
    CALL(call_fail(buf, len, expected));
    if (len < cap) {
        test_asan_unpoison(buf + len, cap - len);
    }
    return 0;
}

static int call_ok_poisoned(uint8_t *buf, size_t len, size_t cap, uint64_t frames,
                            uint64_t bytes)
{
    if (len < cap) {
        test_asan_poison(buf + len, cap - len);
        EXPECT_ASAN_POISONED(buf + len, 1);
        EXPECT_ASAN_POISONED(buf + cap - 1, 1);
    }
    CALL(call_ok(buf, len, frames, bytes));
    if (len < cap) {
        test_asan_unpoison(buf + len, cap - len);
    }
    return 0;
}

static int test_constants(void)
{
    EXPECT_EQ(SPP_DIAG_TRACE_STREAM_PREFIX_SIZE, 4);
    EXPECT_EQ(SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE, 196);
    EXPECT_EQ(4 + 192, 196);
    EXPECT_EQ(WIRE_SEQUENCE, 13);
    return 0;
}

static int test_nulls(void)
{
    uint8_t sentinel[8];
    struct spp_diag_trace_stream_summary out;
    struct spp_diag_trace_stream_summary snap;
    size_t consumed;
    size_t over = (size_t)268435456ull + 1u;

    memset(sentinel, 0x5a, sizeof sentinel);
    test_asan_poison(sentinel, sizeof sentinel);
    EXPECT_ASAN_POISONED(sentinel, 1);

    memset(&out, CANARY2, sizeof out);
    snap = out;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_stream_validate(NULL, 196, &out, &consumed),
              WIRE_NULL);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&out, &snap, sizeof out) == 0);

    memset(&out, CANARY2, sizeof out);
    snap = out;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_stream_validate(NULL, over, &out, &consumed),
              WIRE_NULL);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&out, &snap, sizeof out) == 0);

    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_stream_validate(sentinel, 196, NULL, &consumed),
              WIRE_NULL);
    EXPECT_EQ(consumed, 0);

    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_stream_validate(sentinel, over, NULL, &consumed),
              WIRE_NULL);
    EXPECT_EQ(consumed, 0);

    memset(&out, CANARY2, sizeof out);
    snap = out;
    EXPECT_EQ(spp_diag_trace_stream_validate(sentinel, 196, &out, NULL),
              WIRE_NULL);
    EXPECT(memcmp(&out, &snap, sizeof out) == 0);

    memset(&out, CANARY2, sizeof out);
    snap = out;
    EXPECT_EQ(spp_diag_trace_stream_validate(sentinel, over, &out, NULL),
              WIRE_NULL);
    EXPECT(memcmp(&out, &snap, sizeof out) == 0);

    test_asan_unpoison(sentinel, sizeof sentinel);
    return 0;
}

static int test_positives(void)
{
    uint8_t buf[2048];
    size_t n;
    size_t body;
    size_t off;
    uint16_t event;
    uint64_t i;

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    CALL(call_ok_poisoned(buf, 196, sizeof buf, 0, 196));

    for (event = 1; event <= 10; event++) {
        memset(buf, CANARY, sizeof buf);
        write_header_entry(buf);
        body = layout_valid_frame(buf + 200, event, 0);
        store32(buf + 196, (uint32_t)body);
        n = 196 + 4 + body;
        CALL(call_ok_poisoned(buf, n, sizeof buf, 1, n));
    }

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    for (i = 0; i < 10; i++) {
        uint8_t *p = buf + 196 + (size_t)i * 48u;
        store32(p, 44);
        layout_valid_frame(p + 4, 1, i);
    }
    CALL(call_ok_poisoned(buf, 676, sizeof buf, 10, 676));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    body = layout_denied(buf + 200, 0, 1024);
    store32(buf + 196, (uint32_t)body);
    n = 196 + 4 + body;
    EXPECT_EQ(body, 1088);
    EXPECT_EQ(n, 1288);
    CALL(call_ok_poisoned(buf, n, sizeof buf, 1, n));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    off = 196;
    off += write_frame_entry(buf + off, 10, 0);
    off += write_frame_entry(buf + off, 1, 1);
    CALL(call_ok_poisoned(buf, off, sizeof buf, 2, off));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    off = 196;
    off += write_frame_entry(buf + off, 1, 0);
    off += write_frame_entry(buf + off, 2, 1);
    off += write_frame_entry(buf + off, 3, 2);
    off += write_frame_entry(buf + off, 4, 3);
    off += write_frame_entry(buf + off, 5, 4);
    off += write_frame_entry(buf + off, 6, 5);
    off += write_frame_entry(buf + off, 7, 6);
    off += write_frame_entry(buf + off, 8, 7);
    off += write_frame_entry(buf + off, 9, 8);
    off += write_frame_entry(buf + off, 10, 9);
    CALL(call_ok_poisoned(buf, off, sizeof buf, 10, off));

    return 0;
}

static int test_short_and_header_prefix(void)
{
    uint8_t sentinel[8];
    uint8_t buf[200];
    uint32_t prefixes[] = {0, 1, 191, 193, 1000, 0xffffffffu};
    size_t i;
    size_t len;

    memset(sentinel, 0x5a, sizeof sentinel);
    test_asan_poison(sentinel, sizeof sentinel);
    EXPECT_ASAN_POISONED(sentinel, 1);
    CALL(call_fail(sentinel, 0, WIRE_LENGTH));
    CALL(call_fail(sentinel, 1, WIRE_LENGTH));
    CALL(call_fail(sentinel, 2, WIRE_LENGTH));
    CALL(call_fail(sentinel, 3, WIRE_LENGTH));
    test_asan_unpoison(sentinel, sizeof sentinel);

    for (i = 0; i < sizeof prefixes / sizeof prefixes[0]; i++) {
        memset(buf, CANARY, sizeof buf);
        store32(buf, prefixes[i]);
        CALL(call_fail_poisoned(buf, 4, sizeof buf, WIRE_LENGTH));
    }

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    for (len = 4; len < 196; len++) {
        CALL(call_fail_poisoned(buf, len, sizeof buf, WIRE_LENGTH));
    }
    return 0;
}

static int test_header_field_errors(void)
{
    uint8_t buf[200];
    struct {
        size_t off;
        int kind;
        int expected;
    } faults[] = {
        {4 + 0, 0, WIRE_MAGIC},
        {4 + 8, 1, WIRE_VERSION},
        {4 + 10, 1, WIRE_LENGTH},
        {4 + 12, 1, WIRE_VERSION},
        {4 + 14, 1, WIRE_VALUE},
        {4 + 16, 2, WIRE_CAP},
        {4 + 20, 3, WIRE_CAP},
        {4 + 28, 2, WIRE_CAP},
        {4 + 32, 0, WIRE_VALUE},
        {4 + 180, 3, WIRE_VALUE},
        {4 + 188, 2, WIRE_RESERVED},
    };
    size_t i;

    for (i = 0; i < sizeof faults / sizeof faults[0]; i++) {
        memset(buf, CANARY, sizeof buf);
        write_header_entry(buf);
        if (faults[i].kind == 0) {
            buf[faults[i].off] ^= 1u;
        } else if (faults[i].kind == 1) {
            store16(buf + faults[i].off, 2);
        } else if (faults[i].kind == 2) {
            store32(buf + faults[i].off, 1);
        } else {
            store64(buf + faults[i].off, 1);
        }
        CALL(call_fail_poisoned(buf, 196, sizeof buf, faults[i].expected));
    }
    return 0;
}

static int test_trailing_and_frame_prefix(void)
{
    uint8_t buf[1600];
    size_t n;
    size_t body;
    size_t extra;
    uint32_t bad_len[] = {0, 43};
    size_t i;

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    for (extra = 1; extra <= 3; extra++) {
        CALL(call_fail_poisoned(buf, 196 + extra, sizeof buf, WIRE_LENGTH));
    }

    for (i = 0; i < sizeof bad_len / sizeof bad_len[0]; i++) {
        memset(buf, CANARY, sizeof buf);
        write_header_entry(buf);
        store32(buf + 196, bad_len[i]);
        CALL(call_fail_poisoned(buf, 200, sizeof buf, WIRE_LENGTH));
    }

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    body = layout_valid_frame(buf + 200, 1, 0);
    store32(buf + 196, 44);
    n = 196 + 4 + body;
    CALL(call_ok_poisoned(buf, n, sizeof buf, 1, n));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    body = layout_denied(buf + 200, 0, 1024);
    store32(buf + 196, 1088);
    n = 196 + 4 + body;
    CALL(call_ok_poisoned(buf, n, sizeof buf, 1, n));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    store32(buf + 196, 1089);
    CALL(call_fail_poisoned(buf, 200, sizeof buf, WIRE_CAP));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    body = layout_valid_frame(buf + 200, 1, 0);
    store32(buf + 196, 44);
    n = 196 + 4 + body;
    CALL(call_fail_poisoned(buf, n + 1, sizeof buf, WIRE_LENGTH));
    return 0;
}

static int test_frame_truncations(void)
{
    uint8_t min_buf[196 + 4 + 44 + 8];
    uint8_t mid_buf[196 + 4 + 52 + 8];
    uint8_t max_buf[196 + 4 + 1088 + 8];
    size_t body;
    size_t supplied;

    memset(min_buf, CANARY, sizeof min_buf);
    write_header_entry(min_buf);
    body = layout_valid_frame(min_buf + 200, 1, 0);
    store32(min_buf + 196, 44);
    EXPECT_EQ(body, 44);
    for (supplied = 0; supplied < 44; supplied++) {
        CALL(call_fail_poisoned(min_buf, 196 + 4 + supplied, sizeof min_buf,
                                WIRE_LENGTH));
    }

    memset(mid_buf, CANARY, sizeof mid_buf);
    write_header_entry(mid_buf);
    body = layout_valid_frame(mid_buf + 200, 3, 0);
    store32(mid_buf + 196, 52);
    EXPECT_EQ(body, 52);
    for (supplied = 0; supplied < 52; supplied++) {
        CALL(call_fail_poisoned(mid_buf, 196 + 4 + supplied, sizeof mid_buf,
                                WIRE_LENGTH));
    }

    memset(max_buf, CANARY, sizeof max_buf);
    write_header_entry(max_buf);
    body = layout_denied(max_buf + 200, 0, 1024);
    store32(max_buf + 196, 1088);
    EXPECT_EQ(body, 1088);
    for (supplied = 0; supplied < 1088; supplied++) {
        CALL(call_fail_poisoned(max_buf, 196 + 4 + supplied, sizeof max_buf,
                                WIRE_LENGTH));
    }
    return 0;
}

static int test_hidden_concat_and_extent(void)
{
    uint8_t buf[512];
    size_t n;
    size_t body;

    /* Prefix 44 yields a valid CORE_INIT; leftover is a second unprefixed
     * CORE_INIT whose first four bytes read as u32be 0x00010000 (>1088). */
    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    body = layout_valid_frame(buf + 200, 1, 0);
    store32(buf + 196, 44);
    layout_valid_frame(buf + 200 + body, 1, 1);
    n = 196 + 4 + 44 + 44;
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_CAP));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    store32(buf + 196, 80);
    layout_valid_frame(buf + 200, 1, 0);
    CALL(call_fail_poisoned(buf, 196 + 4 + 20, sizeof buf, WIRE_LENGTH));
    return 0;
}

static int write_bad_frame(uint8_t *entry, int kind, uint64_t seq, size_t *n)
{
    uint8_t *body = entry + 4;
    size_t len = 44;

    switch (kind) {
    case 0:
        layout_frame_header(body, 0, 0, 0, seq, 0, 0, 0, 0, 0);
        break;
    case 1:
        layout_frame_header(body, 11, 0, 0, seq, 0, 0, 0, 0, 0);
        break;
    case 2:
        layout_frame_header(body, 1, 1, 0, seq, 0, 0, 0, 0, 0);
        break;
    case 3:
        layout_frame_header(body, 1, 0, 8, seq, 0, 0, 0, 0, 0);
        memset(body + 44, 0, 8);
        len = 52;
        break;
    case 4:
        layout_frame_header(body, 1, 0, 1045, seq, 0, 0, 0, 0, 0);
        memset(body + 44, 0, 1044);
        len = 1088;
        break;
    case 5:
        layout_frame_header(body, 1, 0, 0, seq, 1, 0, 0, 0, 0);
        break;
    case 6:
        layout_frame_header(body, 1, 0, 0, seq, 0, 1, 0, 0, 0);
        break;
    case 7:
        layout_frame_header(body, 1, 0, 0, seq, 0, 0, 1, 0, 0);
        break;
    case 8:
        layout_frame_header(body, 1, 0, 0, seq, 0, 0, 0, 1, 0);
        break;
    case 9:
        layout_frame_header(body, 1, 0, 0, seq, 0, 0, 0, 0, 1);
        break;
    case 10:
        len = layout_attempt(body, seq, 1, 1, 0);
        body[60] = 0;
        break;
    case 11:
        layout_frame_header(body, 5, 3, 17, seq, 1, 0, 1, 0, 0);
        store32(body + 44, 1);
        store16(body + 48, 1);
        store16(body + 50, 0);
        store32(body + 52, 1);
        store32(body + 56, 1);
        body[60] = 0x61;
        len = 61;
        break;
    default:
        return 1;
    }
    store32(entry, (uint32_t)len);
    *n = 4 + len;
    return 0;
}

static int test_frame_errors_before_sequence(void)
{
    uint8_t buf[196 + 4 + 1088 + 8];
    int expected[] = {
        WIRE_EVENT,    WIRE_EVENT, WIRE_FLAGS,    WIRE_LENGTH, WIRE_CAP,
        WIRE_VALUE,    WIRE_VALUE, WIRE_VALUE,    WIRE_STATE,  WIRE_RESERVED,
        WIRE_VALUE,    WIRE_FLAGS};
    size_t i;
    size_t entry;

    for (i = 0; i < sizeof expected / sizeof expected[0]; i++) {
        memset(buf, CANARY, sizeof buf);
        write_header_entry(buf);
        CALL(write_bad_frame(buf + 196, (int)i, 1, &entry));
        CALL(call_fail_poisoned(buf, 196 + entry, sizeof buf, expected[i]));
    }
    return 0;
}

static int test_sequence(void)
{
    uint8_t buf[1600];
    size_t off;
    size_t body;
    size_t entry;
    uint16_t event;

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    store32(buf + 196, 44);
    layout_valid_frame(buf + 200, 1, 1);
    CALL(call_fail_poisoned(buf, 244, sizeof buf, WIRE_SEQUENCE));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    store32(buf + 196, 44);
    layout_valid_frame(buf + 200, 1, ~(uint64_t)0);
    CALL(call_fail_poisoned(buf, 244, sizeof buf, WIRE_SEQUENCE));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    off = 196;
    off += write_frame_entry(buf + off, 1, 0);
    off += write_frame_entry(buf + off, 1, 0);
    CALL(call_fail_poisoned(buf, off, sizeof buf, WIRE_SEQUENCE));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    off = 196;
    off += write_frame_entry(buf + off, 1, 0);
    off += write_frame_entry(buf + off, 1, 2);
    CALL(call_fail_poisoned(buf, off, sizeof buf, WIRE_SEQUENCE));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    off = 196;
    off += write_frame_entry(buf + off, 1, 0);
    off += write_frame_entry(buf + off, 1, 1);
    off += write_frame_entry(buf + off, 1, 0);
    CALL(call_fail_poisoned(buf, off, sizeof buf, WIRE_SEQUENCE));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    off = 196;
    off += write_frame_entry(buf + off, 1, 0);
    off += write_frame_entry(buf + off, 1, 1);
    off += write_frame_entry(buf + off, 1, 5);
    CALL(call_fail_poisoned(buf, off, sizeof buf, WIRE_SEQUENCE));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    CALL(write_bad_frame(buf + 196, 2, 1, &entry));
    CALL(call_fail_poisoned(buf, 196 + entry, sizeof buf, WIRE_FLAGS));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    off = 196;
    off += write_frame_entry(buf + off, 1, 0);
    body = layout_denied(buf + off + 4, 1, 64);
    store32(buf + off, (uint32_t)body);
    off += 4 + body;
    off += write_frame_entry(buf + off, 3, 2);
    body = layout_attempt(buf + off + 4, 3, 8, 0, 1);
    store32(buf + off, (uint32_t)body);
    off += 4 + body;
    off += write_frame_entry(buf + off, 6, 4);
    off += write_frame_entry(buf + off, 7, 5);
    off += write_frame_entry(buf + off, 8, 6);
    off += write_frame_entry(buf + off, 9, 7);
    off += write_frame_entry(buf + off, 4, 8);
    off += write_frame_entry(buf + off, 10, 9);
    CALL(call_ok_poisoned(buf, off, sizeof buf, 10, off));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf);
    off = 196;
    for (event = 1; event <= 10; event++) {
        off += write_frame_entry(buf + off, event, (uint64_t)(event - 1));
    }
    CALL(call_ok_poisoned(buf, off, sizeof buf, 10, off));
    return 0;
}

static int test_count_cap(void)
{
    const size_t stream_ok = 25166020;
    const size_t extra = 48;
    uint8_t *buf;
    uint8_t *p;
    size_t i;
    struct spp_diag_trace_stream_summary out;
    struct spp_diag_trace_stream_summary snap;
    size_t consumed;

    buf = malloc(stream_ok + extra + 1);
    EXPECT(buf != NULL);
    store32(buf, 192);
    fill_header_body(buf + 4);
    for (i = 0; i < 524289; i++) {
        p = buf + 196 + i * 48;
        store32(p, 44);
        layout_valid_frame(p + 4, 1, (uint64_t)i);
    }
    buf[stream_ok + extra] = CANARY;

    test_asan_poison(buf + stream_ok, extra + 1);
    EXPECT_ASAN_POISONED(buf + stream_ok, 1);
    EXPECT_ASAN_POISONED(buf + stream_ok + extra, 1);
    if (call_ok(buf, stream_ok, 524288, 25166020) != 0) {
        test_asan_unpoison(buf + stream_ok, extra + 1);
        free(buf);
        return 1;
    }
    test_asan_unpoison(buf + stream_ok, extra + 1);

    test_asan_poison(buf + stream_ok + extra, 1);
    EXPECT_ASAN_POISONED(buf + stream_ok + extra, 1);
    memset(&out, CANARY2, sizeof out);
    snap = out;
    consumed = (size_t)-1;
    if (spp_diag_trace_stream_validate(buf, stream_ok + extra, &out, &consumed) !=
            WIRE_CAP ||
        consumed != 0 || memcmp(&out, &snap, sizeof out) != 0) {
        fprintf(stderr, "%s:%d: exact 524289th valid frame did not yield WIRE_CAP\n",
                __FILE__, __LINE__);
        test_asan_unpoison(buf + stream_ok + extra, 1);
        free(buf);
        return 1;
    }
    test_asan_unpoison(buf + stream_ok + extra, 1);

    store16(buf + stream_ok + 4, 0);
    if (call_fail_poisoned(buf, stream_ok + extra, stream_ok + extra + 1,
                           WIRE_EVENT) != 0) {
        free(buf);
        return 1;
    }

    store16(buf + stream_ok + 4, 1);
    store64(buf + stream_ok + 12, 0);
    if (call_fail_poisoned(buf, stream_ok + extra, stream_ok + extra + 1,
                           WIRE_SEQUENCE) != 0) {
        free(buf);
        return 1;
    }

    store64(buf + stream_ok + 12, 999999ull);
    if (call_fail_poisoned(buf, stream_ok + extra, stream_ok + extra + 1,
                           WIRE_SEQUENCE) != 0) {
        free(buf);
        return 1;
    }

    store64(buf + stream_ok + 12, 524288ull);
    if (call_fail_poisoned(buf, stream_ok + extra, stream_ok + extra + 1,
                           WIRE_CAP) != 0) {
        free(buf);
        return 1;
    }

    free(buf);
    return 0;
}

static int test_over_cap_sentinel(void)
{
    uint8_t sentinel[8];

    memset(sentinel, 0x5a, sizeof sentinel);
    test_asan_poison(sentinel, sizeof sentinel);
    EXPECT_ASAN_POISONED(sentinel, 1);
    CALL(call_fail(sentinel, (size_t)268435456ull + 1u, WIRE_CAP));
    test_asan_unpoison(sentinel, sizeof sentinel);
    return 0;
}

int run_spp_diag_trace_stream_tests(void)
{
    if (test_constants() != 0) {
        return 1;
    }
    if (test_nulls() != 0) {
        return 1;
    }
    if (test_positives() != 0) {
        return 1;
    }
    if (test_short_and_header_prefix() != 0) {
        return 1;
    }
    if (test_header_field_errors() != 0) {
        return 1;
    }
    if (test_trailing_and_frame_prefix() != 0) {
        return 1;
    }
    if (test_frame_truncations() != 0) {
        return 1;
    }
    if (test_hidden_concat_and_extent() != 0) {
        return 1;
    }
    if (test_frame_errors_before_sequence() != 0) {
        return 1;
    }
    if (test_sequence() != 0) {
        return 1;
    }
    if (test_count_cap() != 0) {
        return 1;
    }
    if (test_over_cap_sentinel() != 0) {
        return 1;
    }
    return 0;
}
