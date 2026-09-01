/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../conf_proc_spp_diag_trace.h"

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

_Static_assert(SPP_DIAG_TRACE_FILE_POLICY_DECISION_PAYLOAD_SIZE == 48,
               "payload size");
_Static_assert(SPP_DIAG_TRACE_FRAME_HEADER_SIZE +
                   SPP_DIAG_TRACE_FILE_POLICY_DECISION_PAYLOAD_SIZE == 92,
               "frame size");
_Static_assert(SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN + SPP_DIAG_TRACE_CHAIN_LEN +
                       4 + 92 == 155,
               "preimage size");

static const uint8_t k_literal_wire[92] = {
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x35,
    0x00, 0x02, 0x00, 0x03, 0xff, 0xff, 0xff, 0xfb, 0x10, 0x20, 0x30, 0x40,
    0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

static const uint8_t k_preimage_zero[155] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x5c, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x35, 0x00, 0x02, 0x00, 0x03, 0xff, 0xff, 0xff, 0xfb, 0x10,
    0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
    0xee, 0xff, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

static const uint8_t k_preimage_nz[155] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x00,
    0x00, 0x00, 0x5c, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x35, 0x00, 0x02, 0x00, 0x03, 0xff, 0xff, 0xff, 0xfb, 0x10,
    0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
    0xee, 0xff, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

struct frame_box {
    uint8_t pre[8];
    struct spp_diag_trace_frame f;
    uint8_t post[8];
};

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

static void layout_header44(uint8_t *w, const struct spp_diag_trace_frame *f)
{
    store16(w + 0, f->event_type);
    store16(w + 2, f->flags);
    store32(w + 4, f->payload_length);
    store64(w + 8, f->sequence);
    store64(w + 16, f->task_ordinal);
    store64(w + 24, f->parent_task_ordinal);
    store64(w + 32, f->operation_ordinal);
    store16(w + 40, f->phase);
    store16(w + 42, f->reserved);
}

static void layout_frame(uint8_t *w, const struct spp_diag_trace_frame *f)
{
    layout_header44(w, f);
    if (f->payload_length <= SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES) {
        memcpy(w + 44, f->payload, f->payload_length);
    }
}

static void zero_unused(struct spp_diag_trace_frame *f)
{
    size_t i;
    for (i = f->payload_length; i < SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES; i++) {
        f->payload[i] = 0;
    }
}

static int frame_eq(const struct spp_diag_trace_frame *a,
                    const struct spp_diag_trace_frame *b)
{
    if (a->event_type != b->event_type || a->flags != b->flags ||
        a->payload_length != b->payload_length || a->sequence != b->sequence ||
        a->task_ordinal != b->task_ordinal ||
        a->parent_task_ordinal != b->parent_task_ordinal ||
        a->operation_ordinal != b->operation_ordinal || a->phase != b->phase ||
        a->reserved != b->reserved) {
        return 0;
    }
    if (memcmp(a->payload, b->payload, a->payload_length) != 0) {
        return 0;
    }
    return 1;
}

static void fill_valid(struct spp_diag_trace_frame *f)
{
    memset(f, 0, sizeof *f);
    f->event_type = SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION;
    f->payload_length = SPP_DIAG_TRACE_FILE_POLICY_DECISION_PAYLOAD_SIZE;
    f->task_ordinal = 1;
    f->operation_ordinal = 1;
    f->phase = 1;
    store16(f->payload + 0, SPP_DIAG_TRACE_FILE_ACCESS_READ);
    store16(f->payload + 4, SPP_DIAG_TRACE_POLICY_ALLOW);
    store16(f->payload + 6, SPP_DIAG_TRACE_FILE_OBJECT_REGULAR);
    store64(f->payload + 24, 1);
    store64(f->payload + 32, 1);
}

static void fill_distinct(struct spp_diag_trace_frame *f)
{
    memset(f, 0, sizeof *f);
    f->event_type = SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION;
    f->payload_length = SPP_DIAG_TRACE_FILE_POLICY_DECISION_PAYLOAD_SIZE;
    f->task_ordinal = 1;
    f->operation_ordinal = 1;
    f->phase = 1;
    store16(f->payload + 0, 0x0004);
    store16(f->payload + 2, 0x0035);
    store16(f->payload + 4, 0x0002);
    store16(f->payload + 6, 0x0003);
    store32(f->payload + 8, 0xfffffffb);
    store32(f->payload + 12, 0x10203040);
    store32(f->payload + 16, 0x50607080);
    store32(f->payload + 20, 0x90a0b0c0);
    store64(f->payload + 24, UINT64_C(0x1122334455667788));
    store64(f->payload + 32, UINT64_C(0x99aabbccddeeff00));
    store64(f->payload + 40, UINT64_C(0x0123456789abcdef));
}

static void fill_open_min(struct spp_diag_trace_frame *f)
{
    memset(f, 0, sizeof *f);
    f->event_type = SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT;
    f->payload_length = 17;
    f->task_ordinal = 1;
    f->operation_ordinal = 1;
    f->phase = 1;
    store16(f->payload + 0, 1);
    store16(f->payload + 2, 1);
    store16(f->payload + 4, 1);
    f->payload[16] = 0x2f;
}

static int expect_canary(const uint8_t *bytes, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        EXPECT_EQ(bytes[i], CANARY);
    }
    return 0;
}

static int expect_fail_meta(int result, int expected, size_t written,
                            size_t required, const uint8_t *out, size_t out_len)
{
    EXPECT_EQ(result, expected);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, out_len));
    return 0;
}

static size_t decode_len_for(const struct spp_diag_trace_frame *f)
{
    size_t n;

    n = (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE +
        (f->payload_length <= SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES
             ? f->payload_length
             : 0);
    return n < 44 ? 44 : n;
}

static int api_fail_struct(const struct spp_diag_trace_frame *f, int expected,
                           void *later, size_t later_n)
{
    uint8_t out[32];
    uint8_t pre[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    uint8_t chain[SPP_DIAG_TRACE_CHAIN_LEN];
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 8];
    size_t written, required, consumed;
    struct frame_box box, snap;
    size_t n;
    size_t i;

    memset(chain, 0x11, sizeof chain);
    n = decode_len_for(f);

    if (later_n > 0) {
        test_asan_poison(later, later_n);
        EXPECT_ASAN_POISONED(later, 1);
        EXPECT_ASAN_POISONED((uint8_t *)later + later_n - 1, 1);
    }

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    {
        int result = spp_diag_trace_provenance_frame_encode(
            f, out, sizeof out, &written, &required);
        CALL(expect_fail_meta(result, expected, written, required, out,
                              sizeof out));
    }

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    {
        int result = spp_diag_trace_provenance_frame_encode(f, out, 0, &written,
                                                            &required);
        CALL(expect_fail_meta(result, expected, written, required, out,
                              sizeof out));
    }

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    {
        int result = spp_diag_trace_provenance_frame_encode(f, out, 91, &written,
                                                            &required);
        CALL(expect_fail_meta(result, expected, written, required, out,
                              sizeof out));
    }

    memset(pre, CANARY, sizeof pre);
    written = required = (size_t)-1;
    {
        int result = spp_diag_trace_provenance_frame_preimage(
            f, chain, pre, sizeof pre, &written, &required);
        CALL(expect_fail_meta(result, expected, written, required, pre,
                              sizeof pre));
    }

    memset(pre, CANARY, sizeof pre);
    written = required = (size_t)-1;
    {
        int result = spp_diag_trace_provenance_frame_preimage(
            f, chain, pre, 0, &written, &required);
        CALL(expect_fail_meta(result, expected, written, required, pre,
                              sizeof pre));
    }

    memset(pre, CANARY, sizeof pre);
    written = required = (size_t)-1;
    {
        int result = spp_diag_trace_provenance_frame_preimage(
            f, chain, pre, 154, &written, &required);
        CALL(expect_fail_meta(result, expected, written, required, pre,
                              sizeof pre));
    }

    if (later_n > 0) {
        test_asan_unpoison(later, later_n);
    }

    memset(wire, CANARY, sizeof wire);
    layout_frame(wire, f);
    memset(&box, CANARY2, sizeof box);
    snap = box;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(wire, n, &box.f, &consumed),
              expected);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    for (i = n; i < sizeof wire; i++) {
        EXPECT_EQ(wire[i], CANARY);
    }
    return 0;
}

static int api_fail_decode_wire(const uint8_t *wire, size_t len, int expected,
                                void *later, size_t later_n)
{
    struct frame_box box, snap;
    size_t consumed;

    if (later_n > 0) {
        test_asan_poison(later, later_n);
        EXPECT_ASAN_POISONED(later, 1);
        EXPECT_ASAN_POISONED((uint8_t *)later + later_n - 1, 1);
    }
    memset(&box, CANARY2, sizeof box);
    snap = box;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(wire, len, &box.f,
                                                     &consumed),
              expected);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    if (later_n > 0) {
        test_asan_unpoison(later, later_n);
    }
    return 0;
}

static int cheap_fail_struct(const struct spp_diag_trace_frame *f, int expected)
{
    uint8_t out[128];
    uint8_t pre[256];
    uint8_t chain[32];
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    struct spp_diag_trace_frame got;
    size_t written, required, consumed;
    size_t n;

    n = decode_len_for(f);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(f, out, sizeof out,
                                                     &written, &required),
              expected);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);

    memset(chain, 0x11, sizeof chain);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                  f, chain, pre, sizeof pre, &written, &required),
              expected);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);

    layout_frame(wire, f);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(wire, n, &got, &consumed),
              expected);
    EXPECT_EQ(consumed, 0);
    return 0;
}

static int expect_ok_both_paths(const struct spp_diag_trace_frame *f)
{
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    uint8_t got[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    uint8_t pre[256];
    uint8_t chain[32];
    struct frame_box decoded;
    struct spp_diag_trace_frame expect;
    size_t written, required, consumed;
    size_t n;
    size_t i;

    n = (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE + (size_t)f->payload_length;
    layout_frame(wire, f);

    memset(got, CANARY, sizeof got);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(f, got, n, &written,
                                                     &required),
              WIRE_OK);
    EXPECT_EQ(written, n);
    EXPECT_EQ(required, n);
    EXPECT_MEM_EQ(got, wire, n);

    memset(chain, 0, sizeof chain);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(f, chain, pre, sizeof pre,
                                                       &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)27 + 32 + 4 + n);
    EXPECT_EQ(required, (size_t)27 + 32 + 4 + n);

    memset(&decoded, CANARY2, sizeof decoded);
    consumed = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(wire, n, &decoded.f,
                                                     &consumed),
              WIRE_OK);
    EXPECT_EQ(consumed, n);
    expect = *f;
    zero_unused(&expect);
    EXPECT(frame_eq(&decoded.f, &expect));
    for (i = 0; i < sizeof decoded.pre; i++) {
        EXPECT_EQ(decoded.pre[i], CANARY2);
        EXPECT_EQ(decoded.post[i], CANARY2);
    }
    for (i = decoded.f.payload_length; i < SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES;
         i++) {
        EXPECT_EQ(decoded.f.payload[i], 0);
    }
    return 0;
}

typedef void (*frame_poison_fn)(struct spp_diag_trace_frame *);

struct step {
    const char *name;
    frame_poison_fn poison;
    int expected;
    size_t woff;
    size_t wlen;
    size_t soff;
    size_t slen;
};

static void hp_event0(struct spp_diag_trace_frame *f) { f->event_type = 0; }
static void hp_flags1(struct spp_diag_trace_frame *f) { f->flags = 1; }
static void hp_plen_cap(struct spp_diag_trace_frame *f)
{
    f->payload_length = 1045;
}
static void hp_plen47(struct spp_diag_trace_frame *f) { f->payload_length = 47; }
static void hp_task_z(struct spp_diag_trace_frame *f) { f->task_ordinal = 0; }
static void hp_parent_nz(struct spp_diag_trace_frame *f)
{
    f->parent_task_ordinal = 1;
}
static void hp_op_z(struct spp_diag_trace_frame *f) { f->operation_ordinal = 0; }
static void hp_phase0(struct spp_diag_trace_frame *f) { f->phase = 0; }
static void hp_res(struct spp_diag_trace_frame *f) { f->reserved = 1; }
static void pp_access0(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 0, 0);
}
static void pp_mod_unk(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 2, 0x0040);
}
static void pp_decision0(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 4, 0);
}
static void pp_object0(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 6, 0);
}
static void pp_result_bad(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 8, 1);
}
static void pp_inode0(struct spp_diag_trace_frame *f)
{
    store64(f->payload + 24, 0);
}
static void pp_mount0(struct spp_diag_trace_frame *f)
{
    store64(f->payload + 32, 0);
}

#define SOFF(field) offsetof(struct spp_diag_trace_frame, field)
#define SL(field) sizeof(((struct spp_diag_trace_frame *)0)->field)

static int run_pairs(const struct spp_diag_trace_frame *base,
                     const struct step *steps, size_t nsteps)
{
    size_t i;
    struct spp_diag_trace_frame f;
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 16];
    size_t len;
    int same_field;

    for (i = 0; i < nsteps; i++) {
        f = *base;
        steps[i].poison(&f);
        CALL(api_fail_struct(&f, steps[i].expected, NULL, 0));
    }
    for (i = 0; i + 1 < nsteps; i++) {
        same_field = (steps[i].woff == steps[i + 1].woff &&
                      steps[i].wlen == steps[i + 1].wlen);
        f = *base;
        steps[i].poison(&f);
        if (!same_field) {
            steps[i + 1].poison(&f);
        }
        CALL(api_fail_struct(&f, steps[i].expected, NULL, 0));

        f = *base;
        steps[i].poison(&f);
        if (steps[i].expected == steps[i + 1].expected &&
            steps[i + 1].slen > 0 && !same_field) {
            CALL(api_fail_struct(&f, steps[i].expected,
                                 (uint8_t *)&f + steps[i + 1].soff,
                                 sizeof f - steps[i + 1].soff));
        }

        f = *base;
        steps[i].poison(&f);
        memset(wire, CANARY, sizeof wire);
        layout_frame(wire, &f);
        len = decode_len_for(&f);
        if (steps[i].expected == steps[i + 1].expected &&
            steps[i + 1].wlen > 0 && !same_field) {
            CALL(api_fail_decode_wire(wire, len, steps[i].expected,
                                      wire + steps[i + 1].woff,
                                      sizeof wire - steps[i + 1].woff));
        }
    }
    return 0;
}

static int test_compatibility(void)
{
    struct spp_diag_trace_frame f;
    struct spp_diag_trace_header h;
    struct spp_diag_trace_stream_summary sum;
    uint8_t out[128];
    uint8_t pre[256];
    uint8_t chain[32];
    uint8_t header_wire[192];
    uint8_t frame_wire[92];
    uint8_t stream[4 + 192 + 4 + 92];
    size_t written, required, consumed;
    unsigned v;

    EXPECT_EQ(SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION, 0x0101);
    EXPECT_EQ(SPP_DIAG_TRACE_POLICY_ALLOW, 1);
    EXPECT_EQ(SPP_DIAG_TRACE_POLICY_DENY, 2);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_OBJECT_REGULAR, 1);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_OBJECT_DIRECTORY, 2);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_OBJECT_MEMFD, 3);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_OBJECT_OTHER, 4);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_POLICY_DECISION_PAYLOAD_SIZE, 48);

    fill_open_min(&f);
    CALL(expect_ok_both_paths(&f));

    fill_valid(&f);
    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_encode(&f, out, sizeof out, &written,
                                          &required),
              WIRE_EVENT);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    layout_frame(out, &f);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_decode(out, 92, &f, &consumed), WIRE_EVENT);
    EXPECT_EQ(consumed, 0);

    fill_valid(&f);
    memset(chain, 0, sizeof chain);
    memset(pre, CANARY, sizeof pre);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_preimage(&f, chain, pre, sizeof pre, &written,
                                            &required),
              WIRE_EVENT);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(pre, sizeof pre));

    memset(&h, 0, sizeof h);
    memcpy(h.magic, "SPPTRC1", 7);
    h.magic[7] = 0;
    h.wire_version = SPP_DIAG_TRACE_WIRE_VERSION;
    h.header_length = SPP_DIAG_TRACE_HEADER_SIZE;
    h.policy_version = SPP_DIAG_TRACE_POLICY_VERSION;
    h.hash_algorithm = SPP_DIAG_TRACE_HASH_SHA256;
    h.max_frames = SPP_DIAG_TRACE_MAX_FRAMES;
    h.max_stream_bytes = SPP_DIAG_TRACE_MAX_STREAM_BYTES;
    h.max_frame_bytes = SPP_DIAG_TRACE_MAX_FRAME_BYTES;
    memcpy(h.source_commit, SPP_DIAG_TRACE_SOURCE_COMMIT,
           SPP_DIAG_TRACE_SOURCE_COMMIT_LEN);
    h.required_hook_mask = SPP_DIAG_TRACE_HOOK_MASK;
    EXPECT_EQ(spp_diag_trace_header_encode(&h, header_wire, sizeof header_wire,
                                           &written, &required),
              WIRE_OK);
    fill_valid(&f);
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, frame_wire,
                                                     sizeof frame_wire, &written,
                                                     &required),
              WIRE_OK);
    store32(stream, 192);
    memcpy(stream + 4, header_wire, 192);
    store32(stream + 196, 92);
    memcpy(stream + 200, frame_wire, 92);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_stream_validate(stream, sizeof stream, &sum,
                                             &consumed),
              WIRE_EVENT);
    EXPECT_EQ(consumed, 0);

    for (v = 0; v <= 0xffffu; v++) {
        if (v == SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT ||
            v == SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION) {
            continue;
        }
        fill_valid(&f);
        f.event_type = (uint16_t)v;
        CALL(cheap_fail_struct(&f, WIRE_EVENT));
    }
    return 0;
}

static int roundtrip_literal(void)
{
    struct spp_diag_trace_frame f;
    uint8_t got[92];
    uint8_t pre[155];
    uint8_t chain[32];
    struct frame_box decoded;
    size_t written, required, consumed;
    size_t i;

    fill_distinct(&f);
    memset(got, CANARY, sizeof got);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, got, sizeof got,
                                                     &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)92);
    EXPECT_EQ(required, (size_t)92);
    EXPECT_MEM_EQ(got, k_literal_wire, 92);
    EXPECT_MEM_EQ(got + 68, k_literal_wire + 68, 8);
    EXPECT_MEM_EQ(got + 76, k_literal_wire + 76, 8);
    EXPECT(memcmp(got + 68, got + 76, 8) != 0);

    store64(f.payload + 24, UINT64_C(0x99aabbccddeeff00));
    store64(f.payload + 32, UINT64_C(0x1122334455667788));
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, got, sizeof got,
                                                     &written, &required),
              WIRE_OK);
    EXPECT(memcmp(got, k_literal_wire, 92) != 0);
    EXPECT_MEM_EQ(got + 68, k_literal_wire + 76, 8);
    EXPECT_MEM_EQ(got + 76, k_literal_wire + 68, 8);

    fill_distinct(&f);
    memset(chain, 0, sizeof chain);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, pre, sizeof pre,
                                                       &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)155);
    EXPECT_EQ(required, (size_t)155);
    EXPECT_MEM_EQ(pre, k_preimage_zero, 155);
    EXPECT_MEM_EQ(pre + 63, k_literal_wire, 92);

    for (i = 0; i < 32; i++) {
        chain[i] = (uint8_t)(i + 1);
    }
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, pre, sizeof pre,
                                                       &written, &required),
              WIRE_OK);
    EXPECT_MEM_EQ(pre, k_preimage_nz, 155);
    EXPECT_EQ(pre[27], 0x01);

    memset(&decoded, CANARY2, sizeof decoded);
    consumed = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(k_literal_wire, 92,
                                                     &decoded.f, &consumed),
              WIRE_OK);
    EXPECT_EQ(consumed, (size_t)92);
    EXPECT_EQ(decoded.f.event_type, 0x0101);
    EXPECT_EQ(decoded.f.payload_length, 48);
    EXPECT_EQ(decoded.f.task_ordinal, 1);
    EXPECT_EQ(decoded.f.operation_ordinal, 1);
    EXPECT_EQ(decoded.f.phase, 1);
    EXPECT(frame_eq(&decoded.f, &f));
    EXPECT_EQ(decoded.f.payload[0], 0x00);
    EXPECT_EQ(decoded.f.payload[1], 0x04);
    EXPECT_EQ(decoded.f.payload[24], 0x11);
    EXPECT_EQ(decoded.f.payload[32], 0x99);
    return 0;
}

static int test_literals(void)
{
    struct spp_diag_trace_frame f;
    unsigned v;

    EXPECT_EQ(sizeof k_literal_wire, (size_t)92);
    EXPECT_EQ(sizeof k_preimage_zero, (size_t)155);
    EXPECT_EQ(sizeof k_preimage_nz, (size_t)155);
    EXPECT_MEM_EQ(k_preimage_zero + 63, k_literal_wire, 92);
    EXPECT_MEM_EQ(k_preimage_nz + 63, k_literal_wire, 92);

    CALL(roundtrip_literal());

    fill_distinct(&f);
    f.sequence = 0;
    CALL(expect_ok_both_paths(&f));
    f.sequence = UINT64_MAX;
    CALL(expect_ok_both_paths(&f));

    fill_valid(&f);
    f.task_ordinal = 1;
    CALL(expect_ok_both_paths(&f));
    f.task_ordinal = UINT64_MAX;
    CALL(expect_ok_both_paths(&f));
    f.task_ordinal = 0;
    CALL(cheap_fail_struct(&f, WIRE_VALUE));

    fill_valid(&f);
    f.operation_ordinal = 1;
    CALL(expect_ok_both_paths(&f));
    f.operation_ordinal = UINT64_MAX;
    CALL(expect_ok_both_paths(&f));
    f.operation_ordinal = 0;
    CALL(cheap_fail_struct(&f, WIRE_VALUE));

    for (v = 0; v <= 0xffffu; v++) {
        fill_valid(&f);
        f.phase = (uint16_t)v;
        if (v >= 1u && v <= 14u) {
            CALL(expect_ok_both_paths(&f));
        } else {
            CALL(cheap_fail_struct(&f, WIRE_STATE));
        }
    }
    return 0;
}

static int test_matrix(void)
{
    struct spp_diag_trace_frame f;
    unsigned access;
    unsigned decision;
    unsigned object;
    unsigned v;
    static const uint32_t results[] = {
        0x00000000u, 0x7fffffffu, 0x80000000u, 0x80000001u, 0xfffffffbu,
        0xffffffffu};
    size_t ri;

    for (access = 1; access <= 4; access++) {
        for (decision = 1; decision <= 2; decision++) {
            for (object = 1; object <= 4; object++) {
                fill_valid(&f);
                store16(f.payload + 0, (uint16_t)access);
                store16(f.payload + 4, (uint16_t)decision);
                store16(f.payload + 6, (uint16_t)object);
                if (decision == SPP_DIAG_TRACE_POLICY_DENY) {
                    store32(f.payload + 8, 0x80000000u);
                }
                CALL(expect_ok_both_paths(&f));
            }
        }
    }

    fill_valid(&f);
    store16(f.payload + 2, 0);
    CALL(expect_ok_both_paths(&f));
    store16(f.payload + 2, 0x003f);
    CALL(expect_ok_both_paths(&f));

    for (decision = 1; decision <= 2; decision++) {
        for (ri = 0; ri < sizeof results / sizeof results[0]; ri++) {
            int expect;
            fill_valid(&f);
            store16(f.payload + 4, (uint16_t)decision);
            store32(f.payload + 8, results[ri]);
            if (decision == SPP_DIAG_TRACE_POLICY_ALLOW) {
                expect = results[ri] == 0u ? WIRE_OK : WIRE_VALUE;
            } else {
                expect = (results[ri] & 0x80000000u) != 0u ? WIRE_OK
                                                           : WIRE_VALUE;
            }
            if (expect == WIRE_OK) {
                CALL(expect_ok_both_paths(&f));
            } else {
                CALL(cheap_fail_struct(&f, expect));
            }
        }
    }

    fill_valid(&f);
    store32(f.payload + 12, 0);
    store32(f.payload + 16, 0);
    store32(f.payload + 20, 0);
    store64(f.payload + 40, 0);
    CALL(expect_ok_both_paths(&f));
    store32(f.payload + 12, UINT32_MAX);
    store32(f.payload + 16, UINT32_MAX);
    store32(f.payload + 20, UINT32_MAX);
    store64(f.payload + 40, UINT64_MAX);
    CALL(expect_ok_both_paths(&f));

    fill_valid(&f);
    store64(f.payload + 24, 1);
    CALL(expect_ok_both_paths(&f));
    store64(f.payload + 24, UINT64_MAX);
    CALL(expect_ok_both_paths(&f));
    store64(f.payload + 24, 0);
    CALL(cheap_fail_struct(&f, WIRE_VALUE));

    fill_valid(&f);
    store64(f.payload + 32, 1);
    CALL(expect_ok_both_paths(&f));
    store64(f.payload + 32, UINT64_MAX);
    CALL(expect_ok_both_paths(&f));
    store64(f.payload + 32, 0);
    CALL(cheap_fail_struct(&f, WIRE_VALUE));

    for (v = 0; v <= 0xffffu; v++) {
        fill_valid(&f);
        store16(f.payload + 0, (uint16_t)v);
        if (v >= 1u && v <= 4u) {
            CALL(expect_ok_both_paths(&f));
        } else {
            CALL(cheap_fail_struct(&f, WIRE_STATE));
        }
    }
    for (v = 0; v <= 0xffffu; v++) {
        fill_valid(&f);
        store16(f.payload + 4, (uint16_t)v);
        if (v == SPP_DIAG_TRACE_POLICY_ALLOW) {
            CALL(expect_ok_both_paths(&f));
        } else if (v == SPP_DIAG_TRACE_POLICY_DENY) {
            store32(f.payload + 8, 0x80000000u);
            CALL(expect_ok_both_paths(&f));
        } else {
            CALL(cheap_fail_struct(&f, WIRE_STATE));
        }
    }
    for (v = 0; v <= 0xffffu; v++) {
        fill_valid(&f);
        store16(f.payload + 6, (uint16_t)v);
        if (v >= 1u && v <= 4u) {
            CALL(expect_ok_both_paths(&f));
        } else {
            CALL(cheap_fail_struct(&f, WIRE_STATE));
        }
    }
    for (v = 0; v <= 0xffffu; v++) {
        fill_valid(&f);
        store16(f.payload + 2, (uint16_t)v);
        if ((v & ~0x003fu) == 0) {
            CALL(expect_ok_both_paths(&f));
        } else {
            CALL(cheap_fail_struct(&f, WIRE_FLAGS));
        }
    }
    return 0;
}

static int test_bounds(void)
{
    struct spp_diag_trace_frame f;
    const struct step steps[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags1, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"cap", hp_plen_cap, WIRE_CAP, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"plen", hp_plen47, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_z, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_z, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase0, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"hres", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
        {"access", pp_access0, WIRE_STATE, 44, 2, SOFF(payload), 2},
        {"modifier", pp_mod_unk, WIRE_FLAGS, 46, 2, SOFF(payload) + 2, 2},
        {"decision", pp_decision0, WIRE_STATE, 48, 2, SOFF(payload) + 4, 2},
        {"object", pp_object0, WIRE_STATE, 50, 2, SOFF(payload) + 6, 2},
        {"result", pp_result_bad, WIRE_VALUE, 52, 4, SOFF(payload) + 8, 4},
        {"inode", pp_inode0, WIRE_VALUE, 68, 8, SOFF(payload) + 24, 8},
        {"mount", pp_mount0, WIRE_VALUE, 76, 8, SOFF(payload) + 32, 8},
    };
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 16];
    uint8_t buf[8 + SPP_DIAG_TRACE_MAX_FRAME_BYTES + 16];
    uint8_t chain[32];
    uint8_t out[200];
    struct frame_box box, snap;
    size_t written, required, consumed;
    size_t len;
    size_t i;
    uint32_t bad_len[] = {0, 47, 49, 1044};
    _Alignas(8) uint8_t sentinel[8];

    fill_valid(&f);
    CALL(run_pairs(&f, steps, sizeof steps / sizeof steps[0]));

    for (i = 0; i < sizeof bad_len / sizeof bad_len[0]; i++) {
        fill_valid(&f);
        f.payload_length = bad_len[i];
        CALL(api_fail_struct(&f, WIRE_LENGTH, NULL, 0));
    }
    fill_valid(&f);
    f.payload_length = 1045;
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));
    f.payload_length = UINT32_MAX;
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));

    /*
     * Decode supplied-length equality (len != 44+plen) sits after
     * payload_length_check and before task_check for both event kinds.
     * Confirmed by source inspection of
     * spp_diag_trace_provenance_frame_decode; not an ASan-poisoning test.
     */
    fill_valid(&f);
    f.task_ordinal = 0;
    memset(wire, CANARY, sizeof wire);
    layout_frame(wire, &f);
    wire[92] = 0x77;
    CALL(api_fail_decode_wire(wire, 93, WIRE_LENGTH, NULL, 0));

    fill_valid(&f);
    memset(wire, CANARY, sizeof wire);
    layout_frame(wire, &f);
    CALL(api_fail_decode_wire(wire, 93, WIRE_LENGTH, NULL, 0));

    memset(sentinel, 0x5a, sizeof sentinel);
    test_asan_poison(sentinel, sizeof sentinel);
    EXPECT_ASAN_POISONED(sentinel, 1);
    memset(&box, CANARY2, sizeof box);
    snap = box;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(sentinel, 0, &box.f,
                                                     &consumed),
              WIRE_LENGTH);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    test_asan_unpoison(sentinel, sizeof sentinel);

    for (len = 1; len < 44; len++) {
        memset(buf, CANARY, sizeof buf);
        memcpy(buf + 8, k_literal_wire, len);
        test_asan_poison(buf + 8, sizeof buf - 8);
        EXPECT_ASAN_POISONED(buf + 8, 1);
        EXPECT_ASAN_POISONED(buf + sizeof buf - 1, 1);
        memset(&box, CANARY2, sizeof box);
        snap = box;
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_provenance_frame_decode(buf + 8, len, &box.f,
                                                         &consumed),
                  WIRE_LENGTH);
        EXPECT_EQ(consumed, 0);
        EXPECT(memcmp(&box, &snap, sizeof box) == 0);
        test_asan_unpoison(buf + 8, sizeof buf - 8);
        EXPECT_EQ(buf[7], CANARY);
    }
    for (len = 44; len < 92; len++) {
        memset(buf, CANARY, sizeof buf);
        memcpy(buf + 8, k_literal_wire, len);
        test_asan_poison(buf + 8 + len, sizeof buf - 8 - len);
        EXPECT_ASAN_POISONED(buf + 8 + len, 1);
        EXPECT_ASAN_POISONED(buf + sizeof buf - 1, 1);
        memset(&box, CANARY2, sizeof box);
        snap = box;
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_provenance_frame_decode(buf + 8, len, &box.f,
                                                         &consumed),
                  WIRE_LENGTH);
        EXPECT_EQ(consumed, 0);
        EXPECT(memcmp(&box, &snap, sizeof box) == 0);
        test_asan_unpoison(buf + 8 + len, sizeof buf - 8 - len);
    }

    fill_valid(&f);
    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, out, 91, &written,
                                                     &required),
              WIRE_BUFFER_TOO_SMALL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, (size_t)92);
    CALL(expect_canary(out, sizeof out));

    memset(chain, 0, sizeof chain);
    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, out, 154,
                                                       &written, &required),
              WIRE_BUFFER_TOO_SMALL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, (size_t)155);
    CALL(expect_canary(out, sizeof out));

    {
        size_t tail = SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES - f.payload_length;
        test_asan_poison(f.payload + f.payload_length, tail);
        EXPECT_ASAN_POISONED(f.payload + f.payload_length, 1);
        EXPECT_ASAN_POISONED(f.payload + 1043, 1);
        {
            uint8_t got[92];
            uint8_t preimg[155];
            written = required = 0;
            EXPECT_EQ(spp_diag_trace_provenance_frame_encode(
                          &f, got, sizeof got, &written, &required),
                      WIRE_OK);
            EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                          &f, chain, preimg, sizeof preimg, &written, &required),
                      WIRE_OK);
        }
        test_asan_unpoison(f.payload + f.payload_length, tail);
    }
    return 0;
}

int main(void)
{
    if (test_compatibility() != 0) {
        return 1;
    }
    if (test_literals() != 0) {
        return 1;
    }
    if (test_matrix() != 0) {
        return 1;
    }
    if (test_bounds() != 0) {
        return 1;
    }
    return 0;
}
