/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

#include <stddef.h>
#include <stdio.h>
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
_Static_assert(WIRE_ARITHMETIC == 9, "WIRE_ARITHMETIC");
_Static_assert(WIRE_EVENT == 10, "WIRE_EVENT");
_Static_assert(WIRE_FLAGS == 11, "WIRE_FLAGS");
_Static_assert(WIRE_STATE == 12, "WIRE_STATE");
_Static_assert(WIRE_SEQUENCE == 13, "WIRE_SEQUENCE");

_Static_assert(SPP_DIAG_TRACE_EVENT_CORE_INIT == 1u, "EVENT_CORE_INIT");
_Static_assert(SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED == 2u,
               "EVENT_PRE_RELEASE_EXEC_DENIED");
_Static_assert(SPP_DIAG_TRACE_EVENT_IMA_READY == 3u, "EVENT_IMA_READY");
_Static_assert(SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE == 4u,
               "EVENT_USERSPACE_RELEASE");
_Static_assert(SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT == 5u, "EVENT_EXEC_ATTEMPT");
_Static_assert(SPP_DIAG_TRACE_EVENT_EXEC_COMMIT == 6u, "EVENT_EXEC_COMMIT");
_Static_assert(SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT == 7u,
               "EVENT_TASK_ALLOC_ATTEMPT");
_Static_assert(SPP_DIAG_TRACE_EVENT_TASK_CREATED == 8u, "EVENT_TASK_CREATED");
_Static_assert(SPP_DIAG_TRACE_EVENT_PHASE_MARKER == 9u, "EVENT_PHASE_MARKER");
_Static_assert(SPP_DIAG_TRACE_EVENT_TERMINAL == 10u, "EVENT_TERMINAL");

_Static_assert(SPP_DIAG_TRACE_PHASE_PRE_RELEASE == 0u, "PHASE_PRE_RELEASE");
_Static_assert(SPP_DIAG_TRACE_PHASE_INIT == 1u, "PHASE_INIT");
_Static_assert(SPP_DIAG_TRACE_PHASE_COLD_START == 2u, "PHASE_COLD_START");
_Static_assert(SPP_DIAG_TRACE_PHASE_SYNTHETIC_INFERENCE == 3u,
               "PHASE_SYNTHETIC_INFERENCE");
_Static_assert(SPP_DIAG_TRACE_PHASE_POISON_IMPORT == 4u, "PHASE_POISON_IMPORT");
_Static_assert(SPP_DIAG_TRACE_PHASE_POISON_MODULE == 5u, "PHASE_POISON_MODULE");
_Static_assert(SPP_DIAG_TRACE_PHASE_POISON_LIBRARY == 6u,
               "PHASE_POISON_LIBRARY");
_Static_assert(SPP_DIAG_TRACE_PHASE_REMOTE_PACKAGE == 7u,
               "PHASE_REMOTE_PACKAGE");
_Static_assert(SPP_DIAG_TRACE_PHASE_REMOTE_MODEL == 8u, "PHASE_REMOTE_MODEL");
_Static_assert(SPP_DIAG_TRACE_PHASE_REMOTE_PLUGIN == 9u, "PHASE_REMOTE_PLUGIN");
_Static_assert(SPP_DIAG_TRACE_PHASE_WRITABLE_EXEC == 10u, "PHASE_WRITABLE_EXEC");
_Static_assert(SPP_DIAG_TRACE_PHASE_ATTACHED_DISK_EXEC == 11u,
               "PHASE_ATTACHED_DISK_EXEC");
_Static_assert(SPP_DIAG_TRACE_PHASE_REMOTE_CODE == 12u, "PHASE_REMOTE_CODE");
_Static_assert(SPP_DIAG_TRACE_PHASE_JIT_CACHE == 13u, "PHASE_JIT_CACHE");
_Static_assert(SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE == 14u,
               "PHASE_EVIDENCE_FINALIZE");
_Static_assert(SPP_DIAG_TRACE_PHASE_SEALED == 15u, "PHASE_SEALED");

static const uint8_t k_frame_domain[27] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g', '-', 't',
    'r', 'a', 'c', 'e', '-', 'f', 'r', 'a', 'm', 'e', '/', 'v', '1'};

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

static void fill_path_bytes(uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        p[i] = (uint8_t)((i % 255) + 1);
    }
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

static void zero_unused(struct spp_diag_trace_frame *f)
{
    size_t i;
    for (i = f->payload_length; i < SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES; i++) {
        f->payload[i] = 0;
    }
}

static void set_denied_payload(struct spp_diag_trace_frame *f, uint16_t path_len,
                               uint32_t pid, uint32_t tgid, uint64_t task_flags)
{
    store16(f->payload + 0, 13);
    store16(f->payload + 2, path_len);
    store32(f->payload + 4, pid);
    store32(f->payload + 8, tgid);
    store64(f->payload + 12, task_flags);
    fill_path_bytes(f->payload + 20, path_len);
    f->payload_length = 20u + path_len;
}

static void set_attempt_payload(struct spp_diag_trace_frame *f, uint32_t pass,
                                uint16_t path_len, uint32_t pid, uint32_t tgid)
{
    store32(f->payload + 0, pass);
    store16(f->payload + 4, path_len);
    store16(f->payload + 6, 0);
    store32(f->payload + 8, pid);
    store32(f->payload + 12, tgid);
    fill_path_bytes(f->payload + 16, path_len);
    f->payload_length = 16u + path_len;
}

struct frame_vec {
    const char *name;
    struct spp_diag_trace_frame f;
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    size_t wire_len;
};

enum { VEC_COUNT = 21 };

static struct frame_vec k_vecs[VEC_COUNT];

static void init_vec(struct frame_vec *v, const char *name,
                     const struct spp_diag_trace_frame *f)
{
    v->name = name;
    v->f = *f;
    zero_unused(&v->f);
    layout_frame(v->wire, &v->f);
    v->wire_len = (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE + v->f.payload_length;
}

static void init_vectors(void)
{
    struct spp_diag_trace_frame f;
    const uint64_t u64max = ~(uint64_t)0;
    const uint32_t u32max = ~(uint32_t)0;

    memset(&f, 0, sizeof f);
    f.event_type = SPP_DIAG_TRACE_EVENT_CORE_INIT;
    init_vec(&k_vecs[0], "core_init_lo", &f);
    f.sequence = u64max;
    init_vec(&k_vecs[1], "core_init_hi", &f);

    memset(&f, 0, sizeof f);
    f.event_type = SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED;
    f.operation_ordinal = 1;
    set_denied_payload(&f, 1, 1, 1, 0);
    init_vec(&k_vecs[2], "denied_lo", &f);
    f.sequence = u64max;
    f.task_ordinal = u64max;
    f.operation_ordinal = u64max;
    set_denied_payload(&f, 1024, u32max, u32max, u64max);
    init_vec(&k_vecs[3], "denied_hi", &f);

    memset(&f, 0, sizeof f);
    f.event_type = SPP_DIAG_TRACE_EVENT_IMA_READY;
    f.payload_length = 8;
    init_vec(&k_vecs[4], "ima_ready_lo", &f);
    f.sequence = u64max;
    store64(f.payload, u64max);
    init_vec(&k_vecs[5], "ima_ready_hi", &f);

    memset(&f, 0, sizeof f);
    f.event_type = SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE;
    f.task_ordinal = 1;
    f.payload_length = 16;
    store32(f.payload + 0, 1);
    store32(f.payload + 4, 1);
    init_vec(&k_vecs[6], "release_lo", &f);
    f.sequence = u64max;
    f.task_ordinal = u64max;
    store32(f.payload + 0, u32max);
    store32(f.payload + 4, u32max);
    store64(f.payload + 8, u64max);
    init_vec(&k_vecs[7], "release_hi", &f);

    memset(&f, 0, sizeof f);
    f.event_type = SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT;
    f.flags = 1;
    f.task_ordinal = 1;
    f.operation_ordinal = 1;
    f.phase = SPP_DIAG_TRACE_PHASE_PRE_RELEASE;
    set_attempt_payload(&f, 1, 1, 1, 1);
    init_vec(&k_vecs[8], "attempt_flag1_phase0", &f);
    f.flags = 0;
    f.phase = SPP_DIAG_TRACE_PHASE_INIT;
    set_attempt_payload(&f, 1, 1, 1, 1);
    init_vec(&k_vecs[9], "attempt_flag0_phase1", &f);
    f.sequence = u64max;
    f.task_ordinal = u64max;
    f.operation_ordinal = u64max;
    f.phase = SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE;
    set_attempt_payload(&f, u32max, 1024, u32max, u32max);
    init_vec(&k_vecs[10], "attempt_flag0_phase14", &f);

    memset(&f, 0, sizeof f);
    f.event_type = SPP_DIAG_TRACE_EVENT_EXEC_COMMIT;
    f.task_ordinal = 1;
    f.operation_ordinal = 1;
    f.phase = SPP_DIAG_TRACE_PHASE_INIT;
    f.payload_length = 16;
    store32(f.payload + 0, 1);
    store32(f.payload + 4, 1);
    store32(f.payload + 8, 1);
    init_vec(&k_vecs[11], "commit_lo", &f);
    f.sequence = u64max;
    f.task_ordinal = u64max;
    f.operation_ordinal = u64max;
    f.phase = SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE;
    store32(f.payload + 0, u32max);
    store32(f.payload + 4, u32max);
    store32(f.payload + 8, u32max);
    init_vec(&k_vecs[12], "commit_hi", &f);

    memset(&f, 0, sizeof f);
    f.event_type = SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT;
    f.task_ordinal = 1;
    f.parent_task_ordinal = 2;
    f.operation_ordinal = 1;
    f.phase = SPP_DIAG_TRACE_PHASE_INIT;
    f.payload_length = 8;
    init_vec(&k_vecs[13], "alloc_lo", &f);
    f.sequence = u64max;
    f.task_ordinal = u64max;
    f.parent_task_ordinal = u64max - 1u;
    f.operation_ordinal = u64max;
    f.phase = SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE;
    store64(f.payload, u64max);
    init_vec(&k_vecs[14], "alloc_hi", &f);

    memset(&f, 0, sizeof f);
    f.event_type = SPP_DIAG_TRACE_EVENT_TASK_CREATED;
    f.task_ordinal = 1;
    f.parent_task_ordinal = 2;
    f.operation_ordinal = 1;
    f.phase = SPP_DIAG_TRACE_PHASE_INIT;
    f.payload_length = 16;
    store32(f.payload + 0, 1);
    store32(f.payload + 4, 1);
    init_vec(&k_vecs[15], "created_lo", &f);
    f.sequence = u64max;
    f.task_ordinal = u64max;
    f.parent_task_ordinal = 1;
    f.operation_ordinal = u64max;
    f.phase = SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE;
    store32(f.payload + 0, u32max);
    store32(f.payload + 4, u32max);
    store64(f.payload + 8, u64max);
    init_vec(&k_vecs[16], "created_hi", &f);

    memset(&f, 0, sizeof f);
    f.event_type = SPP_DIAG_TRACE_EVENT_PHASE_MARKER;
    f.task_ordinal = 1;
    f.phase = SPP_DIAG_TRACE_PHASE_COLD_START;
    f.payload_length = 8;
    store16(f.payload + 0, 1);
    store16(f.payload + 2, 2);
    init_vec(&k_vecs[17], "marker_lo", &f);
    f.sequence = u64max;
    f.task_ordinal = u64max;
    f.phase = SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE;
    store16(f.payload + 0, 13);
    store16(f.payload + 2, 14);
    init_vec(&k_vecs[18], "marker_hi", &f);

    memset(&f, 0, sizeof f);
    f.event_type = SPP_DIAG_TRACE_EVENT_TERMINAL;
    f.phase = SPP_DIAG_TRACE_PHASE_SEALED;
    init_vec(&k_vecs[19], "terminal_lo", &f);
    f.sequence = u64max;
    init_vec(&k_vecs[20], "terminal_hi", &f);
}

enum { EXTRA_VEC_COUNT = 3 };

static void init_extra_vectors(struct frame_vec extra[EXTRA_VEC_COUNT])
{
    struct spp_diag_trace_frame f;

    f = k_vecs[2].f;
    set_denied_payload(&f, 64, 1, 1, 0);
    init_vec(&extra[0], "denied_path64", &f);

    f = k_vecs[8].f;
    f.flags = 0;
    f.phase = SPP_DIAG_TRACE_PHASE_INIT;
    set_attempt_payload(&f, 1, 64, 1, 1);
    init_vec(&extra[1], "attempt_path64", &f);

    f = k_vecs[17].f;
    store16(f.payload + 0, 7);
    store16(f.payload + 2, 8);
    f.phase = 8;
    init_vec(&extra[2], "marker_interior", &f);
}

static const uint8_t k_core_init_lo_literal[44] = {[1] = 0x01};

static const uint8_t k_core_init_hi_literal[44] = {
    [1] = 0x01,
    [8] = 0xff, [9] = 0xff, [10] = 0xff, [11] = 0xff,
    [12] = 0xff, [13] = 0xff, [14] = 0xff, [15] = 0xff};

struct frame_box {
    uint8_t pre[8];
    struct spp_diag_trace_frame f;
    uint8_t post[8];
};

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
    n = (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE +
        (f->payload_length <= SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES
             ? f->payload_length
             : 0);

    if (later_n > 0) {
        test_asan_poison(later, later_n);
        EXPECT_ASAN_POISONED(later, 1);
        EXPECT_ASAN_POISONED((uint8_t *)later + later_n - 1, 1);
    }

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    {
        int result = spp_diag_trace_frame_encode(f, out, sizeof out, &written,
                                                 &required);
        CALL(expect_fail_meta(result, expected, written, required, out,
                              sizeof out));
    }

    memset(pre, CANARY, sizeof pre);
    written = required = (size_t)-1;
    {
        int result = spp_diag_trace_frame_preimage(f, chain, pre, sizeof pre,
                                                   &written, &required);
        CALL(expect_fail_meta(result, expected, written, required, pre,
                              sizeof pre));
    }

    memset(pre, CANARY, sizeof pre);
    written = required = (size_t)-1;
    {
        int result = spp_diag_trace_frame_preimage(f, chain, pre, 0, &written,
                                                   &required);
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
    EXPECT_EQ(spp_diag_trace_frame_decode(wire, n < 44 ? 44 : n, &box.f,
                                          &consumed),
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
    EXPECT_EQ(spp_diag_trace_frame_decode(wire, len, &box.f, &consumed),
              expected);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    if (later_n > 0) {
        test_asan_unpoison(later, later_n);
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
static void hp_flags2(struct spp_diag_trace_frame *f) { f->flags = 2; }
static void hp_plen_cap(struct spp_diag_trace_frame *f)
{
    f->payload_length = 1045;
}
static void hp_plen_env(struct spp_diag_trace_frame *f)
{
    f->payload_length = 3;
}
static void hp_task_nz(struct spp_diag_trace_frame *f) { f->task_ordinal = 1; }
static void hp_task_z(struct spp_diag_trace_frame *f) { f->task_ordinal = 0; }
static void hp_parent_nz(struct spp_diag_trace_frame *f)
{
    f->parent_task_ordinal = 1;
}
static void hp_parent_z(struct spp_diag_trace_frame *f)
{
    f->parent_task_ordinal = 0;
}
static void hp_parent_eq(struct spp_diag_trace_frame *f)
{
    f->parent_task_ordinal = f->task_ordinal;
}
static void hp_op_nz(struct spp_diag_trace_frame *f)
{
    f->operation_ordinal = 1;
}
static void hp_op_z(struct spp_diag_trace_frame *f) { f->operation_ordinal = 0; }
static void hp_phase_bad(struct spp_diag_trace_frame *f)
{
    if (f->event_type == SPP_DIAG_TRACE_EVENT_TERMINAL) {
        f->phase = 14;
    } else if (f->event_type == SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT &&
               (f->flags & 1u) != 0) {
        f->phase = 1;
    } else {
        f->phase = 0;
        if (f->event_type == SPP_DIAG_TRACE_EVENT_CORE_INIT ||
            f->event_type == SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED ||
            f->event_type == SPP_DIAG_TRACE_EVENT_IMA_READY ||
            f->event_type == SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE) {
            f->phase = 1;
        }
    }
}
static void hp_res(struct spp_diag_trace_frame *f) { f->reserved = 1; }

static void pp_errno(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 0, 12);
}
static void pp_path0(struct spp_diag_trace_frame *f)
{
    if (f->event_type == SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED) {
        store16(f->payload + 2, 0);
    } else {
        store16(f->payload + 4, 0);
    }
}
static void pp_path1025(struct spp_diag_trace_frame *f)
{
    if (f->event_type == SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED) {
        store16(f->payload + 2, 1025);
    } else {
        store16(f->payload + 4, 1025);
    }
}
static void pp_path_mismatch(struct spp_diag_trace_frame *f)
{
    if (f->event_type == SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED) {
        store16(f->payload + 2, 2);
    } else {
        store16(f->payload + 4, 2);
    }
}
static void pp_denied_pid(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 4, 0);
}
static void pp_denied_tgid(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 8, 0);
}
static void pp_denied_pathnul(struct spp_diag_trace_frame *f)
{
    f->payload[20] = 0;
}
static void pp_rel_pid(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 0, 0);
}
static void pp_rel_tgid(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 4, 0);
}
static void pp_att_pass(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 0, 0);
}
static void pp_att_res(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 6, 1);
}
static void pp_att_pid(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 8, 0);
}
static void pp_att_tgid(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 12, 0);
}
static void pp_att_pathnul(struct spp_diag_trace_frame *f)
{
    f->payload[16] = 0;
}
static void pp_commit_pass(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 0, 0);
}
static void pp_commit_pid(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 4, 0);
}
static void pp_commit_tgid(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 8, 0);
}
static void pp_commit_res(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 12, 1);
}
static void pp_created_pid(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 0, 0);
}
static void pp_created_tgid(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 4, 0);
}
static void pp_mark_prev(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 0, 0);
}
static void pp_mark_next(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 2, 9);
}
static void pp_mark_res(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 4, 1);
}

static int run_pairs(const struct spp_diag_trace_frame *base,
                     const struct step *steps, size_t nsteps)
{
    size_t i;
    struct spp_diag_trace_frame f;
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 16];
    size_t len;

    for (i = 0; i < nsteps; i++) {
        f = *base;
        steps[i].poison(&f);
        CALL(api_fail_struct(&f, steps[i].expected, NULL, 0));
    }
    for (i = 0; i + 1 < nsteps; i++) {
        f = *base;
        steps[i].poison(&f);
        steps[i + 1].poison(&f);
        CALL(api_fail_struct(&f, steps[i].expected, NULL, 0));

        f = *base;
        steps[i].poison(&f);
        if (steps[i].expected == steps[i + 1].expected &&
            steps[i + 1].slen > 0) {
            CALL(api_fail_struct(&f, steps[i].expected,
                                 (uint8_t *)&f + steps[i + 1].soff,
                                 sizeof f - steps[i + 1].soff));
        }

        f = *base;
        steps[i].poison(&f);
        memset(wire, CANARY, sizeof wire);
        layout_frame(wire, &f);
        len = (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE +
              (f.payload_length <= SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES
                   ? f.payload_length
                   : 0);
        if (len < 44) {
            len = 44;
        }
        if (steps[i].expected == steps[i + 1].expected &&
            steps[i + 1].wlen > 0) {
            CALL(api_fail_decode_wire(wire, len, steps[i].expected,
                                      wire + steps[i + 1].woff,
                                      sizeof wire - steps[i + 1].woff));
        }
    }
    return 0;
}

#define SOFF(field) offsetof(struct spp_diag_trace_frame, field)
#define SL(field) sizeof(((struct spp_diag_trace_frame *)0)->field)

static int test_constants(void)
{
    EXPECT_EQ(WIRE_OK, 0);
    EXPECT_EQ(WIRE_ARITHMETIC, 9);
    EXPECT_EQ(WIRE_SEQUENCE, 13);
    EXPECT_EQ(SPP_DIAG_TRACE_FRAME_HEADER_SIZE, 44);
    EXPECT_EQ(SPP_DIAG_TRACE_MAX_PATH_BYTES, 1024);
    EXPECT_EQ(SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES, 1044);
    EXPECT_EQ(SPP_DIAG_TRACE_MAX_FRAME_BYTES, 1088);
    EXPECT_EQ(SPP_DIAG_TRACE_FRAME_PREIMAGE_MIN_SIZE, 107);
    EXPECT_EQ(SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE, 1151);
    EXPECT_EQ(k_vecs[3].wire_len, 1088);
    EXPECT_EQ(k_vecs[0].wire_len, 44);
    EXPECT_MEM_EQ(k_vecs[0].wire, k_core_init_lo_literal, 44);
    EXPECT_MEM_EQ(k_vecs[1].wire, k_core_init_hi_literal, 44);
    return 0;
}

static int roundtrip_one(const struct frame_vec *v)
{
    uint8_t got[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    uint8_t layout[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    struct frame_box decoded;
    struct spp_diag_trace_frame expect;
    size_t written, required, consumed;
    size_t i;

    memset(got, CANARY, sizeof got);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_frame_encode(&v->f, got, v->wire_len, &written,
                                          &required),
              WIRE_OK);
    EXPECT_EQ(written, v->wire_len);
    EXPECT_EQ(required, v->wire_len);
    EXPECT_MEM_EQ(got, v->wire, v->wire_len);
    layout_frame(layout, &v->f);
    EXPECT_MEM_EQ(got, layout, v->wire_len);

    memset(&decoded, CANARY2, sizeof decoded);
    consumed = 0;
    EXPECT_EQ(
        spp_diag_trace_frame_decode(got, v->wire_len, &decoded.f, &consumed),
        WIRE_OK);
    EXPECT_EQ(consumed, v->wire_len);
    expect = v->f;
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

static int expect_literal_u16(const uint8_t *p, uint16_t value)
{
    EXPECT_EQ(p[0], (uint8_t)(value >> 8));
    EXPECT_EQ(p[1], (uint8_t)value);
    return 0;
}

static int expect_literal_u32(const uint8_t *p, uint32_t value)
{
    EXPECT_EQ(p[0], (uint8_t)(value >> 24));
    EXPECT_EQ(p[1], (uint8_t)(value >> 16));
    EXPECT_EQ(p[2], (uint8_t)(value >> 8));
    EXPECT_EQ(p[3], (uint8_t)value);
    return 0;
}

static int expect_literal_u64(const uint8_t *p, uint64_t value)
{
    EXPECT_EQ(p[0], (uint8_t)(value >> 56));
    EXPECT_EQ(p[1], (uint8_t)(value >> 48));
    EXPECT_EQ(p[2], (uint8_t)(value >> 40));
    EXPECT_EQ(p[3], (uint8_t)(value >> 32));
    EXPECT_EQ(p[4], (uint8_t)(value >> 24));
    EXPECT_EQ(p[5], (uint8_t)(value >> 16));
    EXPECT_EQ(p[6], (uint8_t)(value >> 8));
    EXPECT_EQ(p[7], (uint8_t)value);
    return 0;
}

static int expect_literal_path(const uint8_t *p, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        EXPECT_EQ(p[i], (uint8_t)((i % 255) + 1));
    }
    return 0;
}

static int expect_literal_wire(size_t index)
{
    static const uint16_t events[VEC_COUNT] = {
        1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10};
    static const uint16_t flags[VEC_COUNT] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    static const uint32_t payload_lengths[VEC_COUNT] = {
        0, 0, 21, 1044, 8, 8, 16, 16, 17, 17, 1040, 16, 16, 8, 8, 16,
        16, 8, 8, 0, 0};
    static const uint64_t sequences[VEC_COUNT] = {
        0, UINT64_MAX, 0, UINT64_MAX, 0, UINT64_MAX, 0, UINT64_MAX, 0, 0,
        UINT64_MAX, 0, UINT64_MAX, 0, UINT64_MAX, 0, UINT64_MAX, 0,
        UINT64_MAX, 0, UINT64_MAX};
    static const uint64_t tasks[VEC_COUNT] = {
        0, 0, 0, UINT64_MAX, 0, 0, 1, UINT64_MAX, 1, 1, UINT64_MAX, 1,
        UINT64_MAX, 1, UINT64_MAX, 1, UINT64_MAX, 1, UINT64_MAX, 0, 0};
    static const uint64_t parents[VEC_COUNT] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, UINT64_MAX - 1u, 2,
        1, 0, 0, 0, 0};
    static const uint64_t operations[VEC_COUNT] = {
        0, 0, 1, UINT64_MAX, 0, 0, 0, 0, 1, 1, UINT64_MAX, 1, UINT64_MAX,
        1, UINT64_MAX, 1, UINT64_MAX, 0, 0, 0, 0};
    static const uint16_t phases[VEC_COUNT] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 14, 1, 14, 1, 14, 1, 14, 2, 14,
        15, 15};
    const uint8_t *w = k_vecs[index].wire;
    uint16_t path_len;

    EXPECT_EQ(k_vecs[index].wire_len,
              (size_t)44 + payload_lengths[index]);
    CALL(expect_literal_u16(w + 0, events[index]));
    CALL(expect_literal_u16(w + 2, flags[index]));
    CALL(expect_literal_u32(w + 4, payload_lengths[index]));
    CALL(expect_literal_u64(w + 8, sequences[index]));
    CALL(expect_literal_u64(w + 16, tasks[index]));
    CALL(expect_literal_u64(w + 24, parents[index]));
    CALL(expect_literal_u64(w + 32, operations[index]));
    CALL(expect_literal_u16(w + 40, phases[index]));
    CALL(expect_literal_u16(w + 42, 0));

    switch (events[index]) {
    case 1:
    case 10:
        break;
    case 2:
        path_len = index == 2 ? 1u : 1024u;
        CALL(expect_literal_u16(w + 44, 13));
        CALL(expect_literal_u16(w + 46, path_len));
        CALL(expect_literal_u32(w + 48, index == 2 ? 1u : UINT32_MAX));
        CALL(expect_literal_u32(w + 52, index == 2 ? 1u : UINT32_MAX));
        CALL(expect_literal_u64(w + 56, index == 2 ? 0u : UINT64_MAX));
        CALL(expect_literal_path(w + 64, path_len));
        break;
    case 3:
        CALL(expect_literal_u64(w + 44, index == 4 ? 0u : UINT64_MAX));
        break;
    case 4:
        CALL(expect_literal_u32(w + 44, index == 6 ? 1u : UINT32_MAX));
        CALL(expect_literal_u32(w + 48, index == 6 ? 1u : UINT32_MAX));
        CALL(expect_literal_u64(w + 52, index == 6 ? 0u : UINT64_MAX));
        break;
    case 5:
        path_len = index == 10 ? 1024u : 1u;
        CALL(expect_literal_u32(w + 44, index == 10 ? UINT32_MAX : 1u));
        CALL(expect_literal_u16(w + 48, path_len));
        CALL(expect_literal_u16(w + 50, 0));
        CALL(expect_literal_u32(w + 52, index == 10 ? UINT32_MAX : 1u));
        CALL(expect_literal_u32(w + 56, index == 10 ? UINT32_MAX : 1u));
        CALL(expect_literal_path(w + 60, path_len));
        break;
    case 6:
        CALL(expect_literal_u32(w + 44, index == 11 ? 1u : UINT32_MAX));
        CALL(expect_literal_u32(w + 48, index == 11 ? 1u : UINT32_MAX));
        CALL(expect_literal_u32(w + 52, index == 11 ? 1u : UINT32_MAX));
        CALL(expect_literal_u32(w + 56, 0));
        break;
    case 7:
        CALL(expect_literal_u64(w + 44, index == 13 ? 0u : UINT64_MAX));
        break;
    case 8:
        CALL(expect_literal_u32(w + 44, index == 15 ? 1u : UINT32_MAX));
        CALL(expect_literal_u32(w + 48, index == 15 ? 1u : UINT32_MAX));
        CALL(expect_literal_u64(w + 52, index == 15 ? 0u : UINT64_MAX));
        break;
    case 9:
        CALL(expect_literal_u16(w + 44, index == 17 ? 1u : 13u));
        CALL(expect_literal_u16(w + 46, index == 17 ? 2u : 14u));
        CALL(expect_literal_u32(w + 48, 0));
        break;
    default:
        EXPECT(0);
    }
    return 0;
}

static int test_literals(void)
{
    size_t i;
    for (i = 0; i < VEC_COUNT; i++) {
        CALL(expect_literal_wire(i));
        CALL(roundtrip_one(&k_vecs[i]));
    }
    return 0;
}

static int test_boundary_twins(void)
{
    struct spp_diag_trace_frame f;
    struct frame_vec extra;

    EXPECT_EQ(k_vecs[0].f.sequence, 0);
    EXPECT_EQ(k_vecs[1].f.sequence, ~(uint64_t)0);
    EXPECT_EQ(k_vecs[8].f.flags, 1);
    EXPECT_EQ(k_vecs[8].f.phase, 0);
    EXPECT_EQ(k_vecs[9].f.flags, 0);
    EXPECT_EQ(k_vecs[9].f.phase, 1);
    EXPECT_EQ(k_vecs[10].f.flags, 0);
    EXPECT_EQ(k_vecs[10].f.phase, 14);
    EXPECT_EQ(k_vecs[3].f.payload_length, 1044);
    EXPECT_EQ(k_vecs[3].wire_len, 1088);

    f = k_vecs[17].f;
    store16(f.payload + 0, 7);
    store16(f.payload + 2, 8);
    f.phase = 8;
    init_vec(&extra, "marker_interior", &f);
    CALL(roundtrip_one(&extra));

    f = k_vecs[2].f;
    set_denied_payload(&f, 64, 1, 1, 0);
    init_vec(&extra, "denied_path64", &f);
    CALL(roundtrip_one(&extra));
    EXPECT_EQ(extra.wire_len, (size_t)44 + 20 + 64);

    f = k_vecs[8].f;
    f.flags = 0;
    f.phase = 1;
    set_attempt_payload(&f, 1, 64, 1, 1);
    init_vec(&extra, "attempt_path64", &f);
    CALL(roundtrip_one(&extra));
    return 0;
}

static int test_unknown_and_cap(void)
{
    struct spp_diag_trace_frame f;
    static const uint16_t bad_events[] = {0, 11, 0x0100, 0x01ff, 0x0200,
                                          0xffff};
    size_t i;
    uint8_t wire[64];

    for (i = 0; i < sizeof bad_events / sizeof bad_events[0]; i++) {
        f = k_vecs[0].f;
        f.event_type = bad_events[i];
        CALL(api_fail_struct(&f, WIRE_EVENT, NULL, 0));
    }

    f = k_vecs[2].f;
    f.payload_length = 1045;
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));

    memset(wire, 0, sizeof wire);
    layout_header44(wire, &k_vecs[0].f);
    store32(wire + 4, 1045);
    CALL(api_fail_decode_wire(wire, 44, WIRE_CAP, NULL, 0));
    CALL(api_fail_decode_wire(wire, 1089, WIRE_CAP, NULL, 0));
    return 0;
}

static int test_path_nuls_and_lens(void)
{
    struct spp_diag_trace_frame f;
    size_t lens[3] = {1, 64, 1024};
    size_t i, j;
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 8];
    size_t n;

    for (i = 0; i < 3; i++) {
        for (j = 0; j < lens[i]; j++) {
            f = k_vecs[2].f;
            set_denied_payload(&f, (uint16_t)lens[i], 1, 1, 0);
            f.payload[20 + j] = 0;
            CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));
        }

        for (j = 0; j < lens[i]; j++) {
            f = k_vecs[9].f;
            set_attempt_payload(&f, 1, (uint16_t)lens[i], 1, 1);
            f.payload[16 + j] = 0;
            CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));
        }
    }

    f = k_vecs[2].f;
    store16(f.payload + 2, 0);
    CALL(api_fail_struct(&f, WIRE_LENGTH, NULL, 0));
    store16(f.payload + 2, 1025);
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));

    f = k_vecs[9].f;
    store16(f.payload + 4, 0);
    CALL(api_fail_struct(&f, WIRE_LENGTH, NULL, 0));
    store16(f.payload + 4, 1025);
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));

    for (j = 0; j < 2; j++) {
        const struct frame_vec *src = (j == 0) ? &k_vecs[2] : &k_vecs[9];
        f = src->f;
        memset(wire, CANARY, sizeof wire);
        layout_frame(wire, &f);
        n = (size_t)44 + f.payload_length;
        test_asan_poison(wire + n, sizeof wire - n);
        EXPECT_ASAN_POISONED(wire + n, 1);
        EXPECT_ASAN_POISONED(wire + sizeof wire - 1, 1);
        {
            struct spp_diag_trace_frame got;
            size_t consumed = 0;
            EXPECT_EQ(spp_diag_trace_frame_decode(wire, n, &got, &consumed),
                      WIRE_OK);
            EXPECT_EQ(consumed, n);
        }
        test_asan_unpoison(wire + n, sizeof wire - n);
    }
    return 0;
}

static int test_closed_negatives(void)
{
    struct spp_diag_trace_frame f;

    f = k_vecs[0].f;
    f.flags = 1;
    CALL(api_fail_struct(&f, WIRE_FLAGS, NULL, 0));
    f = k_vecs[0].f;
    f.task_ordinal = 1;
    CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));
    f = k_vecs[0].f;
    f.phase = 1;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_vecs[0].f;
    f.payload_length = 1;
    CALL(api_fail_struct(&f, WIRE_LENGTH, NULL, 0));

    f = k_vecs[2].f;
    f.flags = 1;
    CALL(api_fail_struct(&f, WIRE_FLAGS, NULL, 0));
    f = k_vecs[2].f;
    f.parent_task_ordinal = 1;
    CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));
    f = k_vecs[2].f;
    f.operation_ordinal = 0;
    CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));
    f = k_vecs[2].f;
    f.phase = 1;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    pp_errno(&f);
    f = k_vecs[2].f;
    pp_errno(&f);
    CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));

    f = k_vecs[6].f;
    f.task_ordinal = 0;
    CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));
    f = k_vecs[6].f;
    pp_rel_pid(&f);
    CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));

    f = k_vecs[8].f;
    f.flags = 3;
    CALL(api_fail_struct(&f, WIRE_FLAGS, NULL, 0));
    f = k_vecs[8].f;
    f.phase = 1;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_vecs[9].f;
    f.phase = 0;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_vecs[9].f;
    f.phase = 15;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_vecs[9].f;
    pp_att_pass(&f);
    CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));
    f = k_vecs[9].f;
    pp_att_res(&f);
    CALL(api_fail_struct(&f, WIRE_RESERVED, NULL, 0));

    f = k_vecs[11].f;
    f.phase = 0;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_vecs[11].f;
    pp_commit_pass(&f);
    CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));
    f = k_vecs[11].f;
    pp_commit_res(&f);
    CALL(api_fail_struct(&f, WIRE_RESERVED, NULL, 0));

    f = k_vecs[13].f;
    f.parent_task_ordinal = 0;
    CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));
    f = k_vecs[13].f;
    f.parent_task_ordinal = f.task_ordinal;
    CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));

    f = k_vecs[17].f;
    f.phase = 1;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_vecs[17].f;
    pp_mark_prev(&f);
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_vecs[17].f;
    pp_mark_next(&f);
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_vecs[17].f;
    store16(f.payload + 0, 1);
    store16(f.payload + 2, 2);
    f.phase = 3;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_vecs[17].f;
    pp_mark_res(&f);
    CALL(api_fail_struct(&f, WIRE_RESERVED, NULL, 0));

    f = k_vecs[19].f;
    f.phase = 0;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_vecs[19].f;
    f.payload_length = 1;
    CALL(api_fail_struct(&f, WIRE_LENGTH, NULL, 0));
    return 0;
}

static int test_precedence(void)
{
    const struct step core[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags2, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen_env, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_nz, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_nz, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase_bad, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"res", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
    };
    const struct step denied[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags2, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen_env, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_z, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase_bad, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"res", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
        {"errno", pp_errno, WIRE_VALUE, 44, 2, SOFF(payload), 2},
        {"path_len", pp_path0, WIRE_LENGTH, 46, 2, SOFF(payload) + 2, 2},
        {"pid", pp_denied_pid, WIRE_VALUE, 48, 4, SOFF(payload) + 4, 4},
        {"tgid", pp_denied_tgid, WIRE_VALUE, 52, 4, SOFF(payload) + 8, 4},
        {"path", pp_denied_pathnul, WIRE_VALUE, 64, 1, SOFF(payload) + 20, 1},
    };
    const struct step ima[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags2, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen_env, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_nz, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_nz, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase_bad, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"res", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
    };
    const struct step release[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags2, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen_env, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_z, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_nz, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase_bad, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"res", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
        {"pid", pp_rel_pid, WIRE_VALUE, 44, 4, SOFF(payload), 4},
        {"tgid", pp_rel_tgid, WIRE_VALUE, 48, 4, SOFF(payload) + 4, 4},
    };
    const struct step attempt[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags2, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen_env, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_z, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_z, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase_bad, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"res", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
        {"pass", pp_att_pass, WIRE_VALUE, 44, 4, SOFF(payload), 4},
        {"path_len", pp_path0, WIRE_LENGTH, 48, 2, SOFF(payload) + 4, 2},
        {"pres", pp_att_res, WIRE_RESERVED, 50, 2, SOFF(payload) + 6, 2},
        {"pid", pp_att_pid, WIRE_VALUE, 52, 4, SOFF(payload) + 8, 4},
        {"tgid", pp_att_tgid, WIRE_VALUE, 56, 4, SOFF(payload) + 12, 4},
        {"path", pp_att_pathnul, WIRE_VALUE, 60, 1, SOFF(payload) + 16, 1},
    };
    const struct step commit[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags2, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen_env, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_z, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_z, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase_bad, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"res", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
        {"pass", pp_commit_pass, WIRE_VALUE, 44, 4, SOFF(payload), 4},
        {"pid", pp_commit_pid, WIRE_VALUE, 48, 4, SOFF(payload) + 4, 4},
        {"tgid", pp_commit_tgid, WIRE_VALUE, 52, 4, SOFF(payload) + 8, 4},
        {"pres", pp_commit_res, WIRE_RESERVED, 56, 4, SOFF(payload) + 12, 4},
    };
    const struct step alloc[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags2, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen_env, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_z, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_z, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_z, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase_bad, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"res", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
    };
    const struct step created[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags2, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen_env, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_z, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_eq, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_z, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase_bad, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"res", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
        {"pid", pp_created_pid, WIRE_VALUE, 44, 4, SOFF(payload), 4},
        {"tgid", pp_created_tgid, WIRE_VALUE, 48, 4, SOFF(payload) + 4, 4},
    };
    const struct step marker[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags2, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen_env, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_z, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_nz, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase_bad, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"res", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
        {"prev", pp_mark_prev, WIRE_STATE, 44, 2, SOFF(payload), 2},
        {"next", pp_mark_next, WIRE_STATE, 46, 2, SOFF(payload) + 2, 2},
        {"pres", pp_mark_res, WIRE_RESERVED, 48, 4, SOFF(payload) + 4, 4},
    };
    const struct step terminal[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags2, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen_env, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_nz, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_nz, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase_bad, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"res", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
    };

    CALL(run_pairs(&k_vecs[0].f, core, sizeof core / sizeof core[0]));
    CALL(run_pairs(&k_vecs[2].f, denied, sizeof denied / sizeof denied[0]));
    CALL(run_pairs(&k_vecs[4].f, ima, sizeof ima / sizeof ima[0]));
    CALL(run_pairs(&k_vecs[6].f, release, sizeof release / sizeof release[0]));
    CALL(run_pairs(&k_vecs[9].f, attempt, sizeof attempt / sizeof attempt[0]));
    CALL(run_pairs(&k_vecs[11].f, commit, sizeof commit / sizeof commit[0]));
    CALL(run_pairs(&k_vecs[13].f, alloc, sizeof alloc / sizeof alloc[0]));
    CALL(run_pairs(&k_vecs[15].f, created, sizeof created / sizeof created[0]));
    CALL(run_pairs(&k_vecs[17].f, marker, sizeof marker / sizeof marker[0]));
    CALL(run_pairs(&k_vecs[19].f, terminal, sizeof terminal / sizeof terminal[0]));

    {
        struct spp_diag_trace_frame f = k_vecs[0].f;
        hp_flags2(&f);
        hp_plen_cap(&f);
        CALL(api_fail_struct(&f, WIRE_FLAGS, NULL, 0));
        f = k_vecs[0].f;
        hp_plen_cap(&f);
        CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));
    }
    {
        struct spp_diag_trace_frame f = k_vecs[2].f;
        pp_path1025(&f);
        CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));
        f = k_vecs[9].f;
        pp_path1025(&f);
        CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));
    }
    {
        struct spp_diag_trace_frame f = k_vecs[2].f;
        uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 8];
        size_t len;

        pp_path_mismatch(&f);
        CALL(api_fail_struct(
            &f, WIRE_LENGTH, f.payload + 4,
            sizeof f - (SOFF(payload) + 4u)));
        memset(wire, CANARY, sizeof wire);
        layout_frame(wire, &f);
        len = 44u + f.payload_length;
        CALL(api_fail_decode_wire(wire, len, WIRE_LENGTH, wire + 48,
                                  sizeof wire - 48u));

        f = k_vecs[9].f;
        pp_path_mismatch(&f);
        CALL(api_fail_struct(
            &f, WIRE_LENGTH, f.payload + 6,
            sizeof f - (SOFF(payload) + 6u)));
        memset(wire, CANARY, sizeof wire);
        layout_frame(wire, &f);
        len = 44u + f.payload_length;
        CALL(api_fail_decode_wire(wire, len, WIRE_LENGTH, wire + 50,
                                  sizeof wire - 50u));
    }
    {
        uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 8];
        static const size_t event_vectors[10] = {0, 2, 4, 6, 9,
                                                  11, 13, 15, 17, 19};
        size_t i;

        for (i = 0; i < 10; i++) {
            const struct frame_vec *v = &k_vecs[event_vectors[i]];

            memset(wire, CANARY, sizeof wire);
            memcpy(wire, v->wire, v->wire_len);
            wire[42] = 1;
            CALL(api_fail_decode_wire(wire, v->wire_len - 1, WIRE_LENGTH,
                                      NULL, 0));
            CALL(api_fail_decode_wire(wire, v->wire_len + 1, WIRE_LENGTH,
                                      NULL, 0));
        }
    }
    {
        uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
        struct spp_diag_trace_frame f = k_vecs[10].f;
        uint32_t payload_length;

        for (payload_length = 1041; payload_length <= 1044;
             payload_length++) {
            f.payload_length = payload_length;
            CALL(api_fail_struct(&f, WIRE_LENGTH, NULL, 0));
            memset(wire, CANARY, sizeof wire);
            layout_frame(wire, &f);
            CALL(api_fail_decode_wire(wire, 44u + payload_length, WIRE_LENGTH,
                                      NULL, 0));
        }
    }
    return 0;
}

static int test_decoder_bounds(void)
{
    size_t vi, len;
    uint8_t buf[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 16];
    _Alignas(8) uint8_t sentinel[8];
    struct frame_box box, snap;
    struct frame_vec extra[EXTRA_VEC_COUNT];
    const struct frame_vec *vectors[VEC_COUNT + EXTRA_VEC_COUNT];

    init_extra_vectors(extra);
    for (vi = 0; vi < VEC_COUNT; vi++) {
        vectors[vi] = &k_vecs[vi];
    }
    for (vi = 0; vi < EXTRA_VEC_COUNT; vi++) {
        vectors[VEC_COUNT + vi] = &extra[vi];
    }

    memset(sentinel, 0x5a, sizeof sentinel);
    test_asan_poison(sentinel, sizeof sentinel);
    EXPECT_ASAN_POISONED(sentinel, 1);
    memset(&box, CANARY2, sizeof box);
    snap = box;
    {
        size_t consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_frame_decode(sentinel, 0, &box.f, &consumed),
                  WIRE_LENGTH);
        EXPECT_EQ(consumed, 0);
        EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    }
    test_asan_unpoison(sentinel, sizeof sentinel);

    for (vi = 0; vi < VEC_COUNT + EXTRA_VEC_COUNT; vi++) {
        const struct frame_vec *v = vectors[vi];
        for (len = 1; len < 44; len++) {
            memset(buf, CANARY, sizeof buf);
            memcpy(buf + 8, v->wire, len);
            test_asan_poison(buf + 8, sizeof buf - 8);
            EXPECT_ASAN_POISONED(buf + 8, 1);
            EXPECT_ASAN_POISONED(buf + sizeof buf - 1, 1);
            memset(&box, CANARY2, sizeof box);
            snap = box;
            {
                size_t consumed = (size_t)-1;
                EXPECT_EQ(spp_diag_trace_frame_decode(buf + 8, len, &box.f,
                                                      &consumed),
                          WIRE_LENGTH);
                EXPECT_EQ(consumed, 0);
                EXPECT(memcmp(&box, &snap, sizeof box) == 0);
            }
            test_asan_unpoison(buf + 8, sizeof buf - 8);
            EXPECT_EQ(buf[7], CANARY);
        }
        for (len = 44; len < v->wire_len; len++) {
            memset(buf, CANARY, sizeof buf);
            memcpy(buf + 8, v->wire, len);
            test_asan_poison(buf + 8 + len, sizeof buf - 8 - len);
            EXPECT_ASAN_POISONED(buf + 8 + len, 1);
            EXPECT_ASAN_POISONED(buf + sizeof buf - 1, 1);
            memset(&box, CANARY2, sizeof box);
            snap = box;
            {
                size_t consumed = (size_t)-1;
                EXPECT_EQ(spp_diag_trace_frame_decode(buf + 8, len, &box.f,
                                                      &consumed),
                          WIRE_LENGTH);
                EXPECT_EQ(consumed, 0);
                EXPECT(memcmp(&box, &snap, sizeof box) == 0);
            }
            test_asan_unpoison(buf + 8 + len, sizeof buf - 8 - len);
        }
        memset(buf, CANARY, sizeof buf);
        memcpy(buf + 8, v->wire, v->wire_len);
        buf[8 + v->wire_len] = 0x77;
        test_asan_poison(buf + 8 + v->wire_len,
                         sizeof buf - 8 - v->wire_len);
        EXPECT_ASAN_POISONED(buf + 8 + v->wire_len, 1);
        EXPECT_ASAN_POISONED(buf + sizeof buf - 1, 1);
        memset(&box, CANARY2, sizeof box);
        snap = box;
        {
            size_t consumed = (size_t)-1;
            EXPECT_EQ(spp_diag_trace_frame_decode(buf + 8, v->wire_len + 1,
                                                  &box.f, &consumed),
                      WIRE_LENGTH);
            EXPECT_EQ(consumed, 0);
            EXPECT(memcmp(&box, &snap, sizeof box) == 0);
        }
        test_asan_unpoison(buf + 8 + v->wire_len,
                           sizeof buf - 8 - v->wire_len);
    }
    return 0;
}

static int check_encode_cap(const struct spp_diag_trace_frame *f,
                            const uint8_t *expected, size_t n, int preimage)
{
    uint8_t buf[8 + SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE + 8];
    uint8_t chain[SPP_DIAG_TRACE_CHAIN_LEN];
    size_t written, required, i;
    size_t cap_max = sizeof buf - 16;

    memset(chain, 0, sizeof chain);
    memset(buf, CANARY, sizeof buf);
    written = required = (size_t)-1;
    if (preimage) {
        EXPECT_EQ(spp_diag_trace_frame_preimage(f, chain, buf + 8, n, &written,
                                                &required),
                  WIRE_OK);
    } else {
        EXPECT_EQ(spp_diag_trace_frame_encode(f, buf + 8, n, &written, &required),
                  WIRE_OK);
    }
    EXPECT_EQ(written, n);
    EXPECT_EQ(required, n);
    EXPECT_MEM_EQ(buf + 8, expected, n);
    CALL(expect_canary(buf, 8));
    CALL(expect_canary(buf + 8 + n, sizeof buf - 8 - n));

    memset(buf, CANARY, sizeof buf);
    written = required = (size_t)-1;
    if (preimage) {
        EXPECT_EQ(spp_diag_trace_frame_preimage(f, chain, buf + 8, 0, &written,
                                                &required),
                  WIRE_BUFFER_TOO_SMALL);
    } else {
        EXPECT_EQ(spp_diag_trace_frame_encode(f, buf + 8, 0, &written, &required),
                  WIRE_BUFFER_TOO_SMALL);
    }
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, n);
    for (i = 0; i < sizeof buf && i < cap_max + 16; i++) {
        EXPECT_EQ(buf[i], CANARY);
    }

    memset(buf, CANARY, sizeof buf);
    written = required = (size_t)-1;
    if (preimage) {
        EXPECT_EQ(spp_diag_trace_frame_preimage(f, chain, buf + 8, n - 1,
                                                &written, &required),
                  WIRE_BUFFER_TOO_SMALL);
    } else {
        EXPECT_EQ(spp_diag_trace_frame_encode(f, buf + 8, n - 1, &written,
                                              &required),
                  WIRE_BUFFER_TOO_SMALL);
    }
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, n);
    for (i = 0; i < sizeof buf; i++) {
        EXPECT_EQ(buf[i], CANARY);
    }

    memset(buf, CANARY, sizeof buf);
    written = required = (size_t)-1;
    if (preimage) {
        EXPECT_EQ(spp_diag_trace_frame_preimage(f, chain, buf + 8, n + 1,
                                                &written, &required),
                  WIRE_OK);
    } else {
        EXPECT_EQ(spp_diag_trace_frame_encode(f, buf + 8, n + 1, &written,
                                              &required),
                  WIRE_OK);
    }
    EXPECT_EQ(written, n);
    EXPECT_EQ(required, n);
    EXPECT_MEM_EQ(buf + 8, expected, n);
    CALL(expect_canary(buf, 8));
    CALL(expect_canary(buf + 8 + n, sizeof buf - 8 - n));
    return 0;
}

static void layout_preimage(uint8_t *out, const struct spp_diag_trace_frame *f,
                            const uint8_t *chain)
{
    size_t flen = (size_t)44 + f->payload_length;
    memcpy(out, k_frame_domain, 27);
    memcpy(out + 27, chain, 32);
    store32(out + 59, (uint32_t)flen);
    layout_frame(out + 63, f);
}

static int test_all_or_nothing(void)
{
    size_t vi;
    uint8_t pre_exp[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    uint8_t zchain[SPP_DIAG_TRACE_CHAIN_LEN];
    struct spp_diag_trace_frame local;
    struct frame_vec extra[EXTRA_VEC_COUNT];
    const struct frame_vec *vectors[VEC_COUNT + EXTRA_VEC_COUNT];
    size_t tail;

    init_extra_vectors(extra);
    for (vi = 0; vi < VEC_COUNT; vi++) {
        vectors[vi] = &k_vecs[vi];
    }
    for (vi = 0; vi < EXTRA_VEC_COUNT; vi++) {
        vectors[VEC_COUNT + vi] = &extra[vi];
    }
    memset(zchain, 0, sizeof zchain);
    for (vi = 0; vi < VEC_COUNT + EXTRA_VEC_COUNT; vi++) {
        const struct frame_vec *v = vectors[vi];

        CALL(check_encode_cap(&v->f, v->wire, v->wire_len, 0));
        layout_preimage(pre_exp, &v->f, zchain);
        CALL(check_encode_cap(&v->f, pre_exp, 63 + v->wire_len, 1));

        tail = SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES - v->f.payload_length;
        if (tail > 0) {
            uint8_t got[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
            uint8_t pre[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
            size_t written, required;
            local = v->f;
            test_asan_poison(local.payload + local.payload_length, tail);
            EXPECT_ASAN_POISONED(local.payload + local.payload_length, 1);
            EXPECT_ASAN_POISONED(local.payload + 1043, 1);
            written = required = 0;
            EXPECT_EQ(spp_diag_trace_frame_encode(&local, got, sizeof got,
                                                  &written, &required),
                      WIRE_OK);
            EXPECT_MEM_EQ(got, v->wire, v->wire_len);
            EXPECT_EQ(spp_diag_trace_frame_preimage(&local, zchain, pre,
                                                    sizeof pre, &written,
                                                    &required),
                      WIRE_OK);
            EXPECT_MEM_EQ(pre, pre_exp, 63 + v->wire_len);
            test_asan_unpoison(local.payload + local.payload_length, tail);
        }
    }

    {
        struct spp_diag_trace_frame f = k_vecs[0].f;
        uint8_t out[64];
        size_t written, required;
        memset(out, CANARY, sizeof out);
        f.payload[0] = 0x7e;
        f.payload[1043] = 0x3d;
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_frame_encode(&f, out, 44, &written, &required),
                  WIRE_OK);
        EXPECT_MEM_EQ(out, k_vecs[0].wire, 44);
    }
    return 0;
}

static int test_preimage(void)
{
    size_t vi;
    uint8_t zchain[SPP_DIAG_TRACE_CHAIN_LEN];
    uint8_t nchain[SPP_DIAG_TRACE_CHAIN_LEN];
    uint8_t got[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    uint8_t exp[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    uint8_t with_nul[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE + 1];
    size_t written, required, need;
    struct frame_vec extra[EXTRA_VEC_COUNT];
    const uint8_t *chains[2];
    size_t ei, ci;

    memset(zchain, 0, sizeof zchain);
    fill_path_bytes(nchain, sizeof nchain);
    chains[0] = zchain;
    chains[1] = nchain;

    for (vi = 0; vi < VEC_COUNT; vi++) {
        need = 63 + k_vecs[vi].wire_len;
        CALL(expect_literal_wire(vi));
        layout_preimage(exp, &k_vecs[vi].f, zchain);
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_frame_preimage(&k_vecs[vi].f, zchain, got,
                                                sizeof got, &written, &required),
                  WIRE_OK);
        EXPECT_EQ(written, need);
        EXPECT_EQ(required, need);
        EXPECT_MEM_EQ(got, exp, need);
        EXPECT_MEM_EQ(got, k_frame_domain, 27);
        EXPECT_MEM_EQ(got + 27, zchain, 32);
        CALL(expect_literal_u32(got + 59, (uint32_t)k_vecs[vi].wire_len));
        EXPECT_MEM_EQ(got + 63, k_vecs[vi].wire, k_vecs[vi].wire_len);

        layout_preimage(exp, &k_vecs[vi].f, nchain);
        EXPECT_EQ(spp_diag_trace_frame_preimage(&k_vecs[vi].f, nchain, got,
                                                sizeof got, &written, &required),
                  WIRE_OK);
        EXPECT_MEM_EQ(got, exp, need);
        EXPECT_MEM_EQ(got + 27, nchain, 32);
        CALL(expect_literal_u32(got + 59, (uint32_t)k_vecs[vi].wire_len));
        EXPECT_MEM_EQ(got + 63, k_vecs[vi].wire, k_vecs[vi].wire_len);
        EXPECT(memcmp(got + 27, zchain, 32) != 0);

        memcpy(with_nul, k_frame_domain, 27);
        with_nul[27] = 0;
        memcpy(with_nul + 28, nchain, 32);
        store32(with_nul + 60, (uint32_t)k_vecs[vi].wire_len);
        layout_frame(with_nul + 64, &k_vecs[vi].f);
        EXPECT(memcmp(got, with_nul, need) != 0);
        EXPECT_EQ(got[27], nchain[0]);
        EXPECT(got[27] != 0);
    }

    init_extra_vectors(extra);
    for (ei = 0; ei < EXTRA_VEC_COUNT; ei++) {
        need = 63 + extra[ei].wire_len;
        for (ci = 0; ci < 2; ci++) {
            layout_preimage(exp, &extra[ei].f, chains[ci]);
            written = required = 0;
            EXPECT_EQ(spp_diag_trace_frame_preimage(
                          &extra[ei].f, chains[ci], got, sizeof got, &written,
                          &required),
                      WIRE_OK);
            EXPECT_EQ(written, need);
            EXPECT_EQ(required, need);
            EXPECT_MEM_EQ(got, exp, need);
        }
    }
    return 0;
}

static int test_nulls(void)
{
    struct spp_diag_trace_frame f = k_vecs[0].f;
    uint8_t out[64];
    uint8_t chain[32];
    size_t written, required, consumed;
    struct frame_box box, snap;

    memset(chain, 0x22, sizeof chain);
    f.event_type = 0;

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_encode(NULL, out, 44, &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_encode(&f, NULL, 44, &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);

    memset(out, CANARY, sizeof out);
    required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_encode(&f, out, 44, NULL, &required),
              WIRE_NULL);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_encode(&f, out, 44, &written, NULL),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_preimage(NULL, chain, out, 64, &written,
                                            &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_preimage(&f, NULL, out, 64, &written,
                                            &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_preimage(&f, chain, NULL, 64, &written,
                                            &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);

    memset(out, CANARY, sizeof out);
    required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_preimage(&f, chain, out, 64, NULL, &required),
              WIRE_NULL);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_preimage(&f, chain, out, 64, &written, NULL),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    CALL(expect_canary(out, sizeof out));

    memset(&box, CANARY2, sizeof box);
    snap = box;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_decode(NULL, 0, &box.f, &consumed),
              WIRE_NULL);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_decode(out, 0, NULL, &consumed), WIRE_NULL);
    EXPECT_EQ(consumed, 0);
    memset(&box, CANARY2, sizeof box);
    snap = box;
    EXPECT_EQ(spp_diag_trace_frame_decode(out, 0, &box.f, NULL), WIRE_NULL);
    EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    return 0;
}

int run_spp_diag_trace_frame_tests(void)
{
    init_vectors();
    if (test_constants() != 0) {
        return 1;
    }
    if (test_literals() != 0) {
        return 1;
    }
    if (test_boundary_twins() != 0) {
        return 1;
    }
    if (test_unknown_and_cap() != 0) {
        return 1;
    }
    if (test_path_nuls_and_lens() != 0) {
        return 1;
    }
    if (test_closed_negatives() != 0) {
        return 1;
    }
    if (test_precedence() != 0) {
        return 1;
    }
    if (test_decoder_bounds() != 0) {
        return 1;
    }
    if (test_all_or_nothing() != 0) {
        return 1;
    }
    if (test_preimage() != 0) {
        return 1;
    }
    if (test_nulls() != 0) {
        return 1;
    }
    return 0;
}
