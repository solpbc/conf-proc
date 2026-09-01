/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

#include <stddef.h>
#include <stdint.h>
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

_Static_assert(SPP_DIAG_TRACE_POLICY_VERSION_PROVENANCE == 2, "policy 2");
_Static_assert(SPP_DIAG_TRACE_HOOK_MASK_PROVENANCE == 0xffffull, "mask 2");
_Static_assert(SPP_DIAG_TRACE_HEADER_SIZE == 192, "header size");
_Static_assert(SPP_DIAG_TRACE_IMA_SIZE == 256, "ima size");
_Static_assert(SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE == 196, "header entry");
_Static_assert(SPP_DIAG_TRACE_TASK_EXIT_PAYLOAD_SIZE == 8, "task-exit payload");

static const uint8_t k_ev_ready[21] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a',
    'g', '-', 'r', 'e', 'a', 'd', 'y', '-', 'v', '1'};
static const uint8_t k_ev_release[23] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g', '-',
    'r', 'e', 'l', 'e', 'a', 's', 'e', '-', 'v', '1'};
static const uint8_t k_ev_terminal[24] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g',
    '-', 't', 'e', 'r', 'm', 'i', 'n', 'a', 'l', '-', 'v', '1'};

static const uint16_t k_all_kinds[16] = {
    1, 0x0100, 2, 0x0101, 3, 0x0102, 4, 0x0103,
    5, 0x0104, 6, 0x0105, 7, 8, 9, 10};

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

static void event_for_kind(uint16_t kind, const uint8_t **name, size_t *len)
{
    if (kind == 1) {
        *name = k_ev_ready;
        *len = sizeof k_ev_ready;
    } else if (kind == 2) {
        *name = k_ev_release;
        *len = sizeof k_ev_release;
    } else {
        *name = k_ev_terminal;
        *len = sizeof k_ev_terminal;
    }
}

static void fill_header_body(uint8_t *w, uint16_t policy, uint64_t mask)
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
    store16(w + 12, policy);
    store16(w + 14, 1);
    store32(w + 16, 524288u);
    store64(w + 20, 268435456ull);
    store32(w + 28, 1088u);
    memcpy(w + 32, SPP_DIAG_TRACE_SOURCE_COMMIT, 20);
    store64(w + 180, mask);
}

static void write_header_entry(uint8_t *p, uint16_t policy, uint64_t mask)
{
    store32(p, 192);
    fill_header_body(p + 4, policy, mask);
}

static void fill_ima_body(uint8_t *w, uint16_t policy, uint64_t mask,
                          uint16_t kind)
{
    memset(w, 0, 256);
    w[0] = 0x53;
    w[1] = 0x50;
    w[2] = 0x50;
    w[3] = 0x49;
    w[4] = 0x4d;
    w[5] = 0x41;
    w[6] = 0x31;
    w[7] = 0x00;
    store16(w + 8, 1);
    store16(w + 10, kind);
    store32(w + 12, 256);
    store16(w + 16, policy);
    store16(w + 18, 1);
    store16(w + 20, kind);
    memcpy(w + 24, SPP_DIAG_TRACE_SOURCE_COMMIT, 20);
    store64(w + 172, 1);
    store64(w + 180, 244);
    store64(w + 220, mask);
}

static void fill_header(struct spp_diag_trace_header *h, uint16_t policy,
                        uint64_t mask)
{
    memset(h, 0, sizeof *h);
    memcpy(h->magic, "SPPTRC1", 7);
    h->magic[7] = 0;
    h->wire_version = 1;
    h->header_length = 192;
    h->policy_version = policy;
    h->hash_algorithm = 1;
    h->max_frames = 524288u;
    h->max_stream_bytes = 268435456ull;
    h->max_frame_bytes = 1088u;
    memcpy(h->source_commit, SPP_DIAG_TRACE_SOURCE_COMMIT, 20);
    h->required_hook_mask = mask;
}

static void fill_ima(struct spp_diag_trace_ima *r, uint16_t policy, uint64_t mask,
                     uint16_t kind)
{
    memset(r, 0, sizeof *r);
    memcpy(r->magic, "SPPIMA1", 7);
    r->magic[7] = 0;
    r->wire_version = 1;
    r->kind = kind;
    r->record_length = 256;
    r->policy_version = policy;
    r->hash_algorithm = 1;
    r->state = kind;
    memcpy(r->source_commit, SPP_DIAG_TRACE_SOURCE_COMMIT, 20);
    r->frame_count = 1;
    r->stream_byte_count = 244;
    r->required_hook_mask = mask;
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

static size_t layout_file_open(uint8_t *w, uint64_t seq)
{
    layout_frame_header(w, 0x0100, 0, 17, seq, 1, 0, 1, 1, 0);
    store16(w + 44, 1);
    store16(w + 46, 1);
    store16(w + 48, 1);
    store16(w + 50, 0);
    store32(w + 52, 0);
    store32(w + 56, 0);
    w[60] = 0x2f;
    return 61;
}

static size_t layout_file_policy(uint8_t *w, uint64_t seq)
{
    layout_frame_header(w, 0x0101, 0, 48, seq, 1, 0, 1, 1, 0);
    memset(w + 44, 0, 48);
    store16(w + 44, 1);
    store16(w + 48, 1);
    store16(w + 50, 1);
    store64(w + 68, 1);
    store64(w + 76, 1);
    return 92;
}

static size_t layout_exec_mapping(uint8_t *w, uint64_t seq)
{
    layout_frame_header(w, 0x0102, 0, 64, seq, 1, 0, 1, 1, 0);
    memset(w + 44, 0, 64);
    store16(w + 44, 1);
    store16(w + 46, 1);
    store16(w + 48, 2);
    store16(w + 50, 1);
    store32(w + 56, 4);
    store64(w + 84, 1);
    store64(w + 92, 1);
    return 108;
}

static size_t layout_network_policy(uint8_t *w, uint64_t seq)
{
    layout_frame_header(w, 0x0103, 0, 64, seq, 1, 0, 1, 1, 0);
    memset(w + 44, 0, 64);
    store16(w + 44, 1);
    store16(w + 46, 1);
    store16(w + 48, 1);
    store16(w + 50, 1);
    store16(w + 52, 1);
    store16(w + 56, 2);
    store16(w + 58, 16);
    store64(w + 72, 1);
    return 108;
}

static size_t layout_operation_return(uint8_t *w, uint64_t seq)
{
    layout_frame_header(w, 0x0104, 0, 16, seq, 1, 0, 1, 1, 0);
    memset(w + 44, 0, 16);
    store16(w + 44, 1);
    return 60;
}

static size_t layout_task_exit(uint8_t *w, uint64_t seq)
{
    layout_frame_header(w, 0x0105, 0, 8, seq, 1, 2, 0, 1, 0);
    memset(w + 44, 0, 8);
    return 52;
}

static size_t layout_valid_core(uint8_t *w, uint16_t event, uint64_t seq)
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

static size_t layout_any_frame(uint8_t *w, uint16_t event, uint64_t seq)
{
    if (event >= 1 && event <= 10) {
        return layout_valid_core(w, event, seq);
    }
    switch (event) {
    case 0x0100:
        return layout_file_open(w, seq);
    case 0x0101:
        return layout_file_policy(w, seq);
    case 0x0102:
        return layout_exec_mapping(w, seq);
    case 0x0103:
        return layout_network_policy(w, seq);
    case 0x0104:
        return layout_operation_return(w, seq);
    case 0x0105:
        return layout_task_exit(w, seq);
    default:
        layout_frame_header(w, event, 0, 0, seq, 0, 0, 0, 0, 0);
        return 44;
    }
}

static size_t write_frame_entry(uint8_t *p, uint16_t event, uint64_t seq)
{
    size_t body = layout_any_frame(p + 4, event, seq);
    store32(p, (uint32_t)body);
    return 4 + body;
}

static int expect_canary(const uint8_t *bytes, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        EXPECT_EQ(bytes[i], CANARY);
    }
    return 0;
}

static int call_ok(const uint8_t *in, size_t len, uint64_t frames, uint64_t bytes)
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

static int header_api_fail(const struct spp_diag_trace_header *h, int expected)
{
    uint8_t out[192];
    uint8_t pre[224];
    size_t written, required;

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_encode(h, out, sizeof out, &written,
                                           &required),
              expected);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(pre, CANARY, sizeof pre);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_preimage(h, pre, sizeof pre, &written,
                                             &required),
              expected);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(pre, sizeof pre));
    return 0;
}

static int ima_api_fail(const struct spp_diag_trace_ima *r, int expected)
{
    uint8_t out[256];
    size_t written, required;
    const uint8_t *ev;
    size_t ev_len;

    event_for_kind(r->kind >= 1 && r->kind <= 3 ? r->kind : 1, &ev, &ev_len);
    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_ima_encode(r, out, sizeof out, &written, &required),
              expected);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));
    EXPECT_EQ(spp_diag_trace_ima_validate(r, ev, ev_len), expected);
    return 0;
}

static int test_constants(void)
{
    uint64_t hook_mask;

    EXPECT_EQ(SPP_DIAG_TRACE_POLICY_VERSION, 1);
    EXPECT_EQ(SPP_DIAG_TRACE_POLICY_VERSION_PROVENANCE, 2);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_MASK, 0xfull);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_MASK_PROVENANCE, 0xffffull);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_BPRM_CHECK_SECURITY, 1ull << 0);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_BPRM_COMMITTED_CREDS, 1ull << 1);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_TASK_ALLOC, 1ull << 2);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_TASK_CREATED, 1ull << 3);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_FILE_OPEN_ATTEMPT, 1ull << 4);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_FILE_OPEN_POLICY, 1ull << 5);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_MMAP_POLICY, 1ull << 6);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_MPROTECT_POLICY, 1ull << 7);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_CONNECT_POLICY, 1ull << 8);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_SENDMSG_POLICY, 1ull << 9);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_FILE_OPEN_RETURN, 1ull << 10);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_MMAP_RETURN, 1ull << 11);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_MPROTECT_RETURN, 1ull << 12);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_CONNECT_RETURN, 1ull << 13);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_SENDMSG_RETURN, 1ull << 14);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_TASK_EXIT, 1ull << 15);
    hook_mask = SPP_DIAG_TRACE_HOOK_BPRM_CHECK_SECURITY |
                SPP_DIAG_TRACE_HOOK_BPRM_COMMITTED_CREDS |
                SPP_DIAG_TRACE_HOOK_TASK_ALLOC |
                SPP_DIAG_TRACE_HOOK_TASK_CREATED |
                SPP_DIAG_TRACE_HOOK_FILE_OPEN_ATTEMPT |
                SPP_DIAG_TRACE_HOOK_FILE_OPEN_POLICY |
                SPP_DIAG_TRACE_HOOK_MMAP_POLICY |
                SPP_DIAG_TRACE_HOOK_MPROTECT_POLICY |
                SPP_DIAG_TRACE_HOOK_CONNECT_POLICY |
                SPP_DIAG_TRACE_HOOK_SENDMSG_POLICY |
                SPP_DIAG_TRACE_HOOK_FILE_OPEN_RETURN |
                SPP_DIAG_TRACE_HOOK_MMAP_RETURN |
                SPP_DIAG_TRACE_HOOK_MPROTECT_RETURN |
                SPP_DIAG_TRACE_HOOK_CONNECT_RETURN |
                SPP_DIAG_TRACE_HOOK_SENDMSG_RETURN |
                SPP_DIAG_TRACE_HOOK_TASK_EXIT;
    EXPECT_EQ(hook_mask, 0xffffull);
    return 0;
}

static int test_header_ima_roundtrip(void)
{
    struct spp_diag_trace_header h, got_h, snap_h;
    struct spp_diag_trace_ima r, got_r, snap_r;
    uint8_t wire[192], expect[192], pre[224];
    uint8_t iwire[256], iexpect[256];
    size_t written, required, consumed;
    const uint8_t *ev;
    size_t ev_len;
    uint16_t kind;

    fill_header(&h, 2, 0xffffull);
    fill_header_body(expect, 2, 0xffffull);
    memset(wire, CANARY, sizeof wire);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_header_encode(&h, wire, sizeof wire, &written,
                                           &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)192);
    EXPECT_EQ(required, (size_t)192);
    EXPECT_MEM_EQ(wire, expect, 192);

    memset(&got_h, CANARY2, sizeof got_h);
    snap_h = got_h;
    consumed = 0;
    EXPECT_EQ(spp_diag_trace_header_decode(wire, 192, &got_h, &consumed),
              WIRE_OK);
    EXPECT_EQ(consumed, (size_t)192);
    EXPECT(memcmp(&got_h, &snap_h, sizeof got_h) != 0);
    EXPECT_EQ(got_h.policy_version, 2);
    EXPECT_EQ(got_h.required_hook_mask, 0xffffull);

    written = required = 0;
    EXPECT_EQ(spp_diag_trace_header_preimage(&h, pre, sizeof pre, &written,
                                             &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)224);
    EXPECT_EQ(required, (size_t)224);

    for (kind = 1; kind <= 3; kind++) {
        fill_ima(&r, 2, 0xffffull, kind);
        fill_ima_body(iexpect, 2, 0xffffull, kind);
        memset(iwire, CANARY, sizeof iwire);
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, sizeof iwire, &written,
                                            &required),
                  WIRE_OK);
        EXPECT_EQ(written, (size_t)256);
        EXPECT_EQ(required, (size_t)256);
        EXPECT_MEM_EQ(iwire, iexpect, 256);

        memset(&got_r, CANARY2, sizeof got_r);
        snap_r = got_r;
        consumed = 0;
        EXPECT_EQ(spp_diag_trace_ima_decode(iwire, 256, &got_r, &consumed),
                  WIRE_OK);
        EXPECT_EQ(consumed, (size_t)256);
        EXPECT(memcmp(&got_r, &snap_r, sizeof got_r) != 0);
        EXPECT_EQ(got_r.policy_version, 2);
        EXPECT_EQ(got_r.required_hook_mask, 0xffffull);
        EXPECT_EQ(got_r.kind, kind);
        event_for_kind(kind, &ev, &ev_len);
        EXPECT_EQ(spp_diag_trace_ima_validate(&r, ev, ev_len), WIRE_OK);
    }
    return 0;
}

static int test_header_only_stream(void)
{
    uint8_t buf[256];

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    CALL(call_ok_poisoned(buf, 196, sizeof buf, 0, 196));
    return 0;
}

static int test_each_kind_alone(void)
{
    uint8_t buf[2048];
    size_t n;
    size_t body;
    uint16_t event;

    for (event = 1; event <= 10; event++) {
        memset(buf, CANARY, sizeof buf);
        write_header_entry(buf, 2, 0xffffull);
        body = layout_any_frame(buf + 200, event, 0);
        store32(buf + 196, (uint32_t)body);
        n = 196 + 4 + body;
        CALL(call_ok_poisoned(buf, n, sizeof buf, 1, n));
    }
    {
        static const uint16_t prov[6] = {0x0100, 0x0101, 0x0102,
                                         0x0103, 0x0104, 0x0105};
        size_t i;
        for (i = 0; i < 6; i++) {
            memset(buf, CANARY, sizeof buf);
            write_header_entry(buf, 2, 0xffffull);
            body = layout_any_frame(buf + 200, prov[i], 0);
            store32(buf + 196, (uint32_t)body);
            n = 196 + 4 + body;
            CALL(call_ok_poisoned(buf, n, sizeof buf, 1, n));
        }
    }
    return 0;
}

static int test_sixteen_and_mixed(void)
{
    uint8_t buf[4096];
    size_t off;
    size_t i;

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    off = 196;
    for (i = 0; i < 16; i++) {
        off += write_frame_entry(buf + off, k_all_kinds[i], (uint64_t)i);
    }
    CALL(call_ok_poisoned(buf, off, sizeof buf, 16, off));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    off = 196;
    off += write_frame_entry(buf + off, 10, 0);
    off += write_frame_entry(buf + off, 0x0100, 1);
    off += write_frame_entry(buf + off, 1, 2);
    CALL(call_ok_poisoned(buf, off, sizeof buf, 3, off));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    off = 196;
    off += write_frame_entry(buf + off, 0x0105, 0);
    off += write_frame_entry(buf + off, 5, 1);
    off += write_frame_entry(buf + off, 8, 2);
    CALL(call_ok_poisoned(buf, off, sizeof buf, 3, off));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    off = 196;
    off += write_frame_entry(buf + off, 1, 0);
    off += write_frame_entry(buf + off, 0x0105, 1);
    off += write_frame_entry(buf + off, 3, 2);
    CALL(call_ok_poisoned(buf, off, sizeof buf, 3, off));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    off = 196;
    off += write_frame_entry(buf + off, 0x0104, 0);
    off += write_frame_entry(buf + off, 1, 1);
    off += write_frame_entry(buf + off, 0x0105, 2);
    CALL(call_ok_poisoned(buf, off, sizeof buf, 3, off));
    return 0;
}

static int test_ac1_version_and_mask(void)
{
    struct spp_diag_trace_header h;
    struct spp_diag_trace_ima r;
    uint32_t v;
    int b;
    uint64_t required_mask;
    uint16_t policy;
    uint8_t hout[192];
    uint8_t iout[256];
    size_t written;
    size_t required;

    for (v = 0; v <= UINT16_MAX; v++) {
        if (v == 1) {
            fill_header(&h, 1, 0xfull);
            written = required = 0;
            EXPECT_EQ(spp_diag_trace_header_encode(&h, hout, sizeof hout,
                                                   &written, &required),
                      WIRE_OK);
            fill_ima(&r, 1, 0xfull, 1);
            written = required = 0;
            EXPECT_EQ(spp_diag_trace_ima_encode(&r, iout, sizeof iout, &written,
                                                &required),
                      WIRE_OK);
        } else if (v == 2) {
            fill_header(&h, 2, 0xffffull);
            written = required = 0;
            EXPECT_EQ(spp_diag_trace_header_encode(&h, hout, sizeof hout,
                                                   &written, &required),
                      WIRE_OK);
            fill_ima(&r, 2, 0xffffull, 1);
            written = required = 0;
            EXPECT_EQ(spp_diag_trace_ima_encode(&r, iout, sizeof iout, &written,
                                                &required),
                      WIRE_OK);
        } else {
            fill_header(&h, (uint16_t)v, 0xfull);
            CALL(header_api_fail(&h, WIRE_VERSION));
            fill_header(&h, (uint16_t)v, 0xffffull);
            CALL(header_api_fail(&h, WIRE_VERSION));
            fill_ima(&r, (uint16_t)v, 0xfull, 1);
            CALL(ima_api_fail(&r, WIRE_VERSION));
            fill_ima(&r, (uint16_t)v, 0xffffull, 1);
            CALL(ima_api_fail(&r, WIRE_VERSION));
        }
    }

    for (policy = 1; policy <= 2; policy++) {
        required_mask = (policy == 1) ? 0xfull : 0xffffull;
        fill_header(&h, policy, required_mask);
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_header_encode(&h, hout, sizeof hout, &written,
                                               &required),
                  WIRE_OK);
        fill_ima(&r, policy, required_mask, 1);
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iout, sizeof iout, &written,
                                            &required),
                  WIRE_OK);
        for (b = 0; b < 64; b++) {
            fill_header(&h, policy, 1ull << b);
            CALL(header_api_fail(&h, WIRE_VALUE));
            fill_header(&h, policy, required_mask ^ (1ull << b));
            CALL(header_api_fail(&h, WIRE_VALUE));
            fill_ima(&r, policy, 1ull << b, 1);
            CALL(ima_api_fail(&r, WIRE_VALUE));
            fill_ima(&r, policy, required_mask ^ (1ull << b), 1);
            CALL(ima_api_fail(&r, WIRE_VALUE));
        }
        fill_header(&h, policy, 0);
        CALL(header_api_fail(&h, WIRE_VALUE));
        fill_header(&h, policy, UINT64_MAX);
        CALL(header_api_fail(&h, WIRE_VALUE));
        fill_ima(&r, policy, 0, 1);
        CALL(ima_api_fail(&r, WIRE_VALUE));
        fill_ima(&r, policy, UINT64_MAX, 1);
        CALL(ima_api_fail(&r, WIRE_VALUE));
    }
    return 0;
}

static int test_ac2_policy1_rejects_provenance(void)
{
    uint8_t buf[2048];
    size_t n;
    size_t body;
    static const uint16_t prov[6] = {0x0100, 0x0101, 0x0102,
                                     0x0103, 0x0104, 0x0105};
    size_t i;

    for (i = 0; i < 6; i++) {
        memset(buf, CANARY, sizeof buf);
        write_header_entry(buf, 1, 0xfull);
        body = layout_any_frame(buf + 200, prov[i], 0);
        store32(buf + 196, (uint32_t)body);
        n = 196 + 4 + body;
        CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_EVENT));
    }

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 1, 0xfull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    n += write_frame_entry(buf + n, 0x0105, 1);
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_EVENT));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 1, 0xfull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    n += write_frame_entry(buf + n, 2, 1);
    n += write_frame_entry(buf + n, 0x0100, 2);
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_EVENT));
    return 0;
}

static int test_ac4_event_and_sequence(void)
{
    uint8_t buf[2048];
    size_t n;
    size_t body;
    uint32_t v;
    uint16_t event;

    for (v = 0; v <= UINT16_MAX; v++) {
        event = (uint16_t)v;
        memset(buf, CANARY, sizeof buf);
        write_header_entry(buf, 2, 0xffffull);
        body = layout_any_frame(buf + 200, event, 0);
        store32(buf + 196, (uint32_t)body);
        n = 196 + 4 + body;
        if ((event >= 1 && event <= 10) ||
            (event >= 0x0100 && event <= 0x0105)) {
            CALL(call_ok(buf, n, 1, n));
        } else {
            CALL(call_fail(buf, n, WIRE_EVENT));
        }
    }

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    n += write_frame_entry(buf + n, 0x0105, 1);
    CALL(call_ok_poisoned(buf, n, sizeof buf, 2, n));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    n += write_frame_entry(buf + n, 0x0105, 0);
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_SEQUENCE));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    n += write_frame_entry(buf + n, 0x0105, 2);
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_SEQUENCE));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    n += write_frame_entry(buf + n, 0x0105, 1);
    n += write_frame_entry(buf + n, 3, 0);
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_SEQUENCE));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    body = layout_any_frame(buf + 200, 1, UINT64_MAX);
    store32(buf + 196, (uint32_t)body);
    n = 196 + 4 + body;
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_SEQUENCE));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    n = 196;
    n += write_frame_entry(buf + n, 0x0105, 0);
    CALL(call_ok(buf, n, 1, n));
    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    CALL(call_ok(buf, n, 1, n));
    return 0;
}

static int test_ac5_bounds_and_precedence(void)
{
    uint8_t buf[2048];
    size_t n;
    size_t body;
    uint32_t flen;
    struct spp_diag_trace_header h;
    struct spp_diag_trace_ima r;

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 3, 0xffffull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    test_asan_poison(buf + 196, n - 196);
    EXPECT_ASAN_POISONED(buf + 196, 1);
    CALL(call_fail(buf, n, WIRE_VERSION));
    test_asan_unpoison(buf + 196, n - 196);

    for (flen = 0; flen < 44; flen++) {
        memset(buf, CANARY, sizeof buf);
        write_header_entry(buf, 2, 0xffffull);
        store32(buf + 196, flen);
        layout_task_exit(buf + 200, 0);
        n = 196 + 4 + (flen > 0 ? flen : 0);
        if (n < 200) {
            n = 200;
        }
        CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_LENGTH));
    }

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    body = layout_task_exit(buf + 200, 0);
    store32(buf + 196, (uint32_t)body);
    n = 196 + 4 + body;
    EXPECT_EQ(body, (size_t)52);
    CALL(call_fail_poisoned(buf, n - 1, sizeof buf, WIRE_LENGTH));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    n += write_frame_entry(buf + n, 0x00ff, 1);
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_EVENT));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    n += write_frame_entry(buf + n, 0x0105, 1);
    n += write_frame_entry(buf + n, 0x0106, 2);
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_EVENT));

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    n = 196;
    n += write_frame_entry(buf + n, 1, 0);
    n += write_frame_entry(buf + n, 0x0105, 1);
    n += write_frame_entry(buf + n, 3, 1);
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_SEQUENCE));

    fill_header(&h, 2, 0);
    h.max_frames = 0;
    CALL(header_api_fail(&h, WIRE_CAP));

    fill_ima(&r, 2, 0, 1);
    r.state = 2;
    CALL(ima_api_fail(&r, WIRE_STATE));
    fill_ima(&r, 2, 0, 1);
    r.reserved16 = 1;
    CALL(ima_api_fail(&r, WIRE_RESERVED));
    fill_ima(&r, 2, 0, 1);
    r.frame_count = 0;
    CALL(ima_api_fail(&r, WIRE_CAP));
    return 0;
}

static int test_ac6_ima(void)
{
    struct spp_diag_trace_ima r;
    uint16_t kind;
    const uint8_t *ev;
    size_t ev_len;
    uint8_t bad[4] = {'x', 'x', 'x', 'x'};

    for (kind = 1; kind <= 3; kind++) {
        fill_ima(&r, 2, 0xffffull, kind);
        event_for_kind(kind, &ev, &ev_len);
        EXPECT_EQ(spp_diag_trace_ima_validate(&r, ev, ev_len), WIRE_OK);
        fill_ima(&r, 2, 0xfull, kind);
        CALL(ima_api_fail(&r, WIRE_VALUE));
        fill_ima(&r, 1, 0xffffull, kind);
        CALL(ima_api_fail(&r, WIRE_VALUE));
    }

    fill_ima(&r, 2, 0xffffull, 1);
    r.loss_count = 1;
    CALL(ima_api_fail(&r, WIRE_VALUE));
    fill_ima(&r, 2, 0xffffull, 1);
    r.overflow_count = 1;
    CALL(ima_api_fail(&r, WIRE_VALUE));
    fill_ima(&r, 2, 0xffffull, 1);
    r.kind = 0;
    CALL(ima_api_fail(&r, WIRE_EVENT));
    fill_ima(&r, 2, 0xffffull, 1);
    event_for_kind(1, &ev, &ev_len);
    EXPECT_EQ(spp_diag_trace_ima_validate(&r, bad, sizeof bad), WIRE_EVENT);
    EXPECT_EQ(spp_diag_trace_ima_validate(&r, ev, ev_len), WIRE_OK);
    return 0;
}

static int test_payload_spot(void)
{
    uint8_t buf[512];
    size_t n;
    size_t body;

    memset(buf, CANARY, sizeof buf);
    write_header_entry(buf, 2, 0xffffull);
    body = layout_task_exit(buf + 200, 0);
    store32(buf + 248, 1);
    store32(buf + 196, (uint32_t)body);
    n = 196 + 4 + body;
    CALL(call_fail_poisoned(buf, n, sizeof buf, WIRE_RESERVED));
    return 0;
}

int main(void)
{
    if (test_constants() != 0) {
        return 1;
    }
    if (test_header_ima_roundtrip() != 0) {
        return 1;
    }
    if (test_header_only_stream() != 0) {
        return 1;
    }
    if (test_each_kind_alone() != 0) {
        return 1;
    }
    if (test_sixteen_and_mixed() != 0) {
        return 1;
    }
    if (test_ac1_version_and_mask() != 0) {
        return 1;
    }
    if (test_ac2_policy1_rejects_provenance() != 0) {
        return 1;
    }
    if (test_ac4_event_and_sequence() != 0) {
        return 1;
    }
    if (test_ac5_bounds_and_precedence() != 0) {
        return 1;
    }
    if (test_ac6_ima() != 0) {
        return 1;
    }
    if (test_payload_spot() != 0) {
        return 1;
    }
    return 0;
}
