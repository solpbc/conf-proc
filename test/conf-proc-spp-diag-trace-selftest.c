/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

#include <stdio.h>
#include <string.h>

#include "../conf_proc_spp_diag_trace.h"

/* Overlap of caller-owned input/output/metadata ranges is a non-detected
 * precondition; these tests do not claim to detect it. */

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

static const uint8_t k_magic_trc[8] = {'S', 'P', 'P', 'T', 'R', 'C', '1', 0x00};
static const uint8_t k_magic_cmd[8] = {'S', 'P', 'P', 'C', 'M', 'D', '1', 0x00};
static const uint8_t k_magic_ima[8] = {'S', 'P', 'P', 'I', 'M', 'A', '1', 0x00};
static const uint8_t k_commit[20] = {
    0x91, 0xa8, 0xe8, 0x26, 0x01, 0x2f, 0xbb, 0x1c, 0x7f, 0x5c,
    0xb2, 0xa3, 0x26, 0xc0, 0x8b, 0x13, 0xe3, 0x90, 0xf4, 0x69};
static const uint8_t k_label[18] = {'s', 'o', 'l', '_', 's', 'p', 'p', '_', 'd',
                                    'i', 'a', 'g', '_', 't', 'r', 'a', 'c', 'e'};
static const uint8_t k_domain[28] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g', '-', 't',
    'r', 'a', 'c', 'e', '-', 'h', 'e', 'a', 'd', 'e', 'r', '/', 'v', '1'};
static const uint8_t k_ev_ready[21] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a',
    'g', '-', 'r', 'e', 'a', 'd', 'y', '-', 'v', '1'};
static const uint8_t k_ev_release[23] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g', '-',
    'r', 'e', 'l', 'e', 'a', 's', 'e', '-', 'v', '1'};
static const uint8_t k_ev_terminal[24] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g',
    '-', 't', 'e', 'r', 'm', 'i', 'n', 'a', 'l', '-', 'v', '1'};

static const uint8_t k_hdr_literal[192] = {
    [0] = 0x53,  [1] = 0x50,  [2] = 0x50,  [3] = 0x54,
    [4] = 0x52,  [5] = 0x43,  [6] = 0x31,  [7] = 0x00,
    [8] = 0x00,  [9] = 0x01,  [10] = 0x00, [11] = 0xc0,
    [12] = 0x00, [13] = 0x01, [14] = 0x00, [15] = 0x01,
    [16] = 0x00, [17] = 0x08, [18] = 0x00, [19] = 0x00,
    [20] = 0x00, [21] = 0x00, [22] = 0x00, [23] = 0x00,
    [24] = 0x10, [25] = 0x00, [26] = 0x00, [27] = 0x00,
    [28] = 0x00, [29] = 0x00, [30] = 0x04, [31] = 0x40,
    [32] = 0x91, [33] = 0xa8, [34] = 0xe8, [35] = 0x26,
    [36] = 0x01, [37] = 0x2f, [38] = 0xbb, [39] = 0x1c,
    [40] = 0x7f, [41] = 0x5c, [42] = 0xb2, [43] = 0xa3,
    [44] = 0x26, [45] = 0xc0, [46] = 0x8b, [47] = 0x13,
    [48] = 0xe3, [49] = 0x90, [50] = 0xf4, [51] = 0x69,
    [180] = 0x00, [181] = 0x00, [182] = 0x00, [183] = 0x00,
    [184] = 0x00, [185] = 0x00, [186] = 0x00, [187] = 0x0f};

static const uint8_t k_cmd_advance2_literal[128] = {
    [0] = 0x53,  [1] = 0x50,  [2] = 0x50,  [3] = 0x43,
    [4] = 0x4d,  [5] = 0x44,  [6] = 0x31,  [7] = 0x00,
    [8] = 0x00,  [9] = 0x01,  [10] = 0x00, [11] = 0x01,
    [12] = 0x00, [13] = 0x00, [14] = 0x00, [15] = 0x80,
    [112] = 0x00, [113] = 0x02};

static const uint8_t k_cmd_seal_literal[128] = {
    [0] = 0x53,  [1] = 0x50,  [2] = 0x50,  [3] = 0x43,
    [4] = 0x4d,  [5] = 0x44,  [6] = 0x31,  [7] = 0x00,
    [8] = 0x00,  [9] = 0x01,  [10] = 0x00, [11] = 0x02,
    [12] = 0x00, [13] = 0x00, [14] = 0x00, [15] = 0x80,
    [112] = 0x00, [113] = 0x0f};

static const uint8_t k_ima_ready_literal[256] = {
    [0] = 0x53,  [1] = 0x50,  [2] = 0x50,  [3] = 0x49,
    [4] = 0x4d,  [5] = 0x41,  [6] = 0x31,  [7] = 0x00,
    [8] = 0x00,  [9] = 0x01,  [10] = 0x00, [11] = 0x01,
    [12] = 0x00, [13] = 0x00, [14] = 0x01, [15] = 0x00,
    [16] = 0x00, [17] = 0x01, [18] = 0x00, [19] = 0x01,
    [20] = 0x00, [21] = 0x01, [22] = 0x00, [23] = 0x00,
    [24] = 0x91, [25] = 0xa8, [26] = 0xe8, [27] = 0x26,
    [28] = 0x01, [29] = 0x2f, [30] = 0xbb, [31] = 0x1c,
    [32] = 0x7f, [33] = 0x5c, [34] = 0xb2, [35] = 0xa3,
    [36] = 0x26, [37] = 0xc0, [38] = 0x8b, [39] = 0x13,
    [40] = 0xe3, [41] = 0x90, [42] = 0xf4, [43] = 0x69,
    [172] = 0x00, [173] = 0x00, [174] = 0x00, [175] = 0x00,
    [176] = 0x00, [177] = 0x00, [178] = 0x00, [179] = 0x01,
    [180] = 0x00, [181] = 0x00, [182] = 0x00, [183] = 0x00,
    [184] = 0x00, [185] = 0x00, [186] = 0x00, [187] = 0xf4,
    [220] = 0x00, [221] = 0x00, [222] = 0x00, [223] = 0x00,
    [224] = 0x00, [225] = 0x00, [226] = 0x00, [227] = 0x0f};

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

static void fill_pattern(uint8_t *p, size_t n, uint8_t seed)
{
    size_t i;
    for (i = 0; i < n; i++) {
        p[i] = (uint8_t)(seed + i + 1u);
    }
}

static void event_for_kind(uint16_t kind, const uint8_t **name, size_t *len)
{
    if (kind == 1) {
        *name = k_ev_ready;
        *len = 21;
    } else if (kind == 2) {
        *name = k_ev_release;
        *len = 23;
    } else {
        *name = k_ev_terminal;
        *len = 24;
    }
}

static void fill_valid_header(struct spp_diag_trace_header *h)
{
    memset(h, 0, sizeof *h);
    memcpy(h->magic, k_magic_trc, 8);
    h->wire_version = 1;
    h->header_length = 192;
    h->policy_version = 1;
    h->hash_algorithm = 1;
    h->max_frames = 524288u;
    h->max_stream_bytes = 268435456ull;
    h->max_frame_bytes = 1088u;
    memcpy(h->source_commit, k_commit, 20);
    h->required_hook_mask = 0xfull;
}

static void fill_valid_command(struct spp_diag_trace_command *c, uint16_t kind,
                               uint16_t phase)
{
    memset(c, 0, sizeof *c);
    memcpy(c->magic, k_magic_cmd, 8);
    c->version = 1;
    c->kind = kind;
    c->command_length = 128;
    c->requested_phase = phase;
}

static void fill_valid_ima(struct spp_diag_trace_ima *r, uint16_t kind)
{
    memset(r, 0, sizeof *r);
    memcpy(r->magic, k_magic_ima, 8);
    r->wire_version = 1;
    r->kind = kind;
    r->record_length = 256;
    r->policy_version = 1;
    r->hash_algorithm = 1;
    r->state = kind;
    memcpy(r->source_commit, k_commit, 20);
    r->frame_count = 1;
    r->stream_byte_count = 244;
    r->required_hook_mask = 0xfull;
}

static void layout_header(uint8_t *w, const struct spp_diag_trace_header *h)
{
    memcpy(w + 0, h->magic, 8);
    store16(w + 8, h->wire_version);
    store16(w + 10, h->header_length);
    store16(w + 12, h->policy_version);
    store16(w + 14, h->hash_algorithm);
    store32(w + 16, h->max_frames);
    store64(w + 20, h->max_stream_bytes);
    store32(w + 28, h->max_frame_bytes);
    memcpy(w + 32, h->source_commit, 20);
    memcpy(w + 52, h->challenge, 32);
    memcpy(w + 84, h->run_identity, 32);
    memcpy(w + 116, h->control_plan_address, 32);
    memcpy(w + 148, h->command_line_sha256, 32);
    store64(w + 180, h->required_hook_mask);
    store32(w + 188, h->reserved);
}

static void layout_command(uint8_t *w, const struct spp_diag_trace_command *c)
{
    memcpy(w + 0, c->magic, 8);
    store16(w + 8, c->version);
    store16(w + 10, c->kind);
    store32(w + 12, c->command_length);
    memcpy(w + 16, c->challenge, 32);
    memcpy(w + 48, c->run_identity, 32);
    memcpy(w + 80, c->control_plan_address, 32);
    store16(w + 112, c->requested_phase);
    memcpy(w + 114, c->reserved, 14);
}

static void layout_ima(uint8_t *w, const struct spp_diag_trace_ima *r)
{
    memcpy(w + 0, r->magic, 8);
    store16(w + 8, r->wire_version);
    store16(w + 10, r->kind);
    store32(w + 12, r->record_length);
    store16(w + 16, r->policy_version);
    store16(w + 18, r->hash_algorithm);
    store16(w + 20, r->state);
    store16(w + 22, r->reserved16);
    memcpy(w + 24, r->source_commit, 20);
    memcpy(w + 44, r->challenge, 32);
    memcpy(w + 76, r->run_identity, 32);
    memcpy(w + 108, r->control_plan_address, 32);
    memcpy(w + 140, r->command_line_sha256, 32);
    store64(w + 172, r->frame_count);
    store64(w + 180, r->stream_byte_count);
    memcpy(w + 188, r->chain, 32);
    store64(w + 220, r->required_hook_mask);
    store64(w + 228, r->denied_exec_count);
    store64(w + 236, r->committed_exec_count);
    store32(w + 244, r->loss_count);
    store32(w + 248, r->overflow_count);
    store32(w + 252, r->reserved32);
}

static int header_eq(const struct spp_diag_trace_header *a,
                     const struct spp_diag_trace_header *b)
{
    return memcmp(a->magic, b->magic, 8) == 0 &&
           a->wire_version == b->wire_version &&
           a->header_length == b->header_length &&
           a->policy_version == b->policy_version &&
           a->hash_algorithm == b->hash_algorithm &&
           a->max_frames == b->max_frames &&
           a->max_stream_bytes == b->max_stream_bytes &&
           a->max_frame_bytes == b->max_frame_bytes &&
           memcmp(a->source_commit, b->source_commit, 20) == 0 &&
           memcmp(a->challenge, b->challenge, 32) == 0 &&
           memcmp(a->run_identity, b->run_identity, 32) == 0 &&
           memcmp(a->control_plan_address, b->control_plan_address, 32) == 0 &&
           memcmp(a->command_line_sha256, b->command_line_sha256, 32) == 0 &&
           a->required_hook_mask == b->required_hook_mask &&
           a->reserved == b->reserved;
}

static int command_eq(const struct spp_diag_trace_command *a,
                      const struct spp_diag_trace_command *b)
{
    return memcmp(a->magic, b->magic, 8) == 0 && a->version == b->version &&
           a->kind == b->kind && a->command_length == b->command_length &&
           memcmp(a->challenge, b->challenge, 32) == 0 &&
           memcmp(a->run_identity, b->run_identity, 32) == 0 &&
           memcmp(a->control_plan_address, b->control_plan_address, 32) == 0 &&
           a->requested_phase == b->requested_phase &&
           memcmp(a->reserved, b->reserved, 14) == 0;
}

static int ima_eq(const struct spp_diag_trace_ima *a,
                  const struct spp_diag_trace_ima *b)
{
    return memcmp(a->magic, b->magic, 8) == 0 &&
           a->wire_version == b->wire_version && a->kind == b->kind &&
           a->record_length == b->record_length &&
           a->policy_version == b->policy_version &&
           a->hash_algorithm == b->hash_algorithm && a->state == b->state &&
           a->reserved16 == b->reserved16 &&
           memcmp(a->source_commit, b->source_commit, 20) == 0 &&
           memcmp(a->challenge, b->challenge, 32) == 0 &&
           memcmp(a->run_identity, b->run_identity, 32) == 0 &&
           memcmp(a->control_plan_address, b->control_plan_address, 32) == 0 &&
           memcmp(a->command_line_sha256, b->command_line_sha256, 32) == 0 &&
           a->frame_count == b->frame_count &&
           a->stream_byte_count == b->stream_byte_count &&
           memcmp(a->chain, b->chain, 32) == 0 &&
           a->required_hook_mask == b->required_hook_mask &&
           a->denied_exec_count == b->denied_exec_count &&
           a->committed_exec_count == b->committed_exec_count &&
           a->loss_count == b->loss_count &&
           a->overflow_count == b->overflow_count &&
           a->reserved32 == b->reserved32;
}

static int test_result_constants(void)
{
    EXPECT_EQ(WIRE_OK, 0);
    EXPECT_EQ(WIRE_NULL, 1);
    EXPECT_EQ(WIRE_BUFFER_TOO_SMALL, 2);
    EXPECT_EQ(WIRE_MAGIC, 3);
    EXPECT_EQ(WIRE_VERSION, 4);
    EXPECT_EQ(WIRE_LENGTH, 5);
    EXPECT_EQ(WIRE_VALUE, 6);
    EXPECT_EQ(WIRE_RESERVED, 7);
    EXPECT_EQ(WIRE_CAP, 8);
    EXPECT_EQ(WIRE_ARITHMETIC, 9);
    EXPECT_EQ(WIRE_EVENT, 10);
    EXPECT_EQ(WIRE_FLAGS, 11);
    EXPECT_EQ(WIRE_STATE, 12);
    EXPECT_EQ(WIRE_SEQUENCE, 13);
    EXPECT_MEM_EQ(SPP_DIAG_TRACE_SOURCE_COMMIT, k_commit, 20);
    EXPECT_EQ(SPP_DIAG_TRACE_IMA_LABEL_LEN, 18);
    EXPECT_MEM_EQ(SPP_DIAG_TRACE_IMA_LABEL, k_label, 18);
    return 0;
}

static int test_positive_header_preimage(void)
{
    struct spp_diag_trace_header h, got;
    uint8_t wire[192], layout[192], pre[224], expl_pre[224];
    size_t written, required, consumed;
    size_t i;

    fill_valid_header(&h);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_header_encode(&h, wire, 192, &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, 192);
    EXPECT_EQ(required, 192);
    EXPECT_MEM_EQ(wire, k_hdr_literal, 192);
    EXPECT_MEM_EQ(wire, k_hdr_literal, 16);
    layout_header(layout, &h);
    EXPECT_MEM_EQ(wire, layout, 192);

    memset(&got, 0x5a, sizeof got);
    consumed = 0;
    EXPECT_EQ(spp_diag_trace_header_decode(wire, 192, &got, &consumed), WIRE_OK);
    EXPECT_EQ(consumed, 192);
    EXPECT(header_eq(&got, &h));

    written = required = 0;
    EXPECT_EQ(spp_diag_trace_header_preimage(&h, pre, 224, &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, 224);
    EXPECT_EQ(required, 224);
    memcpy(expl_pre, k_domain, 28);
    store32(expl_pre + 28, 192);
    memcpy(expl_pre + 32, k_hdr_literal, 192);
    EXPECT_MEM_EQ(pre, expl_pre, 224);
    EXPECT_MEM_EQ(pre, k_domain, 28);
    for (i = 0; i < 28; i++) {
        EXPECT(pre[i] != 0);
    }
    return 0;
}

static int test_positive_commands(void)
{
    struct spp_diag_trace_command c, got;
    uint8_t wire[128], layout[128];
    size_t written, required, consumed;
    uint16_t phase;

    for (phase = 2; phase <= 14; phase++) {
        fill_valid_command(&c, 1, phase);
        written = required = 0;
        EXPECT_EQ(
            spp_diag_trace_command_encode(&c, wire, 128, &written, &required),
            WIRE_OK);
        EXPECT_EQ(written, 128);
        EXPECT_EQ(required, 128);
        layout_command(layout, &c);
        EXPECT_MEM_EQ(wire, layout, 128);
        {
            uint8_t exp[128];
            memcpy(exp, k_cmd_advance2_literal, 128);
            store16(exp + 112, phase);
            EXPECT_MEM_EQ(wire, exp, 128);
        }
        memset(&got, 0x5a, sizeof got);
        consumed = 0;
        EXPECT_EQ(spp_diag_trace_command_decode(wire, 128, &got, &consumed),
                  WIRE_OK);
        EXPECT_EQ(consumed, 128);
        EXPECT(command_eq(&got, &c));
        EXPECT_EQ(got.requested_phase, phase);
        EXPECT_EQ(got.kind, 1);
    }

    fill_valid_command(&c, 2, 15);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_command_encode(&c, wire, 128, &written, &required),
              WIRE_OK);
    layout_command(layout, &c);
    EXPECT_MEM_EQ(wire, layout, 128);
    EXPECT_MEM_EQ(wire, k_cmd_seal_literal, 128);
    consumed = 0;
    EXPECT_EQ(spp_diag_trace_command_decode(wire, 128, &got, &consumed),
              WIRE_OK);
    EXPECT(command_eq(&got, &c));
    return 0;
}

static int test_positive_ima(void)
{
    struct spp_diag_trace_ima r, got;
    uint8_t wire[256], layout[256];
    size_t written, required, consumed;
    const uint8_t *ev;
    size_t ev_len;
    uint16_t kind;

    for (kind = 1; kind <= 3; kind++) {
        fill_valid_ima(&r, kind);
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, wire, 256, &written, &required),
                  WIRE_OK);
        EXPECT_EQ(written, 256);
        EXPECT_EQ(required, 256);
        layout_ima(layout, &r);
        EXPECT_MEM_EQ(wire, layout, 256);
        {
            uint8_t exp[256];
            memcpy(exp, k_ima_ready_literal, 256);
            store16(exp + 10, kind);
            store16(exp + 20, kind);
            EXPECT_MEM_EQ(wire, exp, 256);
        }
        memset(&got, 0x5a, sizeof got);
        consumed = 0;
        EXPECT_EQ(spp_diag_trace_ima_decode(wire, 256, &got, &consumed),
                  WIRE_OK);
        EXPECT_EQ(consumed, 256);
        EXPECT(ima_eq(&got, &r));
        event_for_kind(kind, &ev, &ev_len);
        EXPECT_EQ(spp_diag_trace_ima_validate(&r, ev, ev_len), WIRE_OK);
        EXPECT_EQ(got.kind, kind);
        EXPECT_EQ(got.state, kind);
    }
    return 0;
}

static int roundtrip_header(const struct spp_diag_trace_header *h)
{
    uint8_t wire[192], layout[192];
    struct spp_diag_trace_header got;
    size_t written, required, consumed;

    written = required = 0;
    EXPECT_EQ(spp_diag_trace_header_encode(h, wire, 192, &written, &required),
              WIRE_OK);
    layout_header(layout, h);
    EXPECT_MEM_EQ(wire, layout, 192);
    consumed = 0;
    EXPECT_EQ(spp_diag_trace_header_decode(wire, 192, &got, &consumed),
              WIRE_OK);
    EXPECT(header_eq(&got, h));
    return 0;
}

static int roundtrip_command(const struct spp_diag_trace_command *c)
{
    uint8_t wire[128], layout[128];
    struct spp_diag_trace_command got;
    size_t written, required, consumed;

    written = required = 0;
    EXPECT_EQ(spp_diag_trace_command_encode(c, wire, 128, &written, &required),
              WIRE_OK);
    layout_command(layout, c);
    EXPECT_MEM_EQ(wire, layout, 128);
    consumed = 0;
    EXPECT_EQ(spp_diag_trace_command_decode(wire, 128, &got, &consumed),
              WIRE_OK);
    EXPECT(command_eq(&got, c));
    return 0;
}

static int roundtrip_ima(const struct spp_diag_trace_ima *r)
{
    uint8_t wire[256], layout[256];
    struct spp_diag_trace_ima got;
    size_t written, required, consumed;
    const uint8_t *ev;
    size_t ev_len;

    written = required = 0;
    EXPECT_EQ(spp_diag_trace_ima_encode(r, wire, 256, &written, &required),
              WIRE_OK);
    layout_ima(layout, r);
    EXPECT_MEM_EQ(wire, layout, 256);
    consumed = 0;
    EXPECT_EQ(spp_diag_trace_ima_decode(wire, 256, &got, &consumed), WIRE_OK);
    EXPECT(ima_eq(&got, r));
    event_for_kind(r->kind, &ev, &ev_len);
    EXPECT_EQ(spp_diag_trace_ima_validate(r, ev, ev_len), WIRE_OK);
    return 0;
}

static int test_opaque_twins(void)
{
    struct spp_diag_trace_header h;
    struct spp_diag_trace_command c;
    struct spp_diag_trace_ima r;

    fill_valid_header(&h);
    if (roundtrip_header(&h) != 0) {
        return 1;
    }
    fill_pattern(h.challenge, 32, 0x10);
    fill_pattern(h.run_identity, 32, 0x40);
    fill_pattern(h.control_plan_address, 32, 0x70);
    fill_pattern(h.command_line_sha256, 32, 0xa0);
    if (roundtrip_header(&h) != 0) {
        return 1;
    }

    fill_valid_command(&c, 1, 8);
    if (roundtrip_command(&c) != 0) {
        return 1;
    }
    fill_pattern(c.challenge, 32, 0x21);
    fill_pattern(c.run_identity, 32, 0x51);
    fill_pattern(c.control_plan_address, 32, 0x81);
    if (roundtrip_command(&c) != 0) {
        return 1;
    }

    fill_valid_ima(&r, 1);
    if (roundtrip_ima(&r) != 0) {
        return 1;
    }
    fill_pattern(r.challenge, 32, 0x22);
    fill_pattern(r.run_identity, 32, 0x52);
    fill_pattern(r.control_plan_address, 32, 0x82);
    fill_pattern(r.command_line_sha256, 32, 0xb2);
    fill_pattern(r.chain, 32, 0xc2);
    if (roundtrip_ima(&r) != 0) {
        return 1;
    }
    return 0;
}

static int test_count_and_phase_twins(void)
{
    struct spp_diag_trace_ima r;
    struct spp_diag_trace_command c;
    static const uint64_t frames[] = {1ull, 17ull, 524288ull};
    static const uint64_t streams[] = {244ull, 4096ull, 268435456ull};
    size_t i;

    for (i = 0; i < 3; i++) {
        fill_valid_ima(&r, 2);
        r.frame_count = frames[i];
        r.denied_exec_count = 0;
        r.committed_exec_count = 0;
        if (roundtrip_ima(&r) != 0) {
            return 1;
        }
    }
    for (i = 0; i < 3; i++) {
        fill_valid_ima(&r, 3);
        r.stream_byte_count = streams[i];
        if (roundtrip_ima(&r) != 0) {
            return 1;
        }
    }

    fill_valid_ima(&r, 1);
    r.frame_count = 10;
    r.denied_exec_count = 0;
    r.committed_exec_count = 0;
    if (roundtrip_ima(&r) != 0) {
        return 1;
    }
    r.denied_exec_count = 4;
    r.committed_exec_count = 7;
    if (roundtrip_ima(&r) != 0) {
        return 1;
    }
    r.denied_exec_count = 10;
    r.committed_exec_count = 10;
    if (roundtrip_ima(&r) != 0) {
        return 1;
    }

    fill_valid_command(&c, 1, 2);
    if (roundtrip_command(&c) != 0) {
        return 1;
    }
    fill_valid_command(&c, 1, 9);
    if (roundtrip_command(&c) != 0) {
        return 1;
    }
    fill_valid_command(&c, 1, 14);
    if (roundtrip_command(&c) != 0) {
        return 1;
    }
    return 0;
}

static int test_cross_object_inconsistent_ima(void)
{
    struct spp_diag_trace_header h;
    struct spp_diag_trace_ima r;

    fill_valid_header(&h);
    fill_pattern(h.challenge, 32, 0x11);
    fill_valid_ima(&r, 1);
    fill_pattern(r.challenge, 32, 0x22);
    fill_pattern(r.run_identity, 32, 0x33);
    fill_pattern(r.chain, 32, 0x44);
    r.frame_count = 99;
    r.stream_byte_count = 5000;
    r.denied_exec_count = 3;
    r.committed_exec_count = 8;
    return roundtrip_ima(&r);
}

typedef void (*hdr_poison_fn)(struct spp_diag_trace_header *);
typedef void (*cmd_poison_fn)(struct spp_diag_trace_command *);
typedef void (*ima_poison_fn)(struct spp_diag_trace_ima *);

static void hp_magic(struct spp_diag_trace_header *h) { h->magic[0] ^= 1u; }
static void hp_wver(struct spp_diag_trace_header *h) { h->wire_version = 2; }
static void hp_hlen(struct spp_diag_trace_header *h) { h->header_length = 191; }
static void hp_pver(struct spp_diag_trace_header *h) { h->policy_version = 2; }
static void hp_hash(struct spp_diag_trace_header *h) { h->hash_algorithm = 2; }
static void hp_frames(struct spp_diag_trace_header *h) { h->max_frames = 0; }
static void hp_stream(struct spp_diag_trace_header *h)
{
    h->max_stream_bytes = 0;
}
static void hp_fbytes(struct spp_diag_trace_header *h) { h->max_frame_bytes = 0; }
static void hp_commit(struct spp_diag_trace_header *h)
{
    h->source_commit[0] ^= 1u;
}
static void hp_hook(struct spp_diag_trace_header *h)
{
    h->required_hook_mask = 0;
}
static void hp_res(struct spp_diag_trace_header *h) { h->reserved = 1; }

static void cp_magic(struct spp_diag_trace_command *c) { c->magic[0] ^= 1u; }
static void cp_ver(struct spp_diag_trace_command *c) { c->version = 2; }
static void cp_kind(struct spp_diag_trace_command *c) { c->kind = 0; }
static void cp_len(struct spp_diag_trace_command *c) { c->command_length = 127; }
static void cp_phase(struct spp_diag_trace_command *c)
{
    c->requested_phase = 1;
}
static void cp_res(struct spp_diag_trace_command *c) { c->reserved[0] = 1; }

static void ip_magic(struct spp_diag_trace_ima *r) { r->magic[0] ^= 1u; }
static void ip_wver(struct spp_diag_trace_ima *r) { r->wire_version = 2; }
static void ip_kind(struct spp_diag_trace_ima *r) { r->kind = 0; }
static void ip_len(struct spp_diag_trace_ima *r) { r->record_length = 255; }
static void ip_pver(struct spp_diag_trace_ima *r) { r->policy_version = 2; }
static void ip_hash(struct spp_diag_trace_ima *r) { r->hash_algorithm = 2; }
static void ip_state(struct spp_diag_trace_ima *r) { r->state = 2; }
static void ip_res16(struct spp_diag_trace_ima *r) { r->reserved16 = 1; }
static void ip_commit(struct spp_diag_trace_ima *r) { r->source_commit[0] ^= 1u; }
static void ip_frames(struct spp_diag_trace_ima *r) { r->frame_count = 0; }
static void ip_stream(struct spp_diag_trace_ima *r)
{
    r->stream_byte_count = 243;
}
static void ip_hook(struct spp_diag_trace_ima *r) { r->required_hook_mask = 0; }
static void ip_denied(struct spp_diag_trace_ima *r)
{
    r->denied_exec_count = 2;
}
static void ip_committed(struct spp_diag_trace_ima *r)
{
    r->committed_exec_count = 2;
}
static void ip_loss(struct spp_diag_trace_ima *r) { r->loss_count = 1; }
static void ip_over(struct spp_diag_trace_ima *r) { r->overflow_count = 1; }
static void ip_res32(struct spp_diag_trace_ima *r) { r->reserved32 = 1; }

struct hdr_fault {
    hdr_poison_fn poison;
    int expected;
};
struct cmd_fault {
    cmd_poison_fn poison;
    int expected;
};
struct ima_fault {
    ima_poison_fn poison;
    int expected;
};

static const struct hdr_fault k_hdr_faults[] = {
    {hp_magic, WIRE_MAGIC},   {hp_wver, WIRE_VERSION}, {hp_hlen, WIRE_LENGTH},
    {hp_pver, WIRE_VERSION},  {hp_hash, WIRE_VALUE},   {hp_frames, WIRE_CAP},
    {hp_stream, WIRE_CAP},    {hp_fbytes, WIRE_CAP},   {hp_commit, WIRE_VALUE},
    {hp_hook, WIRE_VALUE},    {hp_res, WIRE_RESERVED}};

static const struct cmd_fault k_cmd_faults[] = {
    {cp_magic, WIRE_MAGIC}, {cp_ver, WIRE_VERSION}, {cp_kind, WIRE_STATE},
    {cp_len, WIRE_LENGTH},  {cp_phase, WIRE_STATE}, {cp_res, WIRE_RESERVED}};

static const struct ima_fault k_ima_faults[] = {
    {ip_magic, WIRE_MAGIC},     {ip_wver, WIRE_VERSION}, {ip_kind, WIRE_EVENT},
    {ip_len, WIRE_LENGTH},      {ip_pver, WIRE_VERSION}, {ip_hash, WIRE_VALUE},
    {ip_state, WIRE_STATE},     {ip_res16, WIRE_RESERVED},
    {ip_commit, WIRE_VALUE},    {ip_frames, WIRE_CAP},    {ip_stream, WIRE_CAP},
    {ip_hook, WIRE_VALUE},      {ip_denied, WIRE_VALUE},  {ip_committed, WIRE_VALUE},
    {ip_loss, WIRE_VALUE},      {ip_over, WIRE_VALUE},    {ip_res32, WIRE_RESERVED}};

static int test_just_outside_and_adjacent(void)
{
    struct spp_diag_trace_header h;
    struct spp_diag_trace_command c;
    struct spp_diag_trace_ima r;
    uint8_t hout[192], cout[128], iout[256], pout[224];
    uint8_t hwire[192], cwire[128], iwire[256];
    size_t written, required, consumed;
    size_t i, n;
    const uint8_t *ev;
    size_t ev_len;
    uint8_t bad_ev[4] = {'x', 'x', 'x', 'x'};

    n = sizeof k_hdr_faults / sizeof k_hdr_faults[0];
    for (i = 0; i < n; i++) {
        fill_valid_header(&h);
        k_hdr_faults[i].poison(&h);
        written = 0x111u;
        required = 0x222u;
        memset(hout, CANARY, sizeof hout);
        EXPECT_EQ(spp_diag_trace_header_encode(&h, hout, 192, &written, &required),
                  k_hdr_faults[i].expected);
        EXPECT_EQ(written, 0);
        EXPECT_EQ(required, 0);
        EXPECT(hout[0] == CANARY && hout[191] == CANARY);
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_header_preimage(&h, pout, 224, &written, &required),
                  k_hdr_faults[i].expected);
        EXPECT_EQ(written, 0);
        EXPECT_EQ(required, 0);
    }
    for (i = 0; i + 1 < n; i++) {
        fill_valid_header(&h);
        k_hdr_faults[i].poison(&h);
        k_hdr_faults[i + 1].poison(&h);
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_header_encode(&h, hout, 192, &written, &required),
                  k_hdr_faults[i].expected);
        EXPECT_EQ(spp_diag_trace_header_preimage(&h, pout, 224, &written, &required),
                  k_hdr_faults[i].expected);
    }

    fill_valid_header(&h);
    EXPECT_EQ(spp_diag_trace_header_encode(&h, hwire, 192, &written, &required),
              WIRE_OK);
    for (i = 0; i < n; i++) {
        uint8_t w[192];
        struct spp_diag_trace_header tmp, snapshot;
        memcpy(w, hwire, 192);
        fill_valid_header(&tmp);
        k_hdr_faults[i].poison(&tmp);
        layout_header(w, &tmp);
        memset(&snapshot, CANARY2, sizeof snapshot);
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_header_decode(w, 192, &snapshot, &consumed),
                  k_hdr_faults[i].expected);
        EXPECT_EQ(consumed, 0);
    }
    for (i = 0; i + 1 < n; i++) {
        uint8_t w[192];
        struct spp_diag_trace_header tmp, out;
        fill_valid_header(&tmp);
        k_hdr_faults[i].poison(&tmp);
        k_hdr_faults[i + 1].poison(&tmp);
        layout_header(w, &tmp);
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_header_decode(w, 192, &out, &consumed),
                  k_hdr_faults[i].expected);
        EXPECT_EQ(consumed, 0);
    }

    n = sizeof k_cmd_faults / sizeof k_cmd_faults[0];
    for (i = 0; i < n; i++) {
        fill_valid_command(&c, 1, 2);
        k_cmd_faults[i].poison(&c);
        written = required = 1;
        memset(cout, CANARY, sizeof cout);
        EXPECT_EQ(spp_diag_trace_command_encode(&c, cout, 128, &written, &required),
                  k_cmd_faults[i].expected);
        EXPECT_EQ(written, 0);
        EXPECT_EQ(required, 0);
    }
    for (i = 0; i + 1 < n; i++) {
        fill_valid_command(&c, 1, 2);
        k_cmd_faults[i].poison(&c);
        k_cmd_faults[i + 1].poison(&c);
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_command_encode(&c, cout, 128, &written, &required),
                  k_cmd_faults[i].expected);
    }
    fill_valid_command(&c, 1, 2);
    EXPECT_EQ(spp_diag_trace_command_encode(&c, cwire, 128, &written, &required),
              WIRE_OK);
    for (i = 0; i < n; i++) {
        uint8_t w[128];
        struct spp_diag_trace_command tmp, snapshot;
        fill_valid_command(&tmp, 1, 2);
        k_cmd_faults[i].poison(&tmp);
        layout_command(w, &tmp);
        memset(&snapshot, CANARY2, sizeof snapshot);
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_command_decode(w, 128, &snapshot, &consumed),
                  k_cmd_faults[i].expected);
        EXPECT_EQ(consumed, 0);
    }
    for (i = 0; i + 1 < n; i++) {
        uint8_t w[128];
        struct spp_diag_trace_command tmp, out;
        fill_valid_command(&tmp, 1, 2);
        k_cmd_faults[i].poison(&tmp);
        k_cmd_faults[i + 1].poison(&tmp);
        layout_command(w, &tmp);
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_command_decode(w, 128, &out, &consumed),
                  k_cmd_faults[i].expected);
        EXPECT_EQ(consumed, 0);
    }

    n = sizeof k_ima_faults / sizeof k_ima_faults[0];
    event_for_kind(1, &ev, &ev_len);
    for (i = 0; i < n; i++) {
        fill_valid_ima(&r, 1);
        k_ima_faults[i].poison(&r);
        written = required = 1;
        memset(iout, CANARY, sizeof iout);
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iout, 256, &written, &required),
                  k_ima_faults[i].expected);
        EXPECT_EQ(written, 0);
        EXPECT_EQ(required, 0);
        EXPECT_EQ(spp_diag_trace_ima_validate(&r, ev, ev_len),
                  k_ima_faults[i].expected);
        EXPECT_EQ(spp_diag_trace_ima_validate(&r, bad_ev, sizeof bad_ev),
                  k_ima_faults[i].expected);
    }
    for (i = 0; i + 1 < n; i++) {
        fill_valid_ima(&r, 1);
        k_ima_faults[i].poison(&r);
        k_ima_faults[i + 1].poison(&r);
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iout, 256, &written, &required),
                  k_ima_faults[i].expected);
        EXPECT_EQ(spp_diag_trace_ima_validate(&r, ev, ev_len),
                  k_ima_faults[i].expected);
    }
    fill_valid_ima(&r, 1);
    EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
              WIRE_OK);
    for (i = 0; i < n; i++) {
        uint8_t w[256];
        struct spp_diag_trace_ima tmp, snapshot;
        fill_valid_ima(&tmp, 1);
        k_ima_faults[i].poison(&tmp);
        layout_ima(w, &tmp);
        memset(&snapshot, CANARY2, sizeof snapshot);
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_ima_decode(w, 256, &snapshot, &consumed),
                  k_ima_faults[i].expected);
        EXPECT_EQ(consumed, 0);
    }
    for (i = 0; i + 1 < n; i++) {
        uint8_t w[256];
        struct spp_diag_trace_ima tmp, out;
        fill_valid_ima(&tmp, 1);
        k_ima_faults[i].poison(&tmp);
        k_ima_faults[i + 1].poison(&tmp);
        layout_ima(w, &tmp);
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_ima_decode(w, 256, &out, &consumed),
                  k_ima_faults[i].expected);
        EXPECT_EQ(consumed, 0);
    }
    fill_valid_ima(&r, 1);
    ip_res32(&r);
    EXPECT_EQ(spp_diag_trace_ima_validate(&r, bad_ev, sizeof bad_ev),
              WIRE_RESERVED);

    {
        struct spp_diag_trace_header extra;
        fill_valid_header(&h);
        extra = h;
        extra.wire_version = 0;
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_VERSION);
        extra = h;
        extra.wire_version = 2;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_VERSION);
        extra = h;
        extra.header_length = 191;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_LENGTH);
        extra = h;
        extra.header_length = 193;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_LENGTH);
        extra = h;
        extra.max_frames = 524287u;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_CAP);
        extra = h;
        extra.max_frames = 524289u;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_CAP);
        extra = h;
        extra.max_stream_bytes = 268435455ull;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_CAP);
        extra = h;
        extra.max_stream_bytes = 268435457ull;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_CAP);
        extra = h;
        extra.max_frame_bytes = 1087u;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_CAP);
        extra = h;
        extra.max_frame_bytes = 1089u;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_CAP);
        extra = h;
        extra.required_hook_mask = 0x0eull;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_VALUE);
        extra = h;
        extra.required_hook_mask = 0x10ull;
        EXPECT_EQ(spp_diag_trace_header_encode(&extra, hout, 192, &written,
                                               &required),
                  WIRE_VALUE);
    }
    {
        struct spp_diag_trace_command extra;
        fill_valid_command(&c, 1, 2);
        extra = c;
        extra.kind = 3;
        EXPECT_EQ(spp_diag_trace_command_encode(&extra, cout, 128, &written,
                                                &required),
                  WIRE_STATE);
        extra = c;
        extra.requested_phase = 1;
        EXPECT_EQ(spp_diag_trace_command_encode(&extra, cout, 128, &written,
                                                &required),
                  WIRE_STATE);
        extra = c;
        extra.requested_phase = 15;
        EXPECT_EQ(spp_diag_trace_command_encode(&extra, cout, 128, &written,
                                                &required),
                  WIRE_STATE);
        fill_valid_command(&extra, 2, 15);
        extra.requested_phase = 14;
        EXPECT_EQ(spp_diag_trace_command_encode(&extra, cout, 128, &written,
                                                &required),
                  WIRE_STATE);
        extra.requested_phase = 16;
        EXPECT_EQ(spp_diag_trace_command_encode(&extra, cout, 128, &written,
                                                &required),
                  WIRE_STATE);
    }
    {
        struct spp_diag_trace_ima extra;
        fill_valid_ima(&r, 1);
        extra = r;
        extra.kind = 4;
        EXPECT_EQ(spp_diag_trace_ima_encode(&extra, iout, 256, &written,
                                            &required),
                  WIRE_EVENT);
        extra = r;
        extra.frame_count = 524289ull;
        EXPECT_EQ(spp_diag_trace_ima_encode(&extra, iout, 256, &written,
                                            &required),
                  WIRE_CAP);
        extra = r;
        extra.stream_byte_count = 268435457ull;
        EXPECT_EQ(spp_diag_trace_ima_encode(&extra, iout, 256, &written,
                                            &required),
                  WIRE_CAP);
        extra = r;
        extra.denied_exec_count = 2;
        EXPECT_EQ(spp_diag_trace_ima_encode(&extra, iout, 256, &written,
                                            &required),
                  WIRE_VALUE);
    }
    return 0;
}

static int flip_region_header(size_t off, size_t n, int expected)
{
    struct spp_diag_trace_header h, out, filled;
    uint8_t wire[192];
    size_t written, required, consumed, i;
    uint8_t saved;

    fill_valid_header(&h);
    EXPECT_EQ(spp_diag_trace_header_encode(&h, wire, 192, &written, &required),
              WIRE_OK);
    for (i = 0; i < n; i++) {
        saved = wire[off + i];
        wire[off + i] = (uint8_t)(saved ^ 1u);
        memset(&out, CANARY2, sizeof out);
        memset(&filled, CANARY2, sizeof filled);
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_header_decode(wire, 192, &out, &consumed),
                  expected);
        EXPECT_EQ(consumed, 0);
        EXPECT(memcmp(&out, &filled, sizeof out) == 0);
        fill_valid_header(&h);
        if (off == 0) {
            h.magic[i] ^= 1u;
        } else if (off == 32) {
            h.source_commit[i] ^= 1u;
        } else if (off == 188) {
            h.reserved = (uint32_t)(1u << (8u * (3u - (unsigned)i)));
        }
        written = required = 0;
        EXPECT_EQ(
            spp_diag_trace_header_encode(&h, wire, 192, &written, &required),
            expected);
        EXPECT_EQ(written, 0);
        EXPECT_EQ(required, 0);
        fill_valid_header(&h);
        EXPECT_EQ(
            spp_diag_trace_header_encode(&h, wire, 192, &written, &required),
            WIRE_OK);
        wire[off + i] = saved;
    }
    return 0;
}

static int test_byte_flips(void)
{
    struct spp_diag_trace_command c, couts;
    struct spp_diag_trace_ima r, iout;
    uint8_t cwire[128], iwire[256];
    size_t written, required, consumed, i;
    uint8_t saved;
    const uint8_t *ev;
    size_t ev_len;
    uint16_t kind;

    if (flip_region_header(0, 8, WIRE_MAGIC) != 0) {
        return 1;
    }
    if (flip_region_header(32, 20, WIRE_VALUE) != 0) {
        return 1;
    }
    if (flip_region_header(188, 4, WIRE_RESERVED) != 0) {
        return 1;
    }

    fill_valid_command(&c, 1, 2);
    EXPECT_EQ(spp_diag_trace_command_encode(&c, cwire, 128, &written, &required),
              WIRE_OK);
    for (i = 0; i < 8; i++) {
        saved = cwire[i];
        cwire[i] ^= 1u;
        memset(&couts, CANARY2, sizeof couts);
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_command_decode(cwire, 128, &couts, &consumed),
                  WIRE_MAGIC);
        EXPECT_EQ(consumed, 0);
        fill_valid_command(&c, 1, 2);
        c.magic[i] ^= 1u;
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_command_encode(&c, cwire, 128, &written,
                                                &required),
                  WIRE_MAGIC);
        fill_valid_command(&c, 1, 2);
        EXPECT_EQ(spp_diag_trace_command_encode(&c, cwire, 128, &written,
                                                &required),
                  WIRE_OK);
        cwire[i] = saved;
    }
    for (i = 0; i < 14; i++) {
        saved = cwire[114 + i];
        cwire[114 + i] ^= 1u;
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_command_decode(cwire, 128, &couts, &consumed),
                  WIRE_RESERVED);
        fill_valid_command(&c, 1, 2);
        c.reserved[i] = 1;
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_command_encode(&c, cwire, 128, &written,
                                                &required),
                  WIRE_RESERVED);
        fill_valid_command(&c, 1, 2);
        EXPECT_EQ(spp_diag_trace_command_encode(&c, cwire, 128, &written,
                                                &required),
                  WIRE_OK);
        cwire[114 + i] = saved;
    }

    fill_valid_ima(&r, 1);
    EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
              WIRE_OK);
    for (i = 0; i < 8; i++) {
        saved = iwire[i];
        iwire[i] ^= 1u;
        memset(&iout, CANARY2, sizeof iout);
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_ima_decode(iwire, 256, &iout, &consumed),
                  WIRE_MAGIC);
        fill_valid_ima(&r, 1);
        r.magic[i] ^= 1u;
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
                  WIRE_MAGIC);
        fill_valid_ima(&r, 1);
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
                  WIRE_OK);
        iwire[i] = saved;
    }
    for (i = 0; i < 20; i++) {
        saved = iwire[24 + i];
        iwire[24 + i] ^= 1u;
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_ima_decode(iwire, 256, &iout, &consumed),
                  WIRE_VALUE);
        fill_valid_ima(&r, 1);
        r.source_commit[i] ^= 1u;
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
                  WIRE_VALUE);
        fill_valid_ima(&r, 1);
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
                  WIRE_OK);
        iwire[24 + i] = saved;
    }
    for (i = 0; i < 2; i++) {
        saved = iwire[22 + i];
        iwire[22 + i] ^= 1u;
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_ima_decode(iwire, 256, &iout, &consumed),
                  WIRE_RESERVED);
        iwire[22 + i] = saved;
        fill_valid_ima(&r, 1);
        r.reserved16 = (uint16_t)(1u << (8u * (1u - (unsigned)i)));
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
                  WIRE_RESERVED);
        EXPECT_EQ(written, 0);
        EXPECT_EQ(required, 0);
        fill_valid_ima(&r, 1);
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
                  WIRE_OK);
    }
    for (i = 0; i < 4; i++) {
        saved = iwire[252 + i];
        iwire[252 + i] ^= 1u;
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_ima_decode(iwire, 256, &iout, &consumed),
                  WIRE_RESERVED);
        iwire[252 + i] = saved;
        fill_valid_ima(&r, 1);
        r.reserved32 = (uint32_t)(1u << (8u * (3u - (unsigned)i)));
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
                  WIRE_RESERVED);
        EXPECT_EQ(written, 0);
        EXPECT_EQ(required, 0);
        fill_valid_ima(&r, 1);
        EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
                  WIRE_OK);
    }

    for (kind = 1; kind <= 3; kind++) {
        uint8_t buf[32];
        size_t j;
        event_for_kind(kind, &ev, &ev_len);
        fill_valid_ima(&r, kind);
        for (j = 0; j < ev_len; j++) {
            memcpy(buf, ev, ev_len);
            buf[j] ^= 1u;
            EXPECT_EQ(spp_diag_trace_ima_validate(&r, buf, ev_len), WIRE_EVENT);
        }
    }
    return 0;
}

static int test_precedence(void)
{
    struct spp_diag_trace_header h, hout;
    struct spp_diag_trace_command c, couts;
    struct spp_diag_trace_ima r, iouts;
    uint8_t wire[192], out[256], pre[224];
    uint8_t cwire[129], iwire[257];
    size_t written, required, consumed;
    uint8_t bad_ev[8];

    fill_valid_header(&h);
    h.magic[0] ^= 1u;
    layout_header(wire, &h);
    memset(&hout, CANARY2, sizeof hout);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_decode(wire, 0, &hout, &consumed),
              WIRE_LENGTH);
    EXPECT_EQ(consumed, 0);
    EXPECT_EQ(spp_diag_trace_header_decode(wire, 191, &hout, &consumed),
              WIRE_LENGTH);
    EXPECT_EQ(spp_diag_trace_header_decode(wire, 193, &hout, &consumed),
              WIRE_LENGTH);
    EXPECT_EQ(spp_diag_trace_header_decode(wire, 192, &hout, &consumed),
              WIRE_MAGIC);

    memset(out, CANARY, sizeof out);
    written = 0x10;
    required = 0x20;
    EXPECT_EQ(spp_diag_trace_header_encode(&h, out, 0, &written, &required),
              WIRE_MAGIC);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    EXPECT_EQ(out[0], CANARY);
    written = required = 1;
    EXPECT_EQ(spp_diag_trace_header_preimage(&h, pre, 0, &written, &required),
              WIRE_MAGIC);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);

    fill_valid_command(&c, 1, 2);
    c.magic[0] ^= 1u;
    layout_command(cwire, &c);
    cwire[128] = CANARY;
    memset(&couts, CANARY2, sizeof couts);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_command_decode(cwire, 0, &couts, &consumed),
              WIRE_LENGTH);
    EXPECT_EQ(consumed, 0);
    EXPECT_EQ(spp_diag_trace_command_decode(cwire, 129, &couts, &consumed),
              WIRE_LENGTH);
    EXPECT_EQ(consumed, 0);
    EXPECT_EQ(spp_diag_trace_command_decode(cwire, 128, &couts, &consumed),
              WIRE_MAGIC);
    memset(out, CANARY, sizeof out);
    written = required = 1;
    EXPECT_EQ(spp_diag_trace_command_encode(&c, out, 0, &written, &required),
              WIRE_MAGIC);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    EXPECT_EQ(out[0], CANARY);

    fill_valid_ima(&r, 1);
    r.magic[0] ^= 1u;
    layout_ima(iwire, &r);
    iwire[256] = CANARY;
    memset(&iouts, CANARY2, sizeof iouts);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_ima_decode(iwire, 0, &iouts, &consumed),
              WIRE_LENGTH);
    EXPECT_EQ(consumed, 0);
    EXPECT_EQ(spp_diag_trace_ima_decode(iwire, 257, &iouts, &consumed),
              WIRE_LENGTH);
    EXPECT_EQ(consumed, 0);
    EXPECT_EQ(spp_diag_trace_ima_decode(iwire, 256, &iouts, &consumed),
              WIRE_MAGIC);
    memset(out, CANARY, sizeof out);
    written = required = 1;
    EXPECT_EQ(spp_diag_trace_ima_encode(&r, out, 0, &written, &required),
              WIRE_MAGIC);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    EXPECT_EQ(out[0], CANARY);

    memset(bad_ev, 'z', sizeof bad_ev);
    EXPECT_EQ(spp_diag_trace_ima_validate(&r, bad_ev, sizeof bad_ev),
              WIRE_MAGIC);
    EXPECT_EQ(spp_diag_trace_ima_validate(&r, k_ev_ready, 5), WIRE_MAGIC);
    fill_valid_ima(&r, 1);
    r.state = 2;
    EXPECT_EQ(spp_diag_trace_ima_validate(&r, k_ev_release, 23), WIRE_STATE);
    return 0;
}

struct hdr_box {
    uint8_t pre[8];
    struct spp_diag_trace_header h;
    uint8_t post[8];
};

struct cmd_box {
    uint8_t pre[8];
    struct spp_diag_trace_command c;
    uint8_t post[8];
};

struct ima_box {
    uint8_t pre[8];
    struct spp_diag_trace_ima r;
    uint8_t post[8];
};

static int test_decoder_bounds(void)
{
    struct spp_diag_trace_header h;
    struct spp_diag_trace_command c;
    struct spp_diag_trace_ima r;
    uint8_t hwire[192], cwire[128], iwire[256];
    uint8_t hin[8 + 193 + 8], cin[8 + 129 + 8], iin[8 + 257 + 8];
    struct hdr_box hb, hb_snap;
    struct cmd_box cb, cb_snap;
    struct ima_box ib, ib_snap;
    size_t written, required, consumed, len;

    fill_valid_header(&h);
    fill_valid_command(&c, 1, 2);
    fill_valid_ima(&r, 1);
    EXPECT_EQ(spp_diag_trace_header_encode(&h, hwire, 192, &written, &required),
              WIRE_OK);
    EXPECT_EQ(spp_diag_trace_command_encode(&c, cwire, 128, &written, &required),
              WIRE_OK);
    EXPECT_EQ(spp_diag_trace_ima_encode(&r, iwire, 256, &written, &required),
              WIRE_OK);

    memset(hin, CANARY, sizeof hin);
    memcpy(hin + 8, hwire, 192);
    memset(&hb, CANARY2, sizeof hb);
    hb_snap = hb;
    for (len = 0; len < 192; len++) {
        hb = hb_snap;
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_header_decode(hin + 8, len, &hb.h, &consumed),
                  WIRE_LENGTH);
        EXPECT_EQ(consumed, 0);
        EXPECT(memcmp(&hb, &hb_snap, sizeof hb) == 0);
        EXPECT_EQ(hin[0], CANARY);
        EXPECT_EQ(hin[7], CANARY);
        EXPECT_EQ(hin[8 + 192], CANARY);
    }
    hb = hb_snap;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_decode(hin + 8, 193, &hb.h, &consumed),
              WIRE_LENGTH);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&hb, &hb_snap, sizeof hb) == 0);
    EXPECT_EQ(hin[8 + 192], CANARY);

    memset(cin, CANARY, sizeof cin);
    memcpy(cin + 8, cwire, 128);
    memset(&cb, CANARY2, sizeof cb);
    cb_snap = cb;
    for (len = 0; len < 128; len++) {
        cb = cb_snap;
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_command_decode(cin + 8, len, &cb.c, &consumed),
                  WIRE_LENGTH);
        EXPECT_EQ(consumed, 0);
        EXPECT(memcmp(&cb, &cb_snap, sizeof cb) == 0);
    }
    cb = cb_snap;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_command_decode(cin + 8, 129, &cb.c, &consumed),
              WIRE_LENGTH);
    EXPECT(memcmp(&cb, &cb_snap, sizeof cb) == 0);

    memset(iin, CANARY, sizeof iin);
    memcpy(iin + 8, iwire, 256);
    memset(&ib, CANARY2, sizeof ib);
    ib_snap = ib;
    for (len = 0; len < 256; len++) {
        ib = ib_snap;
        consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_ima_decode(iin + 8, len, &ib.r, &consumed),
                  WIRE_LENGTH);
        EXPECT_EQ(consumed, 0);
        EXPECT(memcmp(&ib, &ib_snap, sizeof ib) == 0);
    }
    ib = ib_snap;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_ima_decode(iin + 8, 257, &ib.r, &consumed),
              WIRE_LENGTH);
    EXPECT(memcmp(&ib, &ib_snap, sizeof ib) == 0);
    return 0;
}

static int check_encode_capacity(int (*encode)(const void *, uint8_t *, size_t,
                                               size_t *, size_t *),
                                 const void *obj, const uint8_t *expected,
                                 size_t n)
{
    uint8_t buf[8 + 257 + 8];
    size_t written, required, i;

    memset(buf, CANARY, sizeof buf);
    written = required = (size_t)-1;
    EXPECT_EQ(encode(obj, buf + 8, n, &written, &required), WIRE_OK);
    EXPECT_EQ(written, n);
    EXPECT_EQ(required, n);
    EXPECT_MEM_EQ(buf + 8, expected, n);
    EXPECT_EQ(buf[7], CANARY);
    EXPECT_EQ(buf[8 + n], CANARY);

    memset(buf, CANARY, sizeof buf);
    written = required = (size_t)-1;
    EXPECT_EQ(encode(obj, buf + 8, 0, &written, &required),
              WIRE_BUFFER_TOO_SMALL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, n);
    for (i = 0; i < sizeof buf; i++) {
        EXPECT_EQ(buf[i], CANARY);
    }

    memset(buf, CANARY, sizeof buf);
    written = required = (size_t)-1;
    EXPECT_EQ(encode(obj, buf + 8, n - 1, &written, &required),
              WIRE_BUFFER_TOO_SMALL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, n);
    for (i = 0; i < sizeof buf; i++) {
        EXPECT_EQ(buf[i], CANARY);
    }

    memset(buf, CANARY, sizeof buf);
    written = required = (size_t)-1;
    EXPECT_EQ(encode(obj, buf + 8, n + 1, &written, &required), WIRE_OK);
    EXPECT_EQ(written, n);
    EXPECT_EQ(required, n);
    EXPECT_MEM_EQ(buf + 8, expected, n);
    EXPECT_EQ(buf[8 + n], CANARY);
    EXPECT_EQ(buf[7], CANARY);
    return 0;
}

static int enc_hdr(const void *obj, uint8_t *out, size_t cap, size_t *written,
                   size_t *required)
{
    return spp_diag_trace_header_encode((const struct spp_diag_trace_header *)obj,
                                        out, cap, written, required);
}

static int enc_pre(const void *obj, uint8_t *out, size_t cap, size_t *written,
                   size_t *required)
{
    return spp_diag_trace_header_preimage(
        (const struct spp_diag_trace_header *)obj, out, cap, written, required);
}

static int enc_cmd(const void *obj, uint8_t *out, size_t cap, size_t *written,
                   size_t *required)
{
    return spp_diag_trace_command_encode(
        (const struct spp_diag_trace_command *)obj, out, cap, written, required);
}

static int enc_ima(const void *obj, uint8_t *out, size_t cap, size_t *written,
                   size_t *required)
{
    return spp_diag_trace_ima_encode((const struct spp_diag_trace_ima *)obj, out,
                                     cap, written, required);
}

static int test_all_or_nothing_capacity(void)
{
    struct spp_diag_trace_header h;
    struct spp_diag_trace_command c;
    struct spp_diag_trace_ima r;
    uint8_t pre_exp[224];

    fill_valid_header(&h);
    fill_valid_command(&c, 1, 2);
    fill_valid_ima(&r, 1);
    memcpy(pre_exp, k_domain, 28);
    store32(pre_exp + 28, 192);
    memcpy(pre_exp + 32, k_hdr_literal, 192);

    if (check_encode_capacity(enc_hdr, &h, k_hdr_literal, 192) != 0) {
        return 1;
    }
    if (check_encode_capacity(enc_cmd, &c, k_cmd_advance2_literal, 128) != 0) {
        return 1;
    }
    if (check_encode_capacity(enc_ima, &r, k_ima_ready_literal, 256) != 0) {
        return 1;
    }
    if (check_encode_capacity(enc_pre, &h, pre_exp, 224) != 0) {
        return 1;
    }
    return 0;
}

static int test_ima_wrong_state_and_names(void)
{
    struct spp_diag_trace_ima r, got;
    uint8_t wire[256];
    size_t written, required, consumed;
    uint16_t kind, state, other;
    const uint8_t *ev, *ev2;
    size_t ev_len, ev2_len;
    uint8_t buf[40];
    size_t i, n;

    for (kind = 1; kind <= 3; kind++) {
        for (state = 1; state <= 3; state++) {
            if (state == kind) {
                continue;
            }
            fill_valid_ima(&r, kind);
            r.state = state;
            written = required = 1;
            memset(wire, CANARY, sizeof wire);
            EXPECT_EQ(spp_diag_trace_ima_encode(&r, wire, 256, &written,
                                                &required),
                      WIRE_STATE);
            EXPECT_EQ(written, 0);
            EXPECT_EQ(required, 0);
            EXPECT_EQ(wire[0], CANARY);

            fill_valid_ima(&r, kind);
            EXPECT_EQ(
                spp_diag_trace_ima_encode(&r, wire, 256, &written, &required),
                WIRE_OK);
            store16(wire + 20, state);
            memset(&got, CANARY2, sizeof got);
            consumed = (size_t)-1;
            EXPECT_EQ(spp_diag_trace_ima_decode(wire, 256, &got, &consumed),
                      WIRE_STATE);
            EXPECT_EQ(consumed, 0);

            fill_valid_ima(&r, kind);
            r.state = state;
            event_for_kind(kind, &ev, &ev_len);
            EXPECT_EQ(spp_diag_trace_ima_validate(&r, ev, ev_len), WIRE_STATE);
        }
    }

    for (kind = 1; kind <= 3; kind++) {
        fill_valid_ima(&r, kind);
        event_for_kind(kind, &ev, &ev_len);
        for (other = 1; other <= 3; other++) {
            if (other == kind) {
                continue;
            }
            event_for_kind(other, &ev2, &ev2_len);
            EXPECT_EQ(spp_diag_trace_ima_validate(&r, ev2, ev2_len), WIRE_EVENT);
        }
        n = ev_len;
        for (i = 0; i < n; i++) {
            EXPECT_EQ(spp_diag_trace_ima_validate(&r, ev, i), WIRE_EVENT);
        }
        memcpy(buf, ev, n);
        buf[n] = 0x41;
        EXPECT_EQ(spp_diag_trace_ima_validate(&r, buf, n + 1), WIRE_EVENT);
        memcpy(buf, ev, n);
        buf[n] = 0x00;
        EXPECT_EQ(spp_diag_trace_ima_validate(&r, buf, n + 1), WIRE_EVENT);
        memcpy(buf, ev, n);
        buf[0] = 0x00;
        EXPECT_EQ(spp_diag_trace_ima_validate(&r, buf, n), WIRE_EVENT);
        memcpy(buf, ev, n);
        buf[n / 2] = 0x00;
        EXPECT_EQ(spp_diag_trace_ima_validate(&r, buf, n), WIRE_EVENT);
        for (i = 0; i < n; i++) {
            memcpy(buf, ev, n);
            buf[i] ^= 1u;
            EXPECT_EQ(spp_diag_trace_ima_validate(&r, buf, n), WIRE_EVENT);
        }
    }
    return 0;
}

static int test_null_pointers(void)
{
    struct spp_diag_trace_header h;
    struct spp_diag_trace_command c;
    struct spp_diag_trace_ima r;
    uint8_t out[256], snap[256];
    size_t written, required, consumed;
    struct hdr_box hb, hb_snap;
    struct cmd_box cb, cb_snap;
    struct ima_box ib, ib_snap;

    fill_valid_header(&h);
    h.magic[0] ^= 1u;
    fill_valid_command(&c, 1, 2);
    c.magic[0] ^= 1u;
    fill_valid_ima(&r, 1);
    r.magic[0] ^= 1u;

    memset(out, CANARY, sizeof out);
    memcpy(snap, out, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_encode(NULL, out, 0, &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    EXPECT_MEM_EQ(out, snap, sizeof out);

    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_encode(&h, NULL, 192, &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);

    memset(out, CANARY, sizeof out);
    required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_encode(&h, out, 192, NULL, &required),
              WIRE_NULL);
    EXPECT_EQ(required, 0);
    EXPECT_EQ(out[0], CANARY);

    written = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_encode(&h, out, 192, &written, NULL),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(out[0], CANARY);

    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_preimage(NULL, out, 0, &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    EXPECT_EQ(spp_diag_trace_header_preimage(&h, NULL, 224, &written, &required),
              WIRE_NULL);
    EXPECT_EQ(spp_diag_trace_header_preimage(&h, out, 224, NULL, &required),
              WIRE_NULL);
    EXPECT_EQ(spp_diag_trace_header_preimage(&h, out, 224, &written, NULL),
              WIRE_NULL);

    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_command_encode(NULL, out, 0, &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    EXPECT_EQ(spp_diag_trace_command_encode(&c, NULL, 128, &written, &required),
              WIRE_NULL);
    EXPECT_EQ(spp_diag_trace_command_encode(&c, out, 128, NULL, &required),
              WIRE_NULL);
    EXPECT_EQ(spp_diag_trace_command_encode(&c, out, 128, &written, NULL),
              WIRE_NULL);

    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_ima_encode(NULL, out, 0, &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    EXPECT_EQ(spp_diag_trace_ima_encode(&r, NULL, 256, &written, &required),
              WIRE_NULL);
    EXPECT_EQ(spp_diag_trace_ima_encode(&r, out, 256, NULL, &required),
              WIRE_NULL);
    EXPECT_EQ(spp_diag_trace_ima_encode(&r, out, 256, &written, NULL),
              WIRE_NULL);

    memset(&hb, CANARY2, sizeof hb);
    hb_snap = hb;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_decode(NULL, 0, &hb.h, &consumed),
              WIRE_NULL);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&hb, &hb_snap, sizeof hb) == 0);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_header_decode(out, 0, NULL, &consumed), WIRE_NULL);
    EXPECT_EQ(consumed, 0);
    EXPECT_EQ(spp_diag_trace_header_decode(out, 0, &hb.h, NULL), WIRE_NULL);
    EXPECT(memcmp(&hb, &hb_snap, sizeof hb) == 0);

    memset(&cb, CANARY2, sizeof cb);
    cb_snap = cb;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_command_decode(NULL, 0, &cb.c, &consumed),
              WIRE_NULL);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&cb, &cb_snap, sizeof cb) == 0);
    EXPECT_EQ(spp_diag_trace_command_decode(out, 0, NULL, &consumed), WIRE_NULL);
    EXPECT_EQ(spp_diag_trace_command_decode(out, 0, &cb.c, NULL), WIRE_NULL);

    memset(&ib, CANARY2, sizeof ib);
    ib_snap = ib;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_ima_decode(NULL, 0, &ib.r, &consumed), WIRE_NULL);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&ib, &ib_snap, sizeof ib) == 0);
    EXPECT_EQ(spp_diag_trace_ima_decode(out, 0, NULL, &consumed), WIRE_NULL);
    EXPECT_EQ(spp_diag_trace_ima_decode(out, 0, &ib.r, NULL), WIRE_NULL);

    EXPECT_EQ(spp_diag_trace_ima_validate(NULL, k_ev_ready, 21), WIRE_NULL);
    EXPECT_EQ(spp_diag_trace_ima_validate(&r, NULL, 0), WIRE_NULL);
    return 0;
}

int run_spp_diag_trace_frame_tests(void);
int run_spp_diag_trace_stream_tests(void);
int run_spp_diag_trace_provenance_tests(void);

int main(void)
{
    if (test_result_constants() != 0) {
        return 1;
    }
    if (test_positive_header_preimage() != 0) {
        return 1;
    }
    if (test_positive_commands() != 0) {
        return 1;
    }
    if (test_positive_ima() != 0) {
        return 1;
    }
    if (test_opaque_twins() != 0) {
        return 1;
    }
    if (test_count_and_phase_twins() != 0) {
        return 1;
    }
    if (test_cross_object_inconsistent_ima() != 0) {
        return 1;
    }
    if (test_just_outside_and_adjacent() != 0) {
        return 1;
    }
    if (test_byte_flips() != 0) {
        return 1;
    }
    if (test_precedence() != 0) {
        return 1;
    }
    if (test_decoder_bounds() != 0) {
        return 1;
    }
    if (test_all_or_nothing_capacity() != 0) {
        return 1;
    }
    if (test_ima_wrong_state_and_names() != 0) {
        return 1;
    }
    if (test_null_pointers() != 0) {
        return 1;
    }
    if (run_spp_diag_trace_frame_tests() != 0) {
        return 1;
    }
    if (run_spp_diag_trace_stream_tests() != 0) {
        return 1;
    }
    if (run_spp_diag_trace_provenance_tests() != 0) {
        return 1;
    }
    return 0;
}
