/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

#include "conf_proc_spp_diag_trace.h"

const uint8_t SPP_DIAG_TRACE_SOURCE_COMMIT[SPP_DIAG_TRACE_SOURCE_COMMIT_LEN] = {
    0x91, 0xa8, 0xe8, 0x26, 0x01, 0x2f, 0xbb, 0x1c, 0x7f, 0x5c,
    0xb2, 0xa3, 0x26, 0xc0, 0x8b, 0x13, 0xe3, 0x90, 0xf4, 0x69};

const uint8_t SPP_DIAG_TRACE_IMA_LABEL[SPP_DIAG_TRACE_IMA_LABEL_LEN] = {
    's', 'o', 'l', '_', 's', 'p', 'p', '_', 'd', 'i',
    'a', 'g', '_', 't', 'r', 'a', 'c', 'e'};

static const uint8_t k_magic_header[8] = {
    'S', 'P', 'P', 'T', 'R', 'C', '1', 0x00};
static const uint8_t k_magic_command[8] = {
    'S', 'P', 'P', 'C', 'M', 'D', '1', 0x00};
static const uint8_t k_magic_ima[8] = {
    'S', 'P', 'P', 'I', 'M', 'A', '1', 0x00};

static const uint8_t k_preimage_domain[28] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g', '-', 't',
    'r', 'a', 'c', 'e', '-', 'h', 'e', 'a', 'd', 'e', 'r', '/', 'v', '1'};

static const uint8_t k_ima_event_ready[21] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a',
    'g', '-', 'r', 'e', 'a', 'd', 'y', '-', 'v', '1'};
static const uint8_t k_ima_event_release[23] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g',
    '-', 'r', 'e', 'l', 'e', 'a', 's', 'e', '-', 'v', '1'};
static const uint8_t k_ima_event_terminal[24] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g',
    '-', 't', 'e', 'r', 'm', 'i', 'n', 'a', 'l', '-', 'v', '1'};

static void copy_n(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

static int eq_n(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static int is_zero_n(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (p[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void store_u16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void store_u32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void store_u64be(uint8_t *p, uint64_t v)
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

static uint16_t load_u16be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t load_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t load_u64be(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static int fail_encode(int err, size_t *written, size_t *required)
{
    *written = 0;
    *required = 0;
    return err;
}

static int header_fields(const struct spp_diag_trace_header *h)
{
    if (!eq_n(h->magic, k_magic_header, 8)) {
        return WIRE_MAGIC;
    }
    if (h->wire_version != SPP_DIAG_TRACE_WIRE_VERSION) {
        return WIRE_VERSION;
    }
    if (h->header_length != SPP_DIAG_TRACE_HEADER_SIZE) {
        return WIRE_LENGTH;
    }
    if (h->policy_version != SPP_DIAG_TRACE_POLICY_VERSION) {
        return WIRE_VERSION;
    }
    if (h->hash_algorithm != SPP_DIAG_TRACE_HASH_SHA256) {
        return WIRE_VALUE;
    }
    if (h->max_frames != SPP_DIAG_TRACE_MAX_FRAMES) {
        return WIRE_CAP;
    }
    if (h->max_stream_bytes != SPP_DIAG_TRACE_MAX_STREAM_BYTES) {
        return WIRE_CAP;
    }
    if (h->max_frame_bytes != SPP_DIAG_TRACE_MAX_FRAME_BYTES) {
        return WIRE_CAP;
    }
    if (!eq_n(h->source_commit, SPP_DIAG_TRACE_SOURCE_COMMIT,
              SPP_DIAG_TRACE_SOURCE_COMMIT_LEN)) {
        return WIRE_VALUE;
    }
    if (h->required_hook_mask != SPP_DIAG_TRACE_HOOK_MASK) {
        return WIRE_VALUE;
    }
    if (h->reserved != 0) {
        return WIRE_RESERVED;
    }
    return WIRE_OK;
}

static void header_to_wire(const struct spp_diag_trace_header *h, uint8_t *out)
{
    copy_n(out + 0, h->magic, 8);
    store_u16be(out + 8, h->wire_version);
    store_u16be(out + 10, h->header_length);
    store_u16be(out + 12, h->policy_version);
    store_u16be(out + 14, h->hash_algorithm);
    store_u32be(out + 16, h->max_frames);
    store_u64be(out + 20, h->max_stream_bytes);
    store_u32be(out + 28, h->max_frame_bytes);
    copy_n(out + 32, h->source_commit, SPP_DIAG_TRACE_SOURCE_COMMIT_LEN);
    copy_n(out + 52, h->challenge, 32);
    copy_n(out + 84, h->run_identity, 32);
    copy_n(out + 116, h->control_plan_address, 32);
    copy_n(out + 148, h->command_line_sha256, 32);
    store_u64be(out + 180, h->required_hook_mask);
    store_u32be(out + 188, h->reserved);
}

static void header_from_wire(const uint8_t *in, struct spp_diag_trace_header *h)
{
    copy_n(h->magic, in + 0, 8);
    h->wire_version = load_u16be(in + 8);
    h->header_length = load_u16be(in + 10);
    h->policy_version = load_u16be(in + 12);
    h->hash_algorithm = load_u16be(in + 14);
    h->max_frames = load_u32be(in + 16);
    h->max_stream_bytes = load_u64be(in + 20);
    h->max_frame_bytes = load_u32be(in + 28);
    copy_n(h->source_commit, in + 32, SPP_DIAG_TRACE_SOURCE_COMMIT_LEN);
    copy_n(h->challenge, in + 52, 32);
    copy_n(h->run_identity, in + 84, 32);
    copy_n(h->control_plan_address, in + 116, 32);
    copy_n(h->command_line_sha256, in + 148, 32);
    h->required_hook_mask = load_u64be(in + 180);
    h->reserved = load_u32be(in + 188);
}

static int command_fields(const struct spp_diag_trace_command *c)
{
    if (!eq_n(c->magic, k_magic_command, 8)) {
        return WIRE_MAGIC;
    }
    if (c->version != SPP_DIAG_TRACE_WIRE_VERSION) {
        return WIRE_VERSION;
    }
    if (c->kind != SPP_DIAG_TRACE_CMD_ADVANCE_PHASE &&
        c->kind != SPP_DIAG_TRACE_CMD_SEAL) {
        return WIRE_STATE;
    }
    if (c->command_length != SPP_DIAG_TRACE_COMMAND_SIZE) {
        return WIRE_LENGTH;
    }
    if (c->kind == SPP_DIAG_TRACE_CMD_ADVANCE_PHASE) {
        if (c->requested_phase < SPP_DIAG_TRACE_CMD_ADVANCE_PHASE_MIN ||
            c->requested_phase > SPP_DIAG_TRACE_CMD_ADVANCE_PHASE_MAX) {
            return WIRE_STATE;
        }
    } else if (c->requested_phase != SPP_DIAG_TRACE_CMD_SEAL_PHASE) {
        return WIRE_STATE;
    }
    if (!is_zero_n(c->reserved, 14)) {
        return WIRE_RESERVED;
    }
    return WIRE_OK;
}

static void command_to_wire(const struct spp_diag_trace_command *c, uint8_t *out)
{
    copy_n(out + 0, c->magic, 8);
    store_u16be(out + 8, c->version);
    store_u16be(out + 10, c->kind);
    store_u32be(out + 12, c->command_length);
    copy_n(out + 16, c->challenge, 32);
    copy_n(out + 48, c->run_identity, 32);
    copy_n(out + 80, c->control_plan_address, 32);
    store_u16be(out + 112, c->requested_phase);
    copy_n(out + 114, c->reserved, 14);
}

static void command_from_wire(const uint8_t *in, struct spp_diag_trace_command *c)
{
    copy_n(c->magic, in + 0, 8);
    c->version = load_u16be(in + 8);
    c->kind = load_u16be(in + 10);
    c->command_length = load_u32be(in + 12);
    copy_n(c->challenge, in + 16, 32);
    copy_n(c->run_identity, in + 48, 32);
    copy_n(c->control_plan_address, in + 80, 32);
    c->requested_phase = load_u16be(in + 112);
    copy_n(c->reserved, in + 114, 14);
}

static int ima_fields(const struct spp_diag_trace_ima *r)
{
    if (!eq_n(r->magic, k_magic_ima, 8)) {
        return WIRE_MAGIC;
    }
    if (r->wire_version != SPP_DIAG_TRACE_WIRE_VERSION) {
        return WIRE_VERSION;
    }
    if (r->kind < SPP_DIAG_TRACE_IMA_KIND_READY ||
        r->kind > SPP_DIAG_TRACE_IMA_KIND_SEALED) {
        return WIRE_EVENT;
    }
    if (r->record_length != SPP_DIAG_TRACE_IMA_SIZE) {
        return WIRE_LENGTH;
    }
    if (r->policy_version != SPP_DIAG_TRACE_POLICY_VERSION) {
        return WIRE_VERSION;
    }
    if (r->hash_algorithm != SPP_DIAG_TRACE_HASH_SHA256) {
        return WIRE_VALUE;
    }
    if (r->state != r->kind) {
        return WIRE_STATE;
    }
    if (r->reserved16 != 0) {
        return WIRE_RESERVED;
    }
    if (!eq_n(r->source_commit, SPP_DIAG_TRACE_SOURCE_COMMIT,
              SPP_DIAG_TRACE_SOURCE_COMMIT_LEN)) {
        return WIRE_VALUE;
    }
    if (r->frame_count < SPP_DIAG_TRACE_IMA_FRAME_COUNT_MIN ||
        r->frame_count > SPP_DIAG_TRACE_MAX_FRAMES) {
        return WIRE_CAP;
    }
    if (r->stream_byte_count < SPP_DIAG_TRACE_IMA_STREAM_BYTES_MIN ||
        r->stream_byte_count > SPP_DIAG_TRACE_MAX_STREAM_BYTES) {
        return WIRE_CAP;
    }
    if (r->required_hook_mask != SPP_DIAG_TRACE_HOOK_MASK) {
        return WIRE_VALUE;
    }
    if (r->denied_exec_count > r->frame_count) {
        return WIRE_VALUE;
    }
    if (r->committed_exec_count > r->frame_count) {
        return WIRE_VALUE;
    }
    if (r->loss_count != 0) {
        return WIRE_VALUE;
    }
    if (r->overflow_count != 0) {
        return WIRE_VALUE;
    }
    if (r->reserved32 != 0) {
        return WIRE_RESERVED;
    }
    return WIRE_OK;
}

static void ima_to_wire(const struct spp_diag_trace_ima *r, uint8_t *out)
{
    copy_n(out + 0, r->magic, 8);
    store_u16be(out + 8, r->wire_version);
    store_u16be(out + 10, r->kind);
    store_u32be(out + 12, r->record_length);
    store_u16be(out + 16, r->policy_version);
    store_u16be(out + 18, r->hash_algorithm);
    store_u16be(out + 20, r->state);
    store_u16be(out + 22, r->reserved16);
    copy_n(out + 24, r->source_commit, SPP_DIAG_TRACE_SOURCE_COMMIT_LEN);
    copy_n(out + 44, r->challenge, 32);
    copy_n(out + 76, r->run_identity, 32);
    copy_n(out + 108, r->control_plan_address, 32);
    copy_n(out + 140, r->command_line_sha256, 32);
    store_u64be(out + 172, r->frame_count);
    store_u64be(out + 180, r->stream_byte_count);
    copy_n(out + 188, r->chain, 32);
    store_u64be(out + 220, r->required_hook_mask);
    store_u64be(out + 228, r->denied_exec_count);
    store_u64be(out + 236, r->committed_exec_count);
    store_u32be(out + 244, r->loss_count);
    store_u32be(out + 248, r->overflow_count);
    store_u32be(out + 252, r->reserved32);
}

static void ima_from_wire(const uint8_t *in, struct spp_diag_trace_ima *r)
{
    copy_n(r->magic, in + 0, 8);
    r->wire_version = load_u16be(in + 8);
    r->kind = load_u16be(in + 10);
    r->record_length = load_u32be(in + 12);
    r->policy_version = load_u16be(in + 16);
    r->hash_algorithm = load_u16be(in + 18);
    r->state = load_u16be(in + 20);
    r->reserved16 = load_u16be(in + 22);
    copy_n(r->source_commit, in + 24, SPP_DIAG_TRACE_SOURCE_COMMIT_LEN);
    copy_n(r->challenge, in + 44, 32);
    copy_n(r->run_identity, in + 76, 32);
    copy_n(r->control_plan_address, in + 108, 32);
    copy_n(r->command_line_sha256, in + 140, 32);
    r->frame_count = load_u64be(in + 172);
    r->stream_byte_count = load_u64be(in + 180);
    copy_n(r->chain, in + 188, 32);
    r->required_hook_mask = load_u64be(in + 220);
    r->denied_exec_count = load_u64be(in + 228);
    r->committed_exec_count = load_u64be(in + 236);
    r->loss_count = load_u32be(in + 244);
    r->overflow_count = load_u32be(in + 248);
    r->reserved32 = load_u32be(in + 252);
}

static int ima_event_name_check(uint16_t kind, const uint8_t *name, size_t len)
{
    const uint8_t *exp;
    size_t exp_len;

    if (kind == SPP_DIAG_TRACE_IMA_KIND_READY) {
        exp = k_ima_event_ready;
        exp_len = sizeof k_ima_event_ready;
    } else if (kind == SPP_DIAG_TRACE_IMA_KIND_RELEASED) {
        exp = k_ima_event_release;
        exp_len = sizeof k_ima_event_release;
    } else {
        exp = k_ima_event_terminal;
        exp_len = sizeof k_ima_event_terminal;
    }
    if (len != exp_len || !eq_n(name, exp, exp_len)) {
        return WIRE_EVENT;
    }
    return WIRE_OK;
}

int spp_diag_trace_header_encode(const struct spp_diag_trace_header *in,
                                 uint8_t *out, size_t cap, size_t *written,
                                 size_t *required)
{
    int err;

    if (in == NULL || out == NULL || written == NULL || required == NULL) {
        if (written != NULL) {
            *written = 0;
        }
        if (required != NULL) {
            *required = 0;
        }
        return WIRE_NULL;
    }
    err = header_fields(in);
    if (err != WIRE_OK) {
        return fail_encode(err, written, required);
    }
    if (cap < SPP_DIAG_TRACE_HEADER_SIZE) {
        *written = 0;
        *required = SPP_DIAG_TRACE_HEADER_SIZE;
        return WIRE_BUFFER_TOO_SMALL;
    }
    header_to_wire(in, out);
    *written = SPP_DIAG_TRACE_HEADER_SIZE;
    *required = SPP_DIAG_TRACE_HEADER_SIZE;
    return WIRE_OK;
}

int spp_diag_trace_header_decode(const uint8_t *in, size_t len,
                                 struct spp_diag_trace_header *out,
                                 size_t *consumed)
{
    struct spp_diag_trace_header tmp;
    int err;

    if (in == NULL || out == NULL || consumed == NULL) {
        if (consumed != NULL) {
            *consumed = 0;
        }
        return WIRE_NULL;
    }
    if (len != SPP_DIAG_TRACE_HEADER_SIZE) {
        *consumed = 0;
        return WIRE_LENGTH;
    }
    header_from_wire(in, &tmp);
    err = header_fields(&tmp);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    *out = tmp;
    *consumed = SPP_DIAG_TRACE_HEADER_SIZE;
    return WIRE_OK;
}

int spp_diag_trace_header_preimage(const struct spp_diag_trace_header *in,
                                   uint8_t *out, size_t cap, size_t *written,
                                   size_t *required)
{
    int err;

    if (in == NULL || out == NULL || written == NULL || required == NULL) {
        if (written != NULL) {
            *written = 0;
        }
        if (required != NULL) {
            *required = 0;
        }
        return WIRE_NULL;
    }
    err = header_fields(in);
    if (err != WIRE_OK) {
        return fail_encode(err, written, required);
    }
    if (cap < SPP_DIAG_TRACE_PREIMAGE_SIZE) {
        *written = 0;
        *required = SPP_DIAG_TRACE_PREIMAGE_SIZE;
        return WIRE_BUFFER_TOO_SMALL;
    }
    copy_n(out, k_preimage_domain, 28);
    store_u32be(out + 28, SPP_DIAG_TRACE_HEADER_SIZE);
    header_to_wire(in, out + 32);
    *written = SPP_DIAG_TRACE_PREIMAGE_SIZE;
    *required = SPP_DIAG_TRACE_PREIMAGE_SIZE;
    return WIRE_OK;
}

int spp_diag_trace_command_encode(const struct spp_diag_trace_command *in,
                                  uint8_t *out, size_t cap, size_t *written,
                                  size_t *required)
{
    int err;

    if (in == NULL || out == NULL || written == NULL || required == NULL) {
        if (written != NULL) {
            *written = 0;
        }
        if (required != NULL) {
            *required = 0;
        }
        return WIRE_NULL;
    }
    err = command_fields(in);
    if (err != WIRE_OK) {
        return fail_encode(err, written, required);
    }
    if (cap < SPP_DIAG_TRACE_COMMAND_SIZE) {
        *written = 0;
        *required = SPP_DIAG_TRACE_COMMAND_SIZE;
        return WIRE_BUFFER_TOO_SMALL;
    }
    command_to_wire(in, out);
    *written = SPP_DIAG_TRACE_COMMAND_SIZE;
    *required = SPP_DIAG_TRACE_COMMAND_SIZE;
    return WIRE_OK;
}

int spp_diag_trace_command_decode(const uint8_t *in, size_t len,
                                  struct spp_diag_trace_command *out,
                                  size_t *consumed)
{
    struct spp_diag_trace_command tmp;
    int err;

    if (in == NULL || out == NULL || consumed == NULL) {
        if (consumed != NULL) {
            *consumed = 0;
        }
        return WIRE_NULL;
    }
    if (len != SPP_DIAG_TRACE_COMMAND_SIZE) {
        *consumed = 0;
        return WIRE_LENGTH;
    }
    command_from_wire(in, &tmp);
    err = command_fields(&tmp);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    *out = tmp;
    *consumed = SPP_DIAG_TRACE_COMMAND_SIZE;
    return WIRE_OK;
}

int spp_diag_trace_ima_encode(const struct spp_diag_trace_ima *in, uint8_t *out,
                              size_t cap, size_t *written, size_t *required)
{
    int err;

    if (in == NULL || out == NULL || written == NULL || required == NULL) {
        if (written != NULL) {
            *written = 0;
        }
        if (required != NULL) {
            *required = 0;
        }
        return WIRE_NULL;
    }
    err = ima_fields(in);
    if (err != WIRE_OK) {
        return fail_encode(err, written, required);
    }
    if (cap < SPP_DIAG_TRACE_IMA_SIZE) {
        *written = 0;
        *required = SPP_DIAG_TRACE_IMA_SIZE;
        return WIRE_BUFFER_TOO_SMALL;
    }
    ima_to_wire(in, out);
    *written = SPP_DIAG_TRACE_IMA_SIZE;
    *required = SPP_DIAG_TRACE_IMA_SIZE;
    return WIRE_OK;
}

int spp_diag_trace_ima_decode(const uint8_t *in, size_t len,
                              struct spp_diag_trace_ima *out, size_t *consumed)
{
    struct spp_diag_trace_ima tmp;
    int err;

    if (in == NULL || out == NULL || consumed == NULL) {
        if (consumed != NULL) {
            *consumed = 0;
        }
        return WIRE_NULL;
    }
    if (len != SPP_DIAG_TRACE_IMA_SIZE) {
        *consumed = 0;
        return WIRE_LENGTH;
    }
    ima_from_wire(in, &tmp);
    err = ima_fields(&tmp);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    *out = tmp;
    *consumed = SPP_DIAG_TRACE_IMA_SIZE;
    return WIRE_OK;
}

int spp_diag_trace_ima_validate(const struct spp_diag_trace_ima *record,
                                const uint8_t *event_name,
                                size_t event_name_len)
{
    int err;

    if (record == NULL || event_name == NULL) {
        return WIRE_NULL;
    }
    err = ima_fields(record);
    if (err != WIRE_OK) {
        return err;
    }
    return ima_event_name_check(record->kind, event_name, event_name_len);
}
