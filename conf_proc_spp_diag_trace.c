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

static const uint8_t k_frame_preimage_domain[27] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g', '-', 't',
    'r', 'a', 'c', 'e', '-', 'f', 'r', 'a', 'm', 'e', '/', 'v', '1'};

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

static int frame_event_check(uint16_t event)
{
    if (event < SPP_DIAG_TRACE_EVENT_CORE_INIT ||
        event > SPP_DIAG_TRACE_EVENT_TERMINAL) {
        return WIRE_EVENT;
    }
    return WIRE_OK;
}

static int frame_flags_check(uint16_t event, uint16_t flags)
{
    if (event == SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT) {
        if ((flags & ~1u) != 0) {
            return WIRE_FLAGS;
        }
        return WIRE_OK;
    }
    if (flags != 0) {
        return WIRE_FLAGS;
    }
    return WIRE_OK;
}

static int frame_payload_length_check(uint16_t event, uint32_t n)
{
    if (n > SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES) {
        return WIRE_CAP;
    }
    switch (event) {
    case SPP_DIAG_TRACE_EVENT_CORE_INIT:
    case SPP_DIAG_TRACE_EVENT_TERMINAL:
        return n == 0 ? WIRE_OK : WIRE_LENGTH;
    case SPP_DIAG_TRACE_EVENT_IMA_READY:
    case SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT:
    case SPP_DIAG_TRACE_EVENT_PHASE_MARKER:
        return n == 8 ? WIRE_OK : WIRE_LENGTH;
    case SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE:
    case SPP_DIAG_TRACE_EVENT_EXEC_COMMIT:
    case SPP_DIAG_TRACE_EVENT_TASK_CREATED:
        return n == 16 ? WIRE_OK : WIRE_LENGTH;
    case SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED:
        return (n >= 21 && n <= SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES) ? WIRE_OK
                                                                 : WIRE_LENGTH;
    case SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT:
        return (n >= 17 && n <= 16u + SPP_DIAG_TRACE_MAX_PATH_BYTES) ? WIRE_OK
                                                                    : WIRE_LENGTH;
    default:
        return WIRE_EVENT;
    }
}

static int frame_task_check(uint16_t event, uint64_t task)
{
    switch (event) {
    case SPP_DIAG_TRACE_EVENT_CORE_INIT:
    case SPP_DIAG_TRACE_EVENT_IMA_READY:
    case SPP_DIAG_TRACE_EVENT_TERMINAL:
        return task == 0 ? WIRE_OK : WIRE_VALUE;
    case SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED:
        return WIRE_OK;
    case SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE:
    case SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT:
    case SPP_DIAG_TRACE_EVENT_EXEC_COMMIT:
    case SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT:
    case SPP_DIAG_TRACE_EVENT_TASK_CREATED:
    case SPP_DIAG_TRACE_EVENT_PHASE_MARKER:
        return task != 0 ? WIRE_OK : WIRE_VALUE;
    default:
        return WIRE_EVENT;
    }
}

static int frame_parent_check(uint16_t event, uint64_t task, uint64_t parent)
{
    switch (event) {
    case SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT:
    case SPP_DIAG_TRACE_EVENT_TASK_CREATED:
        if (parent == 0 || parent == task) {
            return WIRE_VALUE;
        }
        return WIRE_OK;
    default:
        return parent == 0 ? WIRE_OK : WIRE_VALUE;
    }
}

static int frame_operation_check(uint16_t event, uint64_t operation)
{
    switch (event) {
    case SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED:
    case SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT:
    case SPP_DIAG_TRACE_EVENT_EXEC_COMMIT:
    case SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT:
    case SPP_DIAG_TRACE_EVENT_TASK_CREATED:
        return operation != 0 ? WIRE_OK : WIRE_VALUE;
    default:
        return operation == 0 ? WIRE_OK : WIRE_VALUE;
    }
}

static int frame_phase_check(uint16_t event, uint16_t flags, uint16_t phase)
{
    switch (event) {
    case SPP_DIAG_TRACE_EVENT_CORE_INIT:
    case SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED:
    case SPP_DIAG_TRACE_EVENT_IMA_READY:
    case SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE:
        return phase == SPP_DIAG_TRACE_PHASE_PRE_RELEASE ? WIRE_OK : WIRE_STATE;
    case SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT:
        if ((flags & 1u) != 0) {
            return phase == SPP_DIAG_TRACE_PHASE_PRE_RELEASE ? WIRE_OK
                                                            : WIRE_STATE;
        }
        return (phase >= SPP_DIAG_TRACE_PHASE_INIT &&
                phase <= SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE)
                   ? WIRE_OK
                   : WIRE_STATE;
    case SPP_DIAG_TRACE_EVENT_EXEC_COMMIT:
    case SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT:
    case SPP_DIAG_TRACE_EVENT_TASK_CREATED:
        return (phase >= SPP_DIAG_TRACE_PHASE_INIT &&
                phase <= SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE)
                   ? WIRE_OK
                   : WIRE_STATE;
    case SPP_DIAG_TRACE_EVENT_PHASE_MARKER:
        return (phase >= SPP_DIAG_TRACE_PHASE_COLD_START &&
                phase <= SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE)
                   ? WIRE_OK
                   : WIRE_STATE;
    case SPP_DIAG_TRACE_EVENT_TERMINAL:
        return phase == SPP_DIAG_TRACE_PHASE_SEALED ? WIRE_OK : WIRE_STATE;
    default:
        return WIRE_EVENT;
    }
}

static int frame_reserved_check(uint16_t reserved)
{
    return reserved == 0 ? WIRE_OK : WIRE_RESERVED;
}

static int frame_header_fields(const struct spp_diag_trace_frame *f)
{
    int err;

    err = frame_event_check(f->event_type);
    if (err != WIRE_OK) {
        return err;
    }
    err = frame_flags_check(f->event_type, f->flags);
    if (err != WIRE_OK) {
        return err;
    }
    err = frame_payload_length_check(f->event_type, f->payload_length);
    if (err != WIRE_OK) {
        return err;
    }
    err = frame_task_check(f->event_type, f->task_ordinal);
    if (err != WIRE_OK) {
        return err;
    }
    err = frame_parent_check(f->event_type, f->task_ordinal, f->parent_task_ordinal);
    if (err != WIRE_OK) {
        return err;
    }
    err = frame_operation_check(f->event_type, f->operation_ordinal);
    if (err != WIRE_OK) {
        return err;
    }
    err = frame_phase_check(f->event_type, f->flags, f->phase);
    if (err != WIRE_OK) {
        return err;
    }
    return frame_reserved_check(f->reserved);
}

static int frame_path_len_check(uint16_t path_len, uint32_t payload_length,
                                uint32_t prefix)
{
    if (path_len == 0) {
        return WIRE_LENGTH;
    }
    if (path_len > SPP_DIAG_TRACE_MAX_PATH_BYTES) {
        return WIRE_CAP;
    }
    if (payload_length != prefix + path_len) {
        return WIRE_LENGTH;
    }
    return WIRE_OK;
}

static int frame_path_content_check(const uint8_t *path, uint16_t path_len)
{
    size_t i;

    for (i = 0; i < path_len; i++) {
        if (path[i] == 0) {
            return WIRE_VALUE;
        }
    }
    return WIRE_OK;
}

static int payload_pre_release_exec_denied(const uint8_t *p, uint32_t n)
{
    uint16_t errno_v;
    uint16_t path_len;
    uint32_t pid;
    uint32_t tgid;
    int err;

    errno_v = load_u16be(p + 0);
    if (errno_v != 13u) {
        return WIRE_VALUE;
    }
    path_len = load_u16be(p + 2);
    err = frame_path_len_check(path_len, n, 20u);
    if (err != WIRE_OK) {
        return err;
    }
    pid = load_u32be(p + 4);
    if (pid == 0) {
        return WIRE_VALUE;
    }
    tgid = load_u32be(p + 8);
    if (tgid == 0) {
        return WIRE_VALUE;
    }
    return frame_path_content_check(p + 20, path_len);
}

static int payload_userspace_release(const uint8_t *p, uint32_t n)
{
    uint32_t pid;
    uint32_t tgid;

    (void)n;
    pid = load_u32be(p + 0);
    if (pid == 0) {
        return WIRE_VALUE;
    }
    tgid = load_u32be(p + 4);
    if (tgid == 0) {
        return WIRE_VALUE;
    }
    return WIRE_OK;
}

static int payload_exec_attempt(const uint8_t *p, uint32_t n)
{
    uint32_t pass_index;
    uint16_t path_len;
    uint16_t reserved;
    uint32_t pid;
    uint32_t tgid;
    int err;

    pass_index = load_u32be(p + 0);
    if (pass_index == 0) {
        return WIRE_VALUE;
    }
    path_len = load_u16be(p + 4);
    err = frame_path_len_check(path_len, n, 16u);
    if (err != WIRE_OK) {
        return err;
    }
    reserved = load_u16be(p + 6);
    if (reserved != 0) {
        return WIRE_RESERVED;
    }
    pid = load_u32be(p + 8);
    if (pid == 0) {
        return WIRE_VALUE;
    }
    tgid = load_u32be(p + 12);
    if (tgid == 0) {
        return WIRE_VALUE;
    }
    return frame_path_content_check(p + 16, path_len);
}

static int payload_exec_commit(const uint8_t *p, uint32_t n)
{
    uint32_t pass_count;
    uint32_t pid;
    uint32_t tgid;
    uint32_t reserved;

    (void)n;
    pass_count = load_u32be(p + 0);
    if (pass_count == 0) {
        return WIRE_VALUE;
    }
    pid = load_u32be(p + 4);
    if (pid == 0) {
        return WIRE_VALUE;
    }
    tgid = load_u32be(p + 8);
    if (tgid == 0) {
        return WIRE_VALUE;
    }
    reserved = load_u32be(p + 12);
    if (reserved != 0) {
        return WIRE_RESERVED;
    }
    return WIRE_OK;
}

static int payload_task_created(const uint8_t *p, uint32_t n)
{
    uint32_t pid;
    uint32_t tgid;

    (void)n;
    pid = load_u32be(p + 0);
    if (pid == 0) {
        return WIRE_VALUE;
    }
    tgid = load_u32be(p + 4);
    if (tgid == 0) {
        return WIRE_VALUE;
    }
    return WIRE_OK;
}

static int payload_phase_marker(const uint8_t *p, uint32_t n, uint16_t frame_phase)
{
    uint16_t prev;
    uint16_t next;
    uint32_t reserved;

    (void)n;
    prev = load_u16be(p + 0);
    if (prev < SPP_DIAG_TRACE_PHASE_INIT || prev > SPP_DIAG_TRACE_PHASE_JIT_CACHE) {
        return WIRE_STATE;
    }
    next = load_u16be(p + 2);
    if (next != (uint16_t)(prev + 1u) || frame_phase != next) {
        return WIRE_STATE;
    }
    reserved = load_u32be(p + 4);
    if (reserved != 0) {
        return WIRE_RESERVED;
    }
    return WIRE_OK;
}

static int frame_payload_check(uint16_t event_type, const uint8_t *payload,
                               uint32_t n, uint16_t frame_phase)
{
    switch (event_type) {
    case SPP_DIAG_TRACE_EVENT_CORE_INIT:
    case SPP_DIAG_TRACE_EVENT_IMA_READY:
    case SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT:
    case SPP_DIAG_TRACE_EVENT_TERMINAL:
        (void)payload;
        (void)n;
        (void)frame_phase;
        return WIRE_OK;
    case SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED:
        return payload_pre_release_exec_denied(payload, n);
    case SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE:
        return payload_userspace_release(payload, n);
    case SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT:
        return payload_exec_attempt(payload, n);
    case SPP_DIAG_TRACE_EVENT_EXEC_COMMIT:
        return payload_exec_commit(payload, n);
    case SPP_DIAG_TRACE_EVENT_TASK_CREATED:
        return payload_task_created(payload, n);
    case SPP_DIAG_TRACE_EVENT_PHASE_MARKER:
        return payload_phase_marker(payload, n, frame_phase);
    default:
        return WIRE_EVENT;
    }
}

static int frame_fields(const struct spp_diag_trace_frame *f)
{
    int err;

    err = frame_header_fields(f);
    if (err != WIRE_OK) {
        return err;
    }
    return frame_payload_check(f->event_type, f->payload, f->payload_length,
                               f->phase);
}

static void frame_to_wire(const struct spp_diag_trace_frame *f, uint8_t *out)
{
    store_u16be(out + 0, f->event_type);
    store_u16be(out + 2, f->flags);
    store_u32be(out + 4, f->payload_length);
    store_u64be(out + 8, f->sequence);
    store_u64be(out + 16, f->task_ordinal);
    store_u64be(out + 24, f->parent_task_ordinal);
    store_u64be(out + 32, f->operation_ordinal);
    store_u16be(out + 40, f->phase);
    store_u16be(out + 42, f->reserved);
    copy_n(out + 44, f->payload, f->payload_length);
}

int spp_diag_trace_frame_encode(const struct spp_diag_trace_frame *in,
                                uint8_t *out, size_t cap, size_t *written,
                                size_t *required)
{
    int err;
    size_t need;

    if (in == NULL || out == NULL || written == NULL || required == NULL) {
        if (written != NULL) {
            *written = 0;
        }
        if (required != NULL) {
            *required = 0;
        }
        return WIRE_NULL;
    }
    err = frame_fields(in);
    if (err != WIRE_OK) {
        return fail_encode(err, written, required);
    }
    need = (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE + (size_t)in->payload_length;
    if (cap < need) {
        *written = 0;
        *required = need;
        return WIRE_BUFFER_TOO_SMALL;
    }
    frame_to_wire(in, out);
    *written = need;
    *required = need;
    return WIRE_OK;
}

int spp_diag_trace_frame_decode(const uint8_t *in, size_t len,
                                struct spp_diag_trace_frame *out,
                                size_t *consumed)
{
    struct spp_diag_trace_frame tmp;
    uint16_t event;
    uint16_t flags;
    uint16_t phase;
    uint16_t reserved;
    uint32_t plen;
    uint64_t sequence;
    uint64_t task;
    uint64_t parent;
    uint64_t operation;
    int err;
    size_t i;

    if (in == NULL || out == NULL || consumed == NULL) {
        if (consumed != NULL) {
            *consumed = 0;
        }
        return WIRE_NULL;
    }
    if (len < SPP_DIAG_TRACE_FRAME_HEADER_SIZE) {
        *consumed = 0;
        return WIRE_LENGTH;
    }
    event = load_u16be(in + 0);
    err = frame_event_check(event);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    flags = load_u16be(in + 2);
    err = frame_flags_check(event, flags);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    plen = load_u32be(in + 4);
    err = frame_payload_length_check(event, plen);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    if (len != (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE + (size_t)plen) {
        *consumed = 0;
        return WIRE_LENGTH;
    }
    sequence = load_u64be(in + 8);
    task = load_u64be(in + 16);
    err = frame_task_check(event, task);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    parent = load_u64be(in + 24);
    err = frame_parent_check(event, task, parent);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    operation = load_u64be(in + 32);
    err = frame_operation_check(event, operation);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    phase = load_u16be(in + 40);
    err = frame_phase_check(event, flags, phase);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    reserved = load_u16be(in + 42);
    err = frame_reserved_check(reserved);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    err = frame_payload_check(event, in + 44, plen, phase);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    tmp.event_type = event;
    tmp.flags = flags;
    tmp.payload_length = plen;
    tmp.sequence = sequence;
    tmp.task_ordinal = task;
    tmp.parent_task_ordinal = parent;
    tmp.operation_ordinal = operation;
    tmp.phase = phase;
    tmp.reserved = reserved;
    copy_n(tmp.payload, in + 44, plen);
    for (i = plen; i < SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES; i++) {
        tmp.payload[i] = 0;
    }
    *out = tmp;
    *consumed = len;
    return WIRE_OK;
}

int spp_diag_trace_frame_preimage(const struct spp_diag_trace_frame *in,
                                  const uint8_t previous_chain[SPP_DIAG_TRACE_CHAIN_LEN],
                                  uint8_t *out, size_t cap, size_t *written,
                                  size_t *required)
{
    int err;
    size_t frame_len;
    size_t need;

    if (in == NULL || previous_chain == NULL || out == NULL || written == NULL ||
        required == NULL) {
        if (written != NULL) {
            *written = 0;
        }
        if (required != NULL) {
            *required = 0;
        }
        return WIRE_NULL;
    }
    err = frame_fields(in);
    if (err != WIRE_OK) {
        return fail_encode(err, written, required);
    }
    frame_len =
        (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE + (size_t)in->payload_length;
    need = (size_t)SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN +
           (size_t)SPP_DIAG_TRACE_CHAIN_LEN + 4u + frame_len;
    if (cap < need) {
        *written = 0;
        *required = need;
        return WIRE_BUFFER_TOO_SMALL;
    }
    copy_n(out, k_frame_preimage_domain, SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN);
    copy_n(out + SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN, previous_chain,
           SPP_DIAG_TRACE_CHAIN_LEN);
    store_u32be(out + SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN +
                    SPP_DIAG_TRACE_CHAIN_LEN,
                (uint32_t)frame_len);
    frame_to_wire(in, out + SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN +
                          SPP_DIAG_TRACE_CHAIN_LEN + 4);
    *written = need;
    *required = need;
    return WIRE_OK;
}

static int provenance_event_check(uint16_t event)
{
    return event == SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT ? WIRE_OK
                                                                     : WIRE_EVENT;
}

static int provenance_flags_check(uint16_t flags)
{
    return flags == 0 ? WIRE_OK : WIRE_FLAGS;
}

static int provenance_payload_length_check(uint32_t n)
{
    if (n > SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES) {
        return WIRE_CAP;
    }
    if (n < SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_MIN_PAYLOAD ||
        n > SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_MAX_PAYLOAD) {
        return WIRE_LENGTH;
    }
    return WIRE_OK;
}

static int provenance_task_check(uint64_t task)
{
    return task != 0 ? WIRE_OK : WIRE_VALUE;
}

static int provenance_parent_check(uint64_t parent)
{
    return parent == 0 ? WIRE_OK : WIRE_VALUE;
}

static int provenance_operation_check(uint64_t operation)
{
    return operation != 0 ? WIRE_OK : WIRE_VALUE;
}

static int provenance_phase_check(uint16_t phase)
{
    return (phase >= SPP_DIAG_TRACE_PHASE_INIT &&
            phase <= SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE)
               ? WIRE_OK
               : WIRE_STATE;
}

static int provenance_header_fields(const struct spp_diag_trace_frame *f)
{
    int err;

    err = provenance_event_check(f->event_type);
    if (err != WIRE_OK) {
        return err;
    }
    err = provenance_flags_check(f->flags);
    if (err != WIRE_OK) {
        return err;
    }
    err = provenance_payload_length_check(f->payload_length);
    if (err != WIRE_OK) {
        return err;
    }
    err = provenance_task_check(f->task_ordinal);
    if (err != WIRE_OK) {
        return err;
    }
    err = provenance_parent_check(f->parent_task_ordinal);
    if (err != WIRE_OK) {
        return err;
    }
    err = provenance_operation_check(f->operation_ordinal);
    if (err != WIRE_OK) {
        return err;
    }
    err = provenance_phase_check(f->phase);
    if (err != WIRE_OK) {
        return err;
    }
    return frame_reserved_check(f->reserved);
}

static int provenance_payload_check(const uint8_t *p, uint32_t n)
{
    uint16_t action;
    uint16_t path_len;
    uint16_t access;
    uint16_t modifier;
    uint32_t dirfd_bits;
    uint32_t reserved;
    int err;

    action = load_u16be(p + 0);
    if (action != 1u) {
        return WIRE_STATE;
    }
    path_len = load_u16be(p + 2);
    err = frame_path_len_check(path_len, n,
                               SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_PREFIX_SIZE);
    if (err != WIRE_OK) {
        return err;
    }
    access = load_u16be(p + 4);
    if (access < SPP_DIAG_TRACE_FILE_ACCESS_READ ||
        access > SPP_DIAG_TRACE_FILE_ACCESS_PATH_ONLY) {
        return WIRE_STATE;
    }
    modifier = load_u16be(p + 6);
    if ((modifier & ~(uint32_t)SPP_DIAG_TRACE_FILE_MOD_MASK) != 0) {
        return WIRE_FLAGS;
    }
    /* dirfd: opaque 32-bit two's-complement bits, every pattern valid, never checked or cast to signed */
    dirfd_bits = load_u32be(p + 8);
    (void)dirfd_bits;
    reserved = load_u32be(p + 12);
    if (reserved != 0) {
        return WIRE_RESERVED;
    }
    return frame_path_content_check(p + 16, path_len);
}

static int provenance_fields(const struct spp_diag_trace_frame *f)
{
    int err;

    err = provenance_header_fields(f);
    if (err != WIRE_OK) {
        return err;
    }
    return provenance_payload_check(f->payload, f->payload_length);
}

int spp_diag_trace_provenance_frame_encode(
    const struct spp_diag_trace_frame *in, uint8_t *out, size_t cap,
    size_t *written, size_t *required)
{
    int err;
    size_t need;

    if (in == NULL || out == NULL || written == NULL || required == NULL) {
        if (written != NULL) {
            *written = 0;
        }
        if (required != NULL) {
            *required = 0;
        }
        return WIRE_NULL;
    }
    err = provenance_fields(in);
    if (err != WIRE_OK) {
        return fail_encode(err, written, required);
    }
    need = (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE + (size_t)in->payload_length;
    if (cap < need) {
        *written = 0;
        *required = need;
        return WIRE_BUFFER_TOO_SMALL;
    }
    frame_to_wire(in, out);
    *written = need;
    *required = need;
    return WIRE_OK;
}

int spp_diag_trace_provenance_frame_decode(const uint8_t *in, size_t len,
                                           struct spp_diag_trace_frame *out,
                                           size_t *consumed)
{
    struct spp_diag_trace_frame tmp;
    uint16_t event;
    uint16_t flags;
    uint16_t phase;
    uint16_t reserved;
    uint32_t plen;
    uint64_t sequence;
    uint64_t task;
    uint64_t parent;
    uint64_t operation;
    int err;
    size_t i;

    if (in == NULL || out == NULL || consumed == NULL) {
        if (consumed != NULL) {
            *consumed = 0;
        }
        return WIRE_NULL;
    }
    if (len < SPP_DIAG_TRACE_FRAME_HEADER_SIZE) {
        *consumed = 0;
        return WIRE_LENGTH;
    }
    event = load_u16be(in + 0);
    err = provenance_event_check(event);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    flags = load_u16be(in + 2);
    err = provenance_flags_check(flags);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    plen = load_u32be(in + 4);
    err = provenance_payload_length_check(plen);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    if (len != (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE + (size_t)plen) {
        *consumed = 0;
        return WIRE_LENGTH;
    }
    sequence = load_u64be(in + 8);
    task = load_u64be(in + 16);
    err = provenance_task_check(task);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    parent = load_u64be(in + 24);
    err = provenance_parent_check(parent);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    operation = load_u64be(in + 32);
    err = provenance_operation_check(operation);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    phase = load_u16be(in + 40);
    err = provenance_phase_check(phase);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    reserved = load_u16be(in + 42);
    err = frame_reserved_check(reserved);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    err = provenance_payload_check(in + 44, plen);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    tmp.event_type = event;
    tmp.flags = flags;
    tmp.payload_length = plen;
    tmp.sequence = sequence;
    tmp.task_ordinal = task;
    tmp.parent_task_ordinal = parent;
    tmp.operation_ordinal = operation;
    tmp.phase = phase;
    tmp.reserved = reserved;
    copy_n(tmp.payload, in + 44, plen);
    for (i = plen; i < SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES; i++) {
        tmp.payload[i] = 0;
    }
    *out = tmp;
    *consumed = len;
    return WIRE_OK;
}

int spp_diag_trace_provenance_frame_preimage(
    const struct spp_diag_trace_frame *in,
    const uint8_t previous_chain[SPP_DIAG_TRACE_CHAIN_LEN], uint8_t *out,
    size_t cap, size_t *written, size_t *required)
{
    int err;
    size_t frame_len;
    size_t need;

    if (in == NULL || previous_chain == NULL || out == NULL || written == NULL ||
        required == NULL) {
        if (written != NULL) {
            *written = 0;
        }
        if (required != NULL) {
            *required = 0;
        }
        return WIRE_NULL;
    }
    err = provenance_fields(in);
    if (err != WIRE_OK) {
        return fail_encode(err, written, required);
    }
    frame_len =
        (size_t)SPP_DIAG_TRACE_FRAME_HEADER_SIZE + (size_t)in->payload_length;
    need = (size_t)SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN +
           (size_t)SPP_DIAG_TRACE_CHAIN_LEN + 4u + frame_len;
    if (cap < need) {
        *written = 0;
        *required = need;
        return WIRE_BUFFER_TOO_SMALL;
    }
    copy_n(out, k_frame_preimage_domain, SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN);
    copy_n(out + SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN, previous_chain,
           SPP_DIAG_TRACE_CHAIN_LEN);
    store_u32be(out + SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN +
                    SPP_DIAG_TRACE_CHAIN_LEN,
                (uint32_t)frame_len);
    frame_to_wire(in, out + SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN +
                          SPP_DIAG_TRACE_CHAIN_LEN + 4);
    *written = need;
    *required = need;
    return WIRE_OK;
}

int spp_diag_trace_stream_validate(const uint8_t *in, size_t len,
                                   struct spp_diag_trace_stream_summary *out,
                                   size_t *consumed)
{
    struct spp_diag_trace_header header_tmp;
    struct spp_diag_trace_frame frame_tmp;
    struct spp_diag_trace_stream_summary summary;
    size_t header_consumed;
    size_t frame_consumed;
    size_t off;
    size_t remaining;
    uint32_t prefix;
    uint32_t frame_length;
    int err;

    if (in == NULL || out == NULL || consumed == NULL) {
        if (consumed != NULL) {
            *consumed = 0;
        }
        return WIRE_NULL;
    }
    if (len > SPP_DIAG_TRACE_MAX_STREAM_BYTES) {
        *consumed = 0;
        return WIRE_CAP;
    }
    if (len < SPP_DIAG_TRACE_STREAM_PREFIX_SIZE) {
        *consumed = 0;
        return WIRE_LENGTH;
    }
    prefix = load_u32be(in);
    if (prefix != SPP_DIAG_TRACE_HEADER_SIZE) {
        *consumed = 0;
        return WIRE_LENGTH;
    }
    if (len < SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE) {
        *consumed = 0;
        return WIRE_LENGTH;
    }
    err = spp_diag_trace_header_decode(in + SPP_DIAG_TRACE_STREAM_PREFIX_SIZE,
                                       SPP_DIAG_TRACE_HEADER_SIZE, &header_tmp,
                                       &header_consumed);
    if (err != WIRE_OK) {
        *consumed = 0;
        return err;
    }
    summary.frame_count = 0;
    summary.stream_byte_count = SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE;
    off = SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE;
    if (len == SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE) {
        *out = summary;
        *consumed = SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE;
        return WIRE_OK;
    }
    for (;;) {
        remaining = len - off;
        if (remaining == 0) {
            *out = summary;
            *consumed = len;
            return WIRE_OK;
        }
        if (remaining < SPP_DIAG_TRACE_STREAM_PREFIX_SIZE) {
            *consumed = 0;
            return WIRE_LENGTH;
        }
        frame_length = load_u32be(in + off);
        if (frame_length < SPP_DIAG_TRACE_FRAME_HEADER_SIZE) {
            *consumed = 0;
            return WIRE_LENGTH;
        }
        if (frame_length > SPP_DIAG_TRACE_MAX_FRAME_BYTES) {
            *consumed = 0;
            return WIRE_CAP;
        }
        if (frame_length > remaining - SPP_DIAG_TRACE_STREAM_PREFIX_SIZE) {
            *consumed = 0;
            return WIRE_LENGTH;
        }
        err = spp_diag_trace_frame_decode(
            in + off + SPP_DIAG_TRACE_STREAM_PREFIX_SIZE, frame_length,
            &frame_tmp, &frame_consumed);
        if (err != WIRE_OK) {
            *consumed = 0;
            return err;
        }
        if (frame_tmp.sequence != summary.frame_count) {
            *consumed = 0;
            return WIRE_SEQUENCE;
        }
        if (summary.frame_count == SPP_DIAG_TRACE_MAX_FRAMES) {
            *consumed = 0;
            return WIRE_CAP;
        }
        summary.frame_count++;
        summary.stream_byte_count +=
            (uint64_t)SPP_DIAG_TRACE_STREAM_PREFIX_SIZE + (uint64_t)frame_length;
        off += SPP_DIAG_TRACE_STREAM_PREFIX_SIZE + (size_t)frame_length;
    }
}
