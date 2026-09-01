/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

#ifndef CONF_PROC_SPP_DIAG_TRACE_H
#define CONF_PROC_SPP_DIAG_TRACE_H

#include <stddef.h>
#include <stdint.h>

enum spp_diag_trace_result {
    WIRE_OK = 0,
    WIRE_NULL = 1,
    WIRE_BUFFER_TOO_SMALL = 2,
    WIRE_MAGIC = 3,
    WIRE_VERSION = 4,
    WIRE_LENGTH = 5,
    WIRE_VALUE = 6,
    WIRE_RESERVED = 7,
    WIRE_CAP = 8,
    WIRE_ARITHMETIC = 9,
    WIRE_EVENT = 10,
    WIRE_FLAGS = 11,
    WIRE_STATE = 12,
    WIRE_SEQUENCE = 13
};

#define SPP_DIAG_TRACE_HEADER_SIZE 192
#define SPP_DIAG_TRACE_PREIMAGE_SIZE 224
#define SPP_DIAG_TRACE_COMMAND_SIZE 128
#define SPP_DIAG_TRACE_IMA_SIZE 256
#define SPP_DIAG_TRACE_IMA_LABEL_LEN 18
#define SPP_DIAG_TRACE_SOURCE_COMMIT_LEN 20

#define SPP_DIAG_TRACE_WIRE_VERSION 1u
#define SPP_DIAG_TRACE_POLICY_VERSION 1u
#define SPP_DIAG_TRACE_HASH_SHA256 1u
#define SPP_DIAG_TRACE_MAX_FRAMES 524288u
#define SPP_DIAG_TRACE_MAX_STREAM_BYTES 268435456ull
#define SPP_DIAG_TRACE_MAX_FRAME_BYTES 1088u
#define SPP_DIAG_TRACE_HOOK_MASK 0xfull
#define SPP_DIAG_TRACE_IMA_FRAME_COUNT_MIN 1ull
#define SPP_DIAG_TRACE_IMA_STREAM_BYTES_MIN 244ull

#define SPP_DIAG_TRACE_CMD_ADVANCE_PHASE 1u
#define SPP_DIAG_TRACE_CMD_SEAL 2u
#define SPP_DIAG_TRACE_CMD_ADVANCE_PHASE_MIN 2u
#define SPP_DIAG_TRACE_CMD_ADVANCE_PHASE_MAX 14u
#define SPP_DIAG_TRACE_CMD_SEAL_PHASE 15u

#define SPP_DIAG_TRACE_IMA_KIND_READY 1u
#define SPP_DIAG_TRACE_IMA_KIND_RELEASED 2u
#define SPP_DIAG_TRACE_IMA_KIND_SEALED 3u
#define SPP_DIAG_TRACE_IMA_STATE_LIST_READY 1u
#define SPP_DIAG_TRACE_IMA_STATE_LIST_RELEASED 2u
#define SPP_DIAG_TRACE_IMA_STATE_LIST_SEALED 3u

_Static_assert(SPP_DIAG_TRACE_HEADER_SIZE == 192, "header wire size");
_Static_assert(SPP_DIAG_TRACE_PREIMAGE_SIZE == 224, "preimage size");
_Static_assert(SPP_DIAG_TRACE_COMMAND_SIZE == 128, "command wire size");
_Static_assert(SPP_DIAG_TRACE_IMA_SIZE == 256, "IMA wire size");
_Static_assert(SPP_DIAG_TRACE_IMA_LABEL_LEN == 18, "IMA label length");
_Static_assert(SPP_DIAG_TRACE_SOURCE_COMMIT_LEN == 20, "source-commit length");

/*
 * Structural byte codec only: WIRE_OK does not establish transcript order,
 * cross-object identity, IMA/PCR extension, attestation, or qualification.
 *
 * Every API requires its input, output/result, and metadata ranges to be
 * non-overlapping. Overlap is caller error with undefined behavior; this
 * portable reference does not attempt pointer-range detection.
 */

extern const uint8_t SPP_DIAG_TRACE_SOURCE_COMMIT[SPP_DIAG_TRACE_SOURCE_COMMIT_LEN];
extern const uint8_t SPP_DIAG_TRACE_IMA_LABEL[SPP_DIAG_TRACE_IMA_LABEL_LEN];

struct spp_diag_trace_header {
    uint8_t magic[8];
    uint16_t wire_version;
    uint16_t header_length;
    uint16_t policy_version;
    uint16_t hash_algorithm;
    uint32_t max_frames;
    uint64_t max_stream_bytes;
    uint32_t max_frame_bytes;
    uint8_t source_commit[SPP_DIAG_TRACE_SOURCE_COMMIT_LEN];
    uint8_t challenge[32];
    uint8_t run_identity[32];
    uint8_t control_plan_address[32];
    uint8_t command_line_sha256[32];
    uint64_t required_hook_mask;
    uint32_t reserved;
};

struct spp_diag_trace_command {
    uint8_t magic[8];
    uint16_t version;
    uint16_t kind;
    uint32_t command_length;
    uint8_t challenge[32];
    uint8_t run_identity[32];
    uint8_t control_plan_address[32];
    uint16_t requested_phase;
    uint8_t reserved[14];
};

struct spp_diag_trace_ima {
    uint8_t magic[8];
    uint16_t wire_version;
    uint16_t kind;
    uint32_t record_length;
    uint16_t policy_version;
    uint16_t hash_algorithm;
    uint16_t state;
    uint16_t reserved16;
    uint8_t source_commit[SPP_DIAG_TRACE_SOURCE_COMMIT_LEN];
    uint8_t challenge[32];
    uint8_t run_identity[32];
    uint8_t control_plan_address[32];
    uint8_t command_line_sha256[32];
    uint64_t frame_count;
    uint64_t stream_byte_count;
    uint8_t chain[32];
    uint64_t required_hook_mask;
    uint64_t denied_exec_count;
    uint64_t committed_exec_count;
    uint32_t loss_count;
    uint32_t overflow_count;
    uint32_t reserved32;
};

int spp_diag_trace_header_encode(const struct spp_diag_trace_header *in,
                                 uint8_t *out, size_t cap, size_t *written,
                                 size_t *required);
int spp_diag_trace_header_decode(const uint8_t *in, size_t len,
                                 struct spp_diag_trace_header *out,
                                 size_t *consumed);
int spp_diag_trace_header_preimage(const struct spp_diag_trace_header *in,
                                   uint8_t *out, size_t cap, size_t *written,
                                   size_t *required);

int spp_diag_trace_command_encode(const struct spp_diag_trace_command *in,
                                  uint8_t *out, size_t cap, size_t *written,
                                  size_t *required);
int spp_diag_trace_command_decode(const uint8_t *in, size_t len,
                                  struct spp_diag_trace_command *out,
                                  size_t *consumed);

int spp_diag_trace_ima_encode(const struct spp_diag_trace_ima *in, uint8_t *out,
                              size_t cap, size_t *written, size_t *required);
int spp_diag_trace_ima_decode(const uint8_t *in, size_t len,
                              struct spp_diag_trace_ima *out, size_t *consumed);
int spp_diag_trace_ima_validate(const struct spp_diag_trace_ima *record,
                                const uint8_t *event_name,
                                size_t event_name_len);

#endif
