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
#define SPP_DIAG_TRACE_FRAME_HEADER_SIZE 44
#define SPP_DIAG_TRACE_STREAM_PREFIX_SIZE 4
#define SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE 196
#define SPP_DIAG_TRACE_MAX_PATH_BYTES 1024
#define SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES 1044
#define SPP_DIAG_TRACE_CHAIN_LEN 32
#define SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN 27
#define SPP_DIAG_TRACE_FRAME_PREIMAGE_MIN_SIZE 107
#define SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE 1151
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

#define SPP_DIAG_TRACE_EVENT_CORE_INIT 1u
#define SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED 2u
#define SPP_DIAG_TRACE_EVENT_IMA_READY 3u
#define SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE 4u
#define SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT 5u
#define SPP_DIAG_TRACE_EVENT_EXEC_COMMIT 6u
#define SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT 7u
#define SPP_DIAG_TRACE_EVENT_TASK_CREATED 8u
#define SPP_DIAG_TRACE_EVENT_PHASE_MARKER 9u
#define SPP_DIAG_TRACE_EVENT_TERMINAL 10u

#define SPP_DIAG_TRACE_PHASE_PRE_RELEASE 0u
#define SPP_DIAG_TRACE_PHASE_INIT 1u
#define SPP_DIAG_TRACE_PHASE_COLD_START 2u
#define SPP_DIAG_TRACE_PHASE_SYNTHETIC_INFERENCE 3u
#define SPP_DIAG_TRACE_PHASE_POISON_IMPORT 4u
#define SPP_DIAG_TRACE_PHASE_POISON_MODULE 5u
#define SPP_DIAG_TRACE_PHASE_POISON_LIBRARY 6u
#define SPP_DIAG_TRACE_PHASE_REMOTE_PACKAGE 7u
#define SPP_DIAG_TRACE_PHASE_REMOTE_MODEL 8u
#define SPP_DIAG_TRACE_PHASE_REMOTE_PLUGIN 9u
#define SPP_DIAG_TRACE_PHASE_WRITABLE_EXEC 10u
#define SPP_DIAG_TRACE_PHASE_ATTACHED_DISK_EXEC 11u
#define SPP_DIAG_TRACE_PHASE_REMOTE_CODE 12u
#define SPP_DIAG_TRACE_PHASE_JIT_CACHE 13u
#define SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE 14u
#define SPP_DIAG_TRACE_PHASE_SEALED 15u

#define SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT 0x0100u
#define SPP_DIAG_TRACE_FILE_ACCESS_READ 1u
#define SPP_DIAG_TRACE_FILE_ACCESS_WRITE 2u
#define SPP_DIAG_TRACE_FILE_ACCESS_READ_WRITE 3u
#define SPP_DIAG_TRACE_FILE_ACCESS_PATH_ONLY 4u
#define SPP_DIAG_TRACE_FILE_MOD_CREATE 0x0001u
#define SPP_DIAG_TRACE_FILE_MOD_TRUNCATE 0x0002u
#define SPP_DIAG_TRACE_FILE_MOD_APPEND 0x0004u
#define SPP_DIAG_TRACE_FILE_MOD_NOFOLLOW 0x0008u
#define SPP_DIAG_TRACE_FILE_MOD_CLOEXEC 0x0010u
#define SPP_DIAG_TRACE_FILE_MOD_DIRECTORY 0x0020u
#define SPP_DIAG_TRACE_FILE_MOD_MASK 0x003fu
#define SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_PREFIX_SIZE 16u
#define SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_MIN_PAYLOAD 17u
#define SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_MAX_PAYLOAD 1040u
#define SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION 0x0101u
#define SPP_DIAG_TRACE_POLICY_ALLOW 1u
#define SPP_DIAG_TRACE_POLICY_DENY 2u
#define SPP_DIAG_TRACE_FILE_OBJECT_REGULAR 1u
#define SPP_DIAG_TRACE_FILE_OBJECT_DIRECTORY 2u
#define SPP_DIAG_TRACE_FILE_OBJECT_MEMFD 3u
#define SPP_DIAG_TRACE_FILE_OBJECT_OTHER 4u
#define SPP_DIAG_TRACE_FILE_POLICY_DECISION_PAYLOAD_SIZE 48u
#define SPP_DIAG_TRACE_PROVENANCE_EVENT_EXEC_MAPPING_POLICY_DECISION 0x0102u
#define SPP_DIAG_TRACE_MAPPING_OPERATION_MMAP 1u
#define SPP_DIAG_TRACE_MAPPING_OPERATION_MPROTECT 2u
#define SPP_DIAG_TRACE_MAPPING_BACKING_ANONYMOUS 1u
#define SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR 2u
#define SPP_DIAG_TRACE_MAPPING_BACKING_MEMFD 3u
#define SPP_DIAG_TRACE_MAPPING_BACKING_OTHER 4u
#define SPP_DIAG_TRACE_MAPPING_MODE_SHARED 1u
#define SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE 2u
#define SPP_DIAG_TRACE_MAPPING_PROT_READ 0x00000001u
#define SPP_DIAG_TRACE_MAPPING_PROT_WRITE 0x00000002u
#define SPP_DIAG_TRACE_MAPPING_PROT_EXEC 0x00000004u
#define SPP_DIAG_TRACE_MAPPING_PROT_MASK 0x00000007u
#define SPP_DIAG_TRACE_EXEC_MAPPING_POLICY_DECISION_PAYLOAD_SIZE 64u

_Static_assert(SPP_DIAG_TRACE_HEADER_SIZE == 192, "header wire size");
_Static_assert(SPP_DIAG_TRACE_PREIMAGE_SIZE == 224, "preimage size");
_Static_assert(SPP_DIAG_TRACE_COMMAND_SIZE == 128, "command wire size");
_Static_assert(SPP_DIAG_TRACE_IMA_SIZE == 256, "IMA wire size");
_Static_assert(SPP_DIAG_TRACE_IMA_LABEL_LEN == 18, "IMA label length");
_Static_assert(SPP_DIAG_TRACE_SOURCE_COMMIT_LEN == 20, "source-commit length");
_Static_assert(SPP_DIAG_TRACE_FRAME_HEADER_SIZE == 44, "frame header size");
_Static_assert(SPP_DIAG_TRACE_MAX_PATH_BYTES == 1024, "max path bytes");
_Static_assert(SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES == 1044, "max payload bytes");
_Static_assert(SPP_DIAG_TRACE_FRAME_HEADER_SIZE + SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES ==
                   SPP_DIAG_TRACE_MAX_FRAME_BYTES,
               "max frame bytes");
_Static_assert(SPP_DIAG_TRACE_CHAIN_LEN == 32, "chain length");
_Static_assert(SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN == 27,
               "frame preimage domain length");
_Static_assert(SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN + SPP_DIAG_TRACE_CHAIN_LEN +
                       4 + SPP_DIAG_TRACE_FRAME_HEADER_SIZE ==
                   SPP_DIAG_TRACE_FRAME_PREIMAGE_MIN_SIZE,
               "min frame preimage size");
_Static_assert(SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN + SPP_DIAG_TRACE_CHAIN_LEN +
                       4 + SPP_DIAG_TRACE_MAX_FRAME_BYTES ==
                   SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE,
               "max frame preimage size");
_Static_assert(SPP_DIAG_TRACE_FILE_POLICY_DECISION_PAYLOAD_SIZE == 48,
               "file-policy-decision payload size");
_Static_assert(SPP_DIAG_TRACE_FRAME_HEADER_SIZE +
                   SPP_DIAG_TRACE_FILE_POLICY_DECISION_PAYLOAD_SIZE == 92,
               "file-policy-decision frame size");
_Static_assert(SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN + SPP_DIAG_TRACE_CHAIN_LEN +
                       4 + 92 == 155,
               "file-policy-decision preimage size");
_Static_assert(SPP_DIAG_TRACE_EXEC_MAPPING_POLICY_DECISION_PAYLOAD_SIZE == 64,
               "exec-mapping-policy-decision payload size");
_Static_assert(SPP_DIAG_TRACE_FRAME_HEADER_SIZE +
                   SPP_DIAG_TRACE_EXEC_MAPPING_POLICY_DECISION_PAYLOAD_SIZE == 108,
               "exec-mapping-policy-decision frame size");
_Static_assert(SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN + SPP_DIAG_TRACE_CHAIN_LEN +
                       4 + 108 == 171,
               "exec-mapping-policy-decision preimage size");
_Static_assert(SPP_DIAG_TRACE_STREAM_PREFIX_SIZE == 4, "stream prefix size");
_Static_assert(SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE == 196,
               "stream header entry size");
_Static_assert(SPP_DIAG_TRACE_STREAM_PREFIX_SIZE + SPP_DIAG_TRACE_HEADER_SIZE ==
                   SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE,
               "header entry is prefix plus header");
_Static_assert((unsigned long long)SPP_DIAG_TRACE_STREAM_PREFIX_SIZE +
                       SPP_DIAG_TRACE_MAX_FRAME_BYTES <=
                   SPP_DIAG_TRACE_MAX_STREAM_BYTES,
               "max frame entry fits in max stream");

/*
 * Structural byte codec only: WIRE_OK does not establish transcript order,
 * cross-object identity, IMA/PCR extension, attestation, or qualification.
 *
 * Every API requires its input, output/result, previous-chain, and metadata
 * ranges to be non-overlapping. Overlap is caller error with undefined
 * behavior; this portable reference does not attempt pointer-range detection.
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

struct spp_diag_trace_frame {
    uint16_t event_type;
    uint16_t flags;
    uint32_t payload_length;
    uint64_t sequence;
    uint64_t task_ordinal;
    uint64_t parent_task_ordinal;
    uint64_t operation_ordinal;
    uint16_t phase;
    uint16_t reserved;
    uint8_t payload[SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES];
};

int spp_diag_trace_frame_encode(const struct spp_diag_trace_frame *in,
                                uint8_t *out, size_t cap, size_t *written,
                                size_t *required);
int spp_diag_trace_frame_decode(const uint8_t *in, size_t len,
                                struct spp_diag_trace_frame *out,
                                size_t *consumed);
int spp_diag_trace_frame_preimage(const struct spp_diag_trace_frame *in,
                                  const uint8_t previous_chain[SPP_DIAG_TRACE_CHAIN_LEN],
                                  uint8_t *out, size_t cap, size_t *written,
                                  size_t *required);

/*
 * Structural provenance-frame codec only: WIRE_OK means one standalone
 * frame for a supported provenance event is locally well formed.
 * It does not establish that an attempt or decision occurred, kernel
 * authorship, stream membership, IMA, attestation, or qualification.
 *
 * Every API requires its input, output/result, previous-chain, and metadata
 * ranges to be non-overlapping. Overlap is caller error with undefined
 * behavior; this portable reference does not attempt pointer-range detection.
 */
int spp_diag_trace_provenance_frame_encode(
    const struct spp_diag_trace_frame *in,
    uint8_t *out, size_t cap, size_t *written, size_t *required);
int spp_diag_trace_provenance_frame_decode(
    const uint8_t *in, size_t len,
    struct spp_diag_trace_frame *out, size_t *consumed);
int spp_diag_trace_provenance_frame_preimage(
    const struct spp_diag_trace_frame *in,
    const uint8_t previous_chain[SPP_DIAG_TRACE_CHAIN_LEN],
    uint8_t *out, size_t cap, size_t *written, size_t *required);

struct spp_diag_trace_stream_summary {
    uint64_t frame_count;
    uint64_t stream_byte_count;
};

/*
 * Structural stream walk only: WIRE_OK means the length-prefixed header
 * and frames decoded, the sequence field increased by one from zero, and
 * the count/byte caps held. It does not establish transcript order,
 * previous-chain linkage, IMA/PCR extension, attestation, or
 * qualification.
 *
 * Input, summary, and consumed ranges must be non-overlapping. Overlap is
 * caller error with undefined behavior; this portable reference does not
 * attempt pointer-range detection.
 */
int spp_diag_trace_stream_validate(const uint8_t *in, size_t len,
                                   struct spp_diag_trace_stream_summary *out,
                                   size_t *consumed);

#endif
