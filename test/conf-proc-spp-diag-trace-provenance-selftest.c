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

_Static_assert(offsetof(struct spp_diag_trace_header, magic) == 0, "h.magic");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->magic) == 8,
               "h.magic sz");
_Static_assert(offsetof(struct spp_diag_trace_header, wire_version) == 8,
               "h.wire_version");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->wire_version) ==
                   sizeof(uint16_t),
               "h.wire_version sz");
_Static_assert(offsetof(struct spp_diag_trace_header, header_length) == 10,
               "h.header_length");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->header_length) ==
                   sizeof(uint16_t),
               "h.header_length sz");
_Static_assert(offsetof(struct spp_diag_trace_header, policy_version) == 12,
               "h.policy_version");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->policy_version) ==
                   sizeof(uint16_t),
               "h.policy_version sz");
_Static_assert(offsetof(struct spp_diag_trace_header, hash_algorithm) == 14,
               "h.hash_algorithm");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->hash_algorithm) ==
                   sizeof(uint16_t),
               "h.hash_algorithm sz");
_Static_assert(offsetof(struct spp_diag_trace_header, max_frames) == 16,
               "h.max_frames");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->max_frames) ==
                   sizeof(uint32_t),
               "h.max_frames sz");
_Static_assert(offsetof(struct spp_diag_trace_header, max_stream_bytes) == 24,
               "h.max_stream_bytes");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->max_stream_bytes) ==
                   sizeof(uint64_t),
               "h.max_stream_bytes sz");
_Static_assert(offsetof(struct spp_diag_trace_header, max_frame_bytes) == 32,
               "h.max_frame_bytes");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->max_frame_bytes) ==
                   sizeof(uint32_t),
               "h.max_frame_bytes sz");
_Static_assert(offsetof(struct spp_diag_trace_header, source_commit) == 36,
               "h.source_commit");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->source_commit) == 20,
               "h.source_commit sz");
_Static_assert(offsetof(struct spp_diag_trace_header, challenge) == 56,
               "h.challenge");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->challenge) == 32,
               "h.challenge sz");
_Static_assert(offsetof(struct spp_diag_trace_header, run_identity) == 88,
               "h.run_identity");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->run_identity) == 32,
               "h.run_identity sz");
_Static_assert(offsetof(struct spp_diag_trace_header, control_plan_address) ==
                   120,
               "h.control_plan_address");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->control_plan_address) ==
                   32,
               "h.control_plan_address sz");
_Static_assert(offsetof(struct spp_diag_trace_header, command_line_sha256) == 152,
               "h.command_line_sha256");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->command_line_sha256) ==
                   32,
               "h.command_line_sha256 sz");
_Static_assert(offsetof(struct spp_diag_trace_header, required_hook_mask) == 184,
               "h.required_hook_mask");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->required_hook_mask) ==
                   sizeof(uint64_t),
               "h.required_hook_mask sz");
_Static_assert(offsetof(struct spp_diag_trace_header, reserved) == 192,
               "h.reserved");
_Static_assert(sizeof(((struct spp_diag_trace_header *)0)->reserved) ==
                   sizeof(uint32_t),
               "h.reserved sz");

_Static_assert(offsetof(struct spp_diag_trace_command, magic) == 0, "c.magic");
_Static_assert(sizeof(((struct spp_diag_trace_command *)0)->magic) == 8,
               "c.magic sz");
_Static_assert(offsetof(struct spp_diag_trace_command, version) == 8, "c.version");
_Static_assert(sizeof(((struct spp_diag_trace_command *)0)->version) ==
                   sizeof(uint16_t),
               "c.version sz");
_Static_assert(offsetof(struct spp_diag_trace_command, kind) == 10, "c.kind");
_Static_assert(sizeof(((struct spp_diag_trace_command *)0)->kind) ==
                   sizeof(uint16_t),
               "c.kind sz");
_Static_assert(offsetof(struct spp_diag_trace_command, command_length) == 12,
               "c.command_length");
_Static_assert(sizeof(((struct spp_diag_trace_command *)0)->command_length) ==
                   sizeof(uint32_t),
               "c.command_length sz");
_Static_assert(offsetof(struct spp_diag_trace_command, challenge) == 16,
               "c.challenge");
_Static_assert(sizeof(((struct spp_diag_trace_command *)0)->challenge) == 32,
               "c.challenge sz");
_Static_assert(offsetof(struct spp_diag_trace_command, run_identity) == 48,
               "c.run_identity");
_Static_assert(sizeof(((struct spp_diag_trace_command *)0)->run_identity) == 32,
               "c.run_identity sz");
_Static_assert(offsetof(struct spp_diag_trace_command, control_plan_address) == 80,
               "c.control_plan_address");
_Static_assert(sizeof(((struct spp_diag_trace_command *)0)->control_plan_address) ==
                   32,
               "c.control_plan_address sz");
_Static_assert(offsetof(struct spp_diag_trace_command, requested_phase) == 112,
               "c.requested_phase");
_Static_assert(sizeof(((struct spp_diag_trace_command *)0)->requested_phase) ==
                   sizeof(uint16_t),
               "c.requested_phase sz");
_Static_assert(offsetof(struct spp_diag_trace_command, reserved) == 114,
               "c.reserved");
_Static_assert(sizeof(((struct spp_diag_trace_command *)0)->reserved) == 14,
               "c.reserved sz");

_Static_assert(offsetof(struct spp_diag_trace_ima, magic) == 0, "i.magic");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->magic) == 8, "i.magic sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, wire_version) == 8,
               "i.wire_version");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->wire_version) ==
                   sizeof(uint16_t),
               "i.wire_version sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, kind) == 10, "i.kind");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->kind) == sizeof(uint16_t),
               "i.kind sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, record_length) == 12,
               "i.record_length");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->record_length) ==
                   sizeof(uint32_t),
               "i.record_length sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, policy_version) == 16,
               "i.policy_version");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->policy_version) ==
                   sizeof(uint16_t),
               "i.policy_version sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, hash_algorithm) == 18,
               "i.hash_algorithm");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->hash_algorithm) ==
                   sizeof(uint16_t),
               "i.hash_algorithm sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, state) == 20, "i.state");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->state) == sizeof(uint16_t),
               "i.state sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, reserved16) == 22,
               "i.reserved16");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->reserved16) ==
                   sizeof(uint16_t),
               "i.reserved16 sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, source_commit) == 24,
               "i.source_commit");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->source_commit) == 20,
               "i.source_commit sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, challenge) == 44, "i.challenge");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->challenge) == 32,
               "i.challenge sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, run_identity) == 76,
               "i.run_identity");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->run_identity) == 32,
               "i.run_identity sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, control_plan_address) == 108,
               "i.control_plan_address");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->control_plan_address) ==
                   32,
               "i.control_plan_address sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, command_line_sha256) == 140,
               "i.command_line_sha256");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->command_line_sha256) == 32,
               "i.command_line_sha256 sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, frame_count) == 176,
               "i.frame_count");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->frame_count) ==
                   sizeof(uint64_t),
               "i.frame_count sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, stream_byte_count) == 184,
               "i.stream_byte_count");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->stream_byte_count) ==
                   sizeof(uint64_t),
               "i.stream_byte_count sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, chain) == 192, "i.chain");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->chain) == 32, "i.chain sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, required_hook_mask) == 224,
               "i.required_hook_mask");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->required_hook_mask) ==
                   sizeof(uint64_t),
               "i.required_hook_mask sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, denied_exec_count) == 232,
               "i.denied_exec_count");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->denied_exec_count) ==
                   sizeof(uint64_t),
               "i.denied_exec_count sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, committed_exec_count) == 240,
               "i.committed_exec_count");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->committed_exec_count) ==
                   sizeof(uint64_t),
               "i.committed_exec_count sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, loss_count) == 248,
               "i.loss_count");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->loss_count) ==
                   sizeof(uint32_t),
               "i.loss_count sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, overflow_count) == 252,
               "i.overflow_count");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->overflow_count) ==
                   sizeof(uint32_t),
               "i.overflow_count sz");
_Static_assert(offsetof(struct spp_diag_trace_ima, reserved32) == 256,
               "i.reserved32");
_Static_assert(sizeof(((struct spp_diag_trace_ima *)0)->reserved32) ==
                   sizeof(uint32_t),
               "i.reserved32 sz");

_Static_assert(offsetof(struct spp_diag_trace_frame, event_type) == 0,
               "f.event_type");
_Static_assert(sizeof(((struct spp_diag_trace_frame *)0)->event_type) ==
                   sizeof(uint16_t),
               "f.event_type sz");
_Static_assert(offsetof(struct spp_diag_trace_frame, flags) == 2, "f.flags");
_Static_assert(sizeof(((struct spp_diag_trace_frame *)0)->flags) ==
                   sizeof(uint16_t),
               "f.flags sz");
_Static_assert(offsetof(struct spp_diag_trace_frame, payload_length) == 4,
               "f.payload_length");
_Static_assert(sizeof(((struct spp_diag_trace_frame *)0)->payload_length) ==
                   sizeof(uint32_t),
               "f.payload_length sz");
_Static_assert(offsetof(struct spp_diag_trace_frame, sequence) == 8, "f.sequence");
_Static_assert(sizeof(((struct spp_diag_trace_frame *)0)->sequence) ==
                   sizeof(uint64_t),
               "f.sequence sz");
_Static_assert(offsetof(struct spp_diag_trace_frame, task_ordinal) == 16,
               "f.task_ordinal");
_Static_assert(sizeof(((struct spp_diag_trace_frame *)0)->task_ordinal) ==
                   sizeof(uint64_t),
               "f.task_ordinal sz");
_Static_assert(offsetof(struct spp_diag_trace_frame, parent_task_ordinal) == 24,
               "f.parent_task_ordinal");
_Static_assert(sizeof(((struct spp_diag_trace_frame *)0)->parent_task_ordinal) ==
                   sizeof(uint64_t),
               "f.parent_task_ordinal sz");
_Static_assert(offsetof(struct spp_diag_trace_frame, operation_ordinal) == 32,
               "f.operation_ordinal");
_Static_assert(sizeof(((struct spp_diag_trace_frame *)0)->operation_ordinal) ==
                   sizeof(uint64_t),
               "f.operation_ordinal sz");
_Static_assert(offsetof(struct spp_diag_trace_frame, phase) == 40, "f.phase");
_Static_assert(sizeof(((struct spp_diag_trace_frame *)0)->phase) ==
                   sizeof(uint16_t),
               "f.phase sz");
_Static_assert(offsetof(struct spp_diag_trace_frame, reserved) == 42,
               "f.reserved");
_Static_assert(sizeof(((struct spp_diag_trace_frame *)0)->reserved) ==
                   sizeof(uint16_t),
               "f.reserved sz");
_Static_assert(offsetof(struct spp_diag_trace_frame, payload) == 44, "f.payload");
_Static_assert(sizeof(((struct spp_diag_trace_frame *)0)->payload) == 1044,
               "f.payload sz");

_Static_assert(_Generic(&SPP_DIAG_TRACE_SOURCE_COMMIT,
                        const uint8_t (*)[SPP_DIAG_TRACE_SOURCE_COMMIT_LEN]: 1,
                        default: 0),
               "SOURCE_COMMIT type");
_Static_assert(_Generic(&SPP_DIAG_TRACE_IMA_LABEL,
                        const uint8_t (*)[SPP_DIAG_TRACE_IMA_LABEL_LEN]: 1,
                        default: 0),
               "IMA_LABEL type");

static const uint8_t k_frame_domain[27] = {
    's', 'o', 'l', '-', 's', 'p', 'p', '-', 'd', 'i', 'a', 'g', '-', 't',
    'r', 'a', 'c', 'e', '-', 'f', 'r', 'a', 'm', 'e', '/', 'v', '1'};

static const uint8_t k_commit[20] = {
    0x91, 0xa8, 0xe8, 0x26, 0x01, 0x2f, 0xbb, 0x1c, 0x7f, 0x5c,
    0xb2, 0xa3, 0x26, 0xc0, 0x8b, 0x13, 0xe3, 0x90, 0xf4, 0x69};

static const uint8_t k_min_wire[61] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2f};

static const uint8_t k_interior_wire[124] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x40,
    0x00, 0x02, 0x00, 0x3f, 0xff, 0xff, 0xff, 0x9c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
    0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
    0x3d, 0x3e, 0x3f, 0x40};

static const uint8_t k_min_preimage_zero[124] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x3d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x2f};

static const uint8_t k_min_preimage_nz[124] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x00,
    0x00, 0x00, 0x3d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x2f};

static const uint8_t k_max_prefix[60] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static uint8_t k_max_wire[1084];
static struct spp_diag_trace_frame k_min_f;
static struct spp_diag_trace_frame k_interior_f;
static struct spp_diag_trace_frame k_max_f;
static struct spp_diag_trace_frame k_extra_f;

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

static void fill_min_frame(struct spp_diag_trace_frame *f)
{
    memset(f, 0, sizeof *f);
    f->event_type = 0x0100;
    f->payload_length = 17;
    f->task_ordinal = 1;
    f->operation_ordinal = 1;
    f->phase = 1;
    store16(f->payload + 0, 1);
    store16(f->payload + 2, 1);
    store16(f->payload + 4, 1);
    f->payload[16] = 0x2f;
}

static void fill_interior_frame(struct spp_diag_trace_frame *f)
{
    size_t i;

    memset(f, 0, sizeof *f);
    f->event_type = 0x0100;
    f->payload_length = 80;
    f->sequence = UINT64_MAX;
    f->task_ordinal = UINT64_MAX;
    f->operation_ordinal = UINT64_MAX;
    f->phase = 14;
    store16(f->payload + 0, 1);
    store16(f->payload + 2, 64);
    store16(f->payload + 4, 2);
    store16(f->payload + 6, 0x3f);
    store32(f->payload + 8, 0xffffff9c);
    for (i = 0; i < 64; i++) {
        f->payload[16 + i] = (uint8_t)(i + 1);
    }
}

static void fill_max_frame(struct spp_diag_trace_frame *f)
{
    memset(f, 0, sizeof *f);
    f->event_type = 0x0100;
    f->payload_length = 1040;
    f->task_ordinal = 1;
    f->operation_ordinal = 1;
    f->phase = 8;
    store16(f->payload + 0, 1);
    store16(f->payload + 2, 1024);
    store16(f->payload + 4, 4);
    store32(f->payload + 8, 0x80000000u);
    fill_path_bytes(f->payload + 16, 1024);
}

static void fill_extra_frame(struct spp_diag_trace_frame *f)
{
    memset(f, 0, sizeof *f);
    f->event_type = 0x0100;
    f->payload_length = 17;
    f->task_ordinal = 1;
    f->operation_ordinal = 1;
    f->phase = 1;
    store16(f->payload + 0, 1);
    store16(f->payload + 2, 1);
    store16(f->payload + 4, 3);
    store32(f->payload + 8, 3);
    f->payload[16] = 0x61;
}

static void init_vectors(void)
{
    size_t i;

    fill_min_frame(&k_min_f);
    fill_interior_frame(&k_interior_f);
    fill_max_frame(&k_max_f);
    fill_extra_frame(&k_extra_f);
    memcpy(k_max_wire, k_max_prefix, 60);
    for (i = 0; i < 1024; i++) {
        k_max_wire[60 + i] = (uint8_t)((i % 255) + 1);
    }
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
        int result = spp_diag_trace_provenance_frame_encode(
            f, out, sizeof out, &written, &required);
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

    if (later_n > 0) {
        test_asan_unpoison(later, later_n);
    }

    memset(wire, CANARY, sizeof wire);
    layout_frame(wire, f);
    memset(&box, CANARY2, sizeof box);
    snap = box;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(wire, n < 44 ? 44 : n,
                                                     &box.f, &consumed),
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
static void hp_plen16(struct spp_diag_trace_frame *f) { f->payload_length = 16; }
static void hp_task_z(struct spp_diag_trace_frame *f) { f->task_ordinal = 0; }
static void hp_parent_nz(struct spp_diag_trace_frame *f)
{
    f->parent_task_ordinal = 1;
}
static void hp_op_z(struct spp_diag_trace_frame *f) { f->operation_ordinal = 0; }
static void hp_phase0(struct spp_diag_trace_frame *f) { f->phase = 0; }
static void hp_res(struct spp_diag_trace_frame *f) { f->reserved = 1; }
static void pp_action0(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 0, 0);
}
static void pp_path0(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 2, 0);
}
static void pp_access0(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 4, 0);
}
static void pp_mod_unk(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 6, 0x0040);
}
static void pp_pres(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 12, 1);
}
static void pp_pathnul(struct spp_diag_trace_frame *f) { f->payload[16] = 0; }

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

static int roundtrip_one(const struct spp_diag_trace_frame *f, const uint8_t *wire,
                         size_t wire_len)
{
    uint8_t got[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    struct frame_box decoded;
    struct spp_diag_trace_frame expect;
    size_t written, required, consumed;
    size_t i;

    memset(got, CANARY, sizeof got);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(f, got, wire_len, &written,
                                                     &required),
              WIRE_OK);
    EXPECT_EQ(written, wire_len);
    EXPECT_EQ(required, wire_len);
    EXPECT_MEM_EQ(got, wire, wire_len);

    memset(&decoded, CANARY2, sizeof decoded);
    consumed = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(got, wire_len, &decoded.f,
                                                     &consumed),
              WIRE_OK);
    EXPECT_EQ(consumed, wire_len);
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
        EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                      f, chain, buf + 8, n, &written, &required),
                  WIRE_OK);
    } else {
        EXPECT_EQ(spp_diag_trace_provenance_frame_encode(f, buf + 8, n, &written,
                                                         &required),
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
        EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                      f, chain, buf + 8, 0, &written, &required),
                  WIRE_BUFFER_TOO_SMALL);
    } else {
        EXPECT_EQ(spp_diag_trace_provenance_frame_encode(f, buf + 8, 0, &written,
                                                         &required),
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
        EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                      f, chain, buf + 8, n - 1, &written, &required),
                  WIRE_BUFFER_TOO_SMALL);
    } else {
        EXPECT_EQ(spp_diag_trace_provenance_frame_encode(
                      f, buf + 8, n - 1, &written, &required),
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
        EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                      f, chain, buf + 8, n + 1, &written, &required),
                  WIRE_OK);
    } else {
        EXPECT_EQ(spp_diag_trace_provenance_frame_encode(
                      f, buf + 8, n + 1, &written, &required),
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

static int test_compatibility(void)
{
    int (*header_encode)(const struct spp_diag_trace_header *, uint8_t *, size_t,
                         size_t *, size_t *) = spp_diag_trace_header_encode;
    int (*header_decode)(const uint8_t *, size_t, struct spp_diag_trace_header *,
                         size_t *) = spp_diag_trace_header_decode;
    int (*header_preimage)(const struct spp_diag_trace_header *, uint8_t *,
                           size_t, size_t *,
                           size_t *) = spp_diag_trace_header_preimage;
    int (*command_encode)(const struct spp_diag_trace_command *, uint8_t *,
                          size_t, size_t *,
                          size_t *) = spp_diag_trace_command_encode;
    int (*command_decode)(const uint8_t *, size_t,
                          struct spp_diag_trace_command *,
                          size_t *) = spp_diag_trace_command_decode;
    int (*ima_encode)(const struct spp_diag_trace_ima *, uint8_t *, size_t,
                      size_t *, size_t *) = spp_diag_trace_ima_encode;
    int (*ima_decode)(const uint8_t *, size_t, struct spp_diag_trace_ima *,
                      size_t *) = spp_diag_trace_ima_decode;
    int (*ima_validate)(const struct spp_diag_trace_ima *, const uint8_t *,
                        size_t) = spp_diag_trace_ima_validate;
    int (*frame_encode)(const struct spp_diag_trace_frame *, uint8_t *, size_t,
                        size_t *, size_t *) = spp_diag_trace_frame_encode;
    int (*frame_decode)(const uint8_t *, size_t, struct spp_diag_trace_frame *,
                        size_t *) = spp_diag_trace_frame_decode;
    int (*frame_preimage)(const struct spp_diag_trace_frame *,
                          const uint8_t[SPP_DIAG_TRACE_CHAIN_LEN], uint8_t *,
                          size_t, size_t *,
                          size_t *) = spp_diag_trace_frame_preimage;
    int (*stream_validate)(const uint8_t *, size_t,
                           struct spp_diag_trace_stream_summary *,
                           size_t *) = spp_diag_trace_stream_validate;
    int (*prov_encode)(const struct spp_diag_trace_frame *, uint8_t *, size_t,
                       size_t *, size_t *) = spp_diag_trace_provenance_frame_encode;
    int (*prov_decode)(const uint8_t *, size_t, struct spp_diag_trace_frame *,
                       size_t *) = spp_diag_trace_provenance_frame_decode;
    int (*prov_preimage)(const struct spp_diag_trace_frame *,
                         const uint8_t[SPP_DIAG_TRACE_CHAIN_LEN], uint8_t *,
                         size_t, size_t *,
                         size_t *) = spp_diag_trace_provenance_frame_preimage;
    struct spp_diag_trace_frame f;
    uint8_t out[64];
    uint8_t pre[128];
    uint8_t chain[32];
    uint8_t stream[4 + 192 + 4 + 61];
    struct spp_diag_trace_frame got;
    struct spp_diag_trace_stream_summary sum;
    size_t written, required, consumed;

    (void)header_encode;
    (void)header_decode;
    (void)header_preimage;
    (void)command_encode;
    (void)command_decode;
    (void)ima_encode;
    (void)ima_decode;
    (void)ima_validate;
    (void)frame_encode;
    (void)frame_decode;
    (void)frame_preimage;
    (void)stream_validate;
    (void)prov_encode;
    (void)prov_decode;
    (void)prov_preimage;

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
    EXPECT_EQ(SPP_DIAG_TRACE_WIRE_VERSION, 1);
    EXPECT_EQ(SPP_DIAG_TRACE_POLICY_VERSION, 1);
    EXPECT_EQ(SPP_DIAG_TRACE_HOOK_MASK, 0x000f);
    EXPECT_EQ(SPP_DIAG_TRACE_HEADER_SIZE, 192);
    EXPECT_EQ(SPP_DIAG_TRACE_FRAME_HEADER_SIZE, 44);
    EXPECT_EQ(SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES, 1044);
    EXPECT_EQ(SPP_DIAG_TRACE_MAX_FRAME_BYTES, 1088);
    EXPECT_EQ(SPP_DIAG_TRACE_CHAIN_LEN, 32);
    EXPECT_EQ(SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN, 27);
    EXPECT_EQ(SPP_DIAG_TRACE_FRAME_PREIMAGE_MIN_SIZE, 107);
    EXPECT_EQ(SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE, 1151);
    EXPECT_EQ(SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT, 0x0100);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_ACCESS_READ, 1);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_ACCESS_WRITE, 2);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_ACCESS_READ_WRITE, 3);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_ACCESS_PATH_ONLY, 4);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_CREATE, 0x0001);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_TRUNCATE, 0x0002);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_APPEND, 0x0004);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_NOFOLLOW, 0x0008);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_CLOEXEC, 0x0010);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_DIRECTORY, 0x0020);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_MASK, 0x003f);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_PREFIX_SIZE, 16);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_MIN_PAYLOAD, 17);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_MAX_PAYLOAD, 1040);

    fill_min_frame(&f);
    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_encode(&f, out, sizeof out, &written,
                                          &required),
              WIRE_EVENT);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(&got, CANARY2, sizeof got);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_decode(k_min_wire, 61, &got, &consumed),
              WIRE_EVENT);
    EXPECT_EQ(consumed, 0);

    memset(chain, 0, sizeof chain);
    memset(pre, CANARY, sizeof pre);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_frame_preimage(&f, chain, pre, sizeof pre, &written,
                                            &required),
              WIRE_EVENT);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(pre, sizeof pre));

    memset(stream, 0, sizeof stream);
    store32(stream, 192);
    fill_header_body(stream + 4);
    store32(stream + 196, 61);
    memcpy(stream + 200, k_min_wire, 61);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_stream_validate(stream, sizeof stream, &sum,
                                             &consumed),
              WIRE_EVENT);
    EXPECT_EQ(consumed, 0);
    return 0;
}

static int test_constants(void)
{
    EXPECT_EQ(SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT, 0x0100);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_ACCESS_READ, 1);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_ACCESS_WRITE, 2);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_ACCESS_READ_WRITE, 3);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_ACCESS_PATH_ONLY, 4);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_CREATE, 0x0001);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_TRUNCATE, 0x0002);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_APPEND, 0x0004);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_NOFOLLOW, 0x0008);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_CLOEXEC, 0x0010);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_DIRECTORY, 0x0020);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_MOD_MASK, 0x003f);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_PREFIX_SIZE, 16);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_MIN_PAYLOAD, 17);
    EXPECT_EQ(SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_MAX_PAYLOAD, 1040);
    EXPECT_EQ(sizeof k_min_wire, (size_t)61);
    EXPECT_EQ(sizeof k_interior_wire, (size_t)124);
    EXPECT_EQ(sizeof k_max_wire, (size_t)1084);
    EXPECT_EQ(sizeof k_min_preimage_zero, (size_t)124);
    EXPECT_EQ((size_t)27 + 32 + 4 + 1084, (size_t)1147);
    return 0;
}

static int test_literals(void)
{
    uint8_t got[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    uint8_t chain[32];
    size_t written, required;
    size_t i;

    CALL(roundtrip_one(&k_min_f, k_min_wire, 61));
    CALL(roundtrip_one(&k_interior_f, k_interior_wire, 124));

    memset(chain, 0, sizeof chain);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                  &k_min_f, chain, got, sizeof got, &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)124);
    EXPECT_EQ(required, (size_t)124);
    EXPECT_MEM_EQ(got, k_min_preimage_zero, 124);

    fill_path_bytes(chain, 32);
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                  &k_min_f, chain, got, sizeof got, &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)124);
    EXPECT_MEM_EQ(got, k_min_preimage_nz, 124);
    EXPECT_EQ(got[27], 0x01);

    EXPECT_MEM_EQ(k_max_wire, k_max_prefix, 60);
    CALL(roundtrip_one(&k_max_f, k_max_wire, 1084));
    for (i = k_max_f.payload_length; i < SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES; i++) {
        EXPECT_EQ(k_max_f.payload[i], 0);
    }
    return 0;
}

static int test_boundary_twins(void)
{
    struct spp_diag_trace_frame f;
    uint8_t extra_wire[61];

    EXPECT_EQ(k_min_f.sequence, 0);
    EXPECT_EQ(k_interior_f.sequence, UINT64_MAX);
    EXPECT_EQ(k_min_f.task_ordinal, 1);
    EXPECT_EQ(k_interior_f.task_ordinal, UINT64_MAX);
    EXPECT_EQ(k_min_f.operation_ordinal, 1);
    EXPECT_EQ(k_interior_f.operation_ordinal, UINT64_MAX);
    EXPECT_EQ(k_min_f.phase, 1);
    EXPECT_EQ(k_max_f.phase, 8);
    EXPECT_EQ(k_interior_f.phase, 14);

    f = k_min_f;
    f.phase = 0;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));
    f = k_min_f;
    f.phase = 15;
    CALL(api_fail_struct(&f, WIRE_STATE, NULL, 0));

    layout_frame(extra_wire, &k_extra_f);
    CALL(roundtrip_one(&k_extra_f, extra_wire, 61));
    EXPECT_EQ(k_extra_f.payload[16], 0x61);
    return 0;
}

static int decode_expect(const struct spp_diag_trace_frame *f, int expected)
{
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    struct spp_diag_trace_frame got;
    size_t consumed;
    size_t n;

    n = (size_t)44 + f->payload_length;
    layout_frame(wire, f);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(wire, n, &got, &consumed),
              expected);
    EXPECT_EQ(consumed, 0);
    return 0;
}

static int expect_path_nuls(const struct spp_diag_trace_frame *base,
                            uint16_t path_len)
{
    struct spp_diag_trace_frame f;
    size_t positions[3];
    size_t npos;
    size_t i;

    positions[0] = 0;
    npos = 1;
    if (path_len > 1) {
        positions[npos++] = (size_t)path_len / 2;
        positions[npos++] = (size_t)path_len - 1;
    }
    for (i = 0; i < npos; i++) {
        f = *base;
        f.payload[16 + positions[i]] = 0;
        CALL(api_fail_struct(&f, WIRE_VALUE, NULL, 0));
    }
    return 0;
}

static int test_matrix(void)
{
    struct spp_diag_trace_frame f;
    uint8_t extra_wire[61];
    unsigned v;
    static const uint16_t bad_events[] = {0x0001, 0x00ff, 0x0103, 0x01ff, 0x0200,
                                          0xffff};

    CALL(roundtrip_one(&k_min_f, k_min_wire, 61));
    CALL(roundtrip_one(&k_interior_f, k_interior_wire, 124));
    CALL(roundtrip_one(&k_max_f, k_max_wire, 1084));
    layout_frame(extra_wire, &k_extra_f);
    CALL(roundtrip_one(&k_extra_f, extra_wire, 61));

    CALL(expect_path_nuls(&k_min_f, 1));
    CALL(expect_path_nuls(&k_interior_f, 64));
    CALL(expect_path_nuls(&k_max_f, 1024));

    f = k_min_f;
    store16(f.payload + 2, 0);
    CALL(api_fail_struct(&f, WIRE_LENGTH, NULL, 0));
    store16(f.payload + 2, 1025);
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));
    f = k_min_f;
    store16(f.payload + 2, UINT16_MAX);
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));
    f = k_min_f;
    store16(f.payload + 2, 2);
    CALL(api_fail_struct(&f, WIRE_LENGTH, NULL, 0));

    f = k_min_f;
    f.payload_length = UINT32_MAX;
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));

    f = k_min_f;
    store16(f.payload + 6, 0x0040);
    CALL(api_fail_struct(&f, WIRE_FLAGS, NULL, 0));
    f = k_min_f;
    f.reserved = 1;
    CALL(api_fail_struct(&f, WIRE_RESERVED, NULL, 0));
    f = k_min_f;
    store32(f.payload + 12, 1);
    CALL(api_fail_struct(&f, WIRE_RESERVED, NULL, 0));

    for (v = 0; v <= 0xffffu; v++) {
        if (v == 1u) {
            continue;
        }
        f = k_min_f;
        store16(f.payload + 0, (uint16_t)v);
        CALL(decode_expect(&f, WIRE_STATE));
    }
    for (v = 0; v <= 0xffffu; v++) {
        if (v >= 1u && v <= 4u) {
            continue;
        }
        f = k_min_f;
        store16(f.payload + 4, (uint16_t)v);
        CALL(decode_expect(&f, WIRE_STATE));
    }

    for (v = 0; v < sizeof bad_events / sizeof bad_events[0]; v++) {
        f = k_min_f;
        f.event_type = bad_events[v];
        CALL(api_fail_struct(&f, WIRE_EVENT, NULL, 0));
    }
    return 0;
}

static int test_precedence(void)
{
    const struct step steps[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags1, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"plen", hp_plen16, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_z, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_z, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase0, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"hres", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
        {"action", pp_action0, WIRE_STATE, 44, 2, SOFF(payload), 2},
        {"path_len", pp_path0, WIRE_LENGTH, 46, 2, SOFF(payload) + 2, 2},
        {"access", pp_access0, WIRE_STATE, 48, 2, SOFF(payload) + 4, 2},
        {"modifier", pp_mod_unk, WIRE_FLAGS, 50, 2, SOFF(payload) + 6, 2},
        {"pres", pp_pres, WIRE_RESERVED, 56, 4, SOFF(payload) + 12, 4},
        {"path", pp_pathnul, WIRE_VALUE, 60, 1, SOFF(payload) + 16, 1},
    };
    struct spp_diag_trace_frame f;
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 8];
    uint32_t plen;

    CALL(run_pairs(&k_min_f, steps, sizeof steps / sizeof steps[0]));

    memset(wire, CANARY, sizeof wire);
    memcpy(wire, k_min_wire, 44);
    CALL(api_fail_decode_wire(wire, 44, WIRE_LENGTH, wire + 16,
                              sizeof wire - 16u));

    f = k_min_f;
    f.payload_length = 16;
    memset(wire, CANARY, sizeof wire);
    layout_header44(wire, &f);
    CALL(api_fail_decode_wire(wire, 44, WIRE_LENGTH, wire + 16,
                              sizeof wire - 16u));

    for (plen = 1041; plen <= 1044; plen++) {
        f = k_min_f;
        f.payload_length = plen;
        store16(f.payload + 2, (uint16_t)(plen - 16u));
        CALL(api_fail_struct(&f, WIRE_LENGTH, NULL, 0));
    }
    f = k_min_f;
    f.payload_length = 1045;
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));
    f = k_min_f;
    f.payload_length = UINT32_MAX;
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));

    f = k_max_f;
    store16(f.payload + 2, 1025);
    CALL(api_fail_struct(&f, WIRE_CAP, NULL, 0));
    return 0;
}

static int decoder_bounds_one(const uint8_t *wire, size_t wire_len)
{
    size_t len;
    uint8_t buf[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 16];
    struct frame_box box, snap;

    for (len = 1; len < 44; len++) {
        memset(buf, CANARY, sizeof buf);
        memcpy(buf + 8, wire, len);
        test_asan_poison(buf + 8, sizeof buf - 8);
        EXPECT_ASAN_POISONED(buf + 8, 1);
        EXPECT_ASAN_POISONED(buf + sizeof buf - 1, 1);
        memset(&box, CANARY2, sizeof box);
        snap = box;
        {
            size_t consumed = (size_t)-1;
            EXPECT_EQ(spp_diag_trace_provenance_frame_decode(buf + 8, len,
                                                             &box.f, &consumed),
                      WIRE_LENGTH);
            EXPECT_EQ(consumed, 0);
            EXPECT(memcmp(&box, &snap, sizeof box) == 0);
        }
        test_asan_unpoison(buf + 8, sizeof buf - 8);
        EXPECT_EQ(buf[7], CANARY);
    }
    for (len = 44; len < wire_len; len++) {
        memset(buf, CANARY, sizeof buf);
        memcpy(buf + 8, wire, len);
        test_asan_poison(buf + 8 + len, sizeof buf - 8 - len);
        EXPECT_ASAN_POISONED(buf + 8 + len, 1);
        EXPECT_ASAN_POISONED(buf + sizeof buf - 1, 1);
        memset(&box, CANARY2, sizeof box);
        snap = box;
        {
            size_t consumed = (size_t)-1;
            EXPECT_EQ(spp_diag_trace_provenance_frame_decode(buf + 8, len,
                                                             &box.f, &consumed),
                      WIRE_LENGTH);
            EXPECT_EQ(consumed, 0);
            EXPECT(memcmp(&box, &snap, sizeof box) == 0);
        }
        test_asan_unpoison(buf + 8 + len, sizeof buf - 8 - len);
    }
    memset(buf, CANARY, sizeof buf);
    memcpy(buf + 8, wire, wire_len);
    buf[8 + wire_len] = 0x77;
    test_asan_poison(buf + 8 + wire_len, sizeof buf - 8 - wire_len);
    EXPECT_ASAN_POISONED(buf + 8 + wire_len, 1);
    EXPECT_ASAN_POISONED(buf + sizeof buf - 1, 1);
    memset(&box, CANARY2, sizeof box);
    snap = box;
    {
        size_t consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_provenance_frame_decode(buf + 8, wire_len + 1,
                                                         &box.f, &consumed),
                  WIRE_LENGTH);
        EXPECT_EQ(consumed, 0);
        EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    }
    test_asan_unpoison(buf + 8 + wire_len, sizeof buf - 8 - wire_len);
    return 0;
}

static int test_decoder_bounds(void)
{
    _Alignas(8) uint8_t sentinel[8];
    struct frame_box box, snap;

    memset(sentinel, 0x5a, sizeof sentinel);
    test_asan_poison(sentinel, sizeof sentinel);
    EXPECT_ASAN_POISONED(sentinel, 1);
    memset(&box, CANARY2, sizeof box);
    snap = box;
    {
        size_t consumed = (size_t)-1;
        EXPECT_EQ(spp_diag_trace_provenance_frame_decode(sentinel, 0, &box.f,
                                                         &consumed),
                  WIRE_LENGTH);
        EXPECT_EQ(consumed, 0);
        EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    }
    test_asan_unpoison(sentinel, sizeof sentinel);

    CALL(decoder_bounds_one(k_min_wire, 61));
    CALL(decoder_bounds_one(k_interior_wire, 124));
    CALL(decoder_bounds_one(k_max_wire, 1084));
    return 0;
}

static int test_all_or_nothing(void)
{
    uint8_t pre_exp[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    uint8_t zchain[SPP_DIAG_TRACE_CHAIN_LEN];
    struct spp_diag_trace_frame local;
    size_t tail;
    uint8_t extra_wire[61];

    memset(zchain, 0, sizeof zchain);
    layout_frame(extra_wire, &k_extra_f);

    CALL(check_encode_cap(&k_min_f, k_min_wire, 61, 0));
    layout_preimage(pre_exp, &k_min_f, zchain);
    CALL(check_encode_cap(&k_min_f, pre_exp, 124, 1));

    CALL(check_encode_cap(&k_interior_f, k_interior_wire, 124, 0));
    layout_preimage(pre_exp, &k_interior_f, zchain);
    CALL(check_encode_cap(&k_interior_f, pre_exp, 187, 1));

    CALL(check_encode_cap(&k_max_f, k_max_wire, 1084, 0));
    layout_preimage(pre_exp, &k_max_f, zchain);
    CALL(check_encode_cap(&k_max_f, pre_exp, 1147, 1));

    CALL(check_encode_cap(&k_extra_f, extra_wire, 61, 0));

    tail = SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES - k_min_f.payload_length;
    local = k_min_f;
    test_asan_poison(local.payload + local.payload_length, tail);
    EXPECT_ASAN_POISONED(local.payload + local.payload_length, 1);
    EXPECT_ASAN_POISONED(local.payload + 1043, 1);
    {
        uint8_t got[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
        uint8_t pre[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
        size_t written, required;
        written = required = 0;
        EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&local, got, sizeof got,
                                                         &written, &required),
                  WIRE_OK);
        EXPECT_MEM_EQ(got, k_min_wire, 61);
        EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                      &local, zchain, pre, sizeof pre, &written, &required),
                  WIRE_OK);
        EXPECT_MEM_EQ(pre, k_min_preimage_zero, 124);
    }
    test_asan_unpoison(local.payload + local.payload_length, tail);

    tail = SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES - k_max_f.payload_length;
    if (tail > 0) {
        local = k_max_f;
        test_asan_poison(local.payload + local.payload_length, tail);
        EXPECT_ASAN_POISONED(local.payload + local.payload_length, 1);
        EXPECT_ASAN_POISONED(local.payload + 1043, 1);
        {
            uint8_t got[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
            size_t written, required;
            written = required = 0;
            EXPECT_EQ(spp_diag_trace_provenance_frame_encode(
                          &local, got, sizeof got, &written, &required),
                      WIRE_OK);
            EXPECT_MEM_EQ(got, k_max_wire, 1084);
        }
        test_asan_unpoison(local.payload + local.payload_length, tail);
    }
    return 0;
}

static int test_preimage(void)
{
    uint8_t zchain[SPP_DIAG_TRACE_CHAIN_LEN];
    uint8_t nchain[SPP_DIAG_TRACE_CHAIN_LEN];
    uint8_t got[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    uint8_t exp[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    size_t written, required;

    memset(zchain, 0, sizeof zchain);
    fill_path_bytes(nchain, sizeof nchain);

    written = required = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                  &k_min_f, zchain, got, sizeof got, &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)124);
    EXPECT_EQ(required, (size_t)124);
    EXPECT_MEM_EQ(got, k_min_preimage_zero, 124);
    EXPECT_MEM_EQ(got, k_frame_domain, 27);
    EXPECT_MEM_EQ(got + 27, zchain, 32);
    EXPECT_EQ(got[59], 0x00);
    EXPECT_EQ(got[60], 0x00);
    EXPECT_EQ(got[61], 0x00);
    EXPECT_EQ(got[62], 0x3d);
    EXPECT_MEM_EQ(got + 63, k_min_wire, 61);

    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                  &k_min_f, nchain, got, sizeof got, &written, &required),
              WIRE_OK);
    EXPECT_MEM_EQ(got, k_min_preimage_nz, 124);
    EXPECT_MEM_EQ(got + 27, nchain, 32);
    EXPECT_EQ(got[27], nchain[0]);
    EXPECT(got[27] != 0);

    layout_preimage(exp, &k_max_f, zchain);
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                  &k_max_f, zchain, got, sizeof got, &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)1147);
    EXPECT_EQ(required, (size_t)1147);
    EXPECT_MEM_EQ(got, exp, 1147);
    EXPECT_MEM_EQ(got, k_frame_domain, 27);
    EXPECT_MEM_EQ(got + 27, zchain, 32);
    EXPECT_EQ(got[59], 0x00);
    EXPECT_EQ(got[60], 0x00);
    EXPECT_EQ(got[61], 0x04);
    EXPECT_EQ(got[62], 0x3c);
    EXPECT_MEM_EQ(got + 63, k_max_wire, 1084);
    return 0;
}

static int test_nulls(void)
{
    struct spp_diag_trace_frame f = k_min_f;
    uint8_t out[64];
    uint8_t chain[32];
    size_t written, required, consumed;
    struct frame_box box, snap;

    memset(chain, 0x22, sizeof chain);
    f.event_type = 0;

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(NULL, out, 44, &written,
                                                     &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, NULL, 44, &written,
                                                     &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);

    memset(out, CANARY, sizeof out);
    required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, out, 44, NULL, &required),
              WIRE_NULL);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, out, 44, &written, NULL),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(NULL, chain, out, 64,
                                                       &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, NULL, out, 64,
                                                       &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, NULL, 64,
                                                       &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);

    memset(out, CANARY, sizeof out);
    required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, out, 64, NULL,
                                                       &required),
              WIRE_NULL);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, out, 64,
                                                       &written, NULL),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    CALL(expect_canary(out, sizeof out));

    memset(&box, CANARY2, sizeof box);
    snap = box;
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(NULL, 0, &box.f, &consumed),
              WIRE_NULL);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(out, 0, NULL, &consumed),
              WIRE_NULL);
    EXPECT_EQ(consumed, 0);
    memset(&box, CANARY2, sizeof box);
    snap = box;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(out, 0, &box.f, NULL),
              WIRE_NULL);
    EXPECT(memcmp(&box, &snap, sizeof box) == 0);
    return 0;
}

int main(void)
{
    init_vectors();
    if (test_compatibility() != 0) {
        return 1;
    }
    if (test_constants() != 0) {
        return 1;
    }
    if (test_literals() != 0) {
        return 1;
    }
    if (test_boundary_twins() != 0) {
        return 1;
    }
    if (test_matrix() != 0) {
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
