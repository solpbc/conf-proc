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

_Static_assert(SPP_DIAG_TRACE_OPERATION_RETURN_PAYLOAD_SIZE == 16,
               "payload size");
_Static_assert(SPP_DIAG_TRACE_FRAME_HEADER_SIZE +
                   SPP_DIAG_TRACE_OPERATION_RETURN_PAYLOAD_SIZE == 60,
               "frame size");
_Static_assert(SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_LEN + SPP_DIAG_TRACE_CHAIN_LEN +
                       4 + 60 == 123,
               "preimage size");

static const uint8_t k_literal_a[60] = {
    0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t k_literal_b[60] = {
    0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static const uint8_t k_literal_c[60] = {
    0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

static const uint8_t k_literal_d[60] = {
    0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static const uint8_t k_literal_e[60] = {
    0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t k_preimage_zero_a[123] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x3c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00};

static const uint8_t k_preimage_nz_a[123] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x00,
    0x00, 0x00, 0x3c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00};

static const uint8_t k_preimage_zero_b[123] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x3c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01};

static const uint8_t k_preimage_nz_b[123] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x00,
    0x00, 0x00, 0x3c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01};

static const uint8_t k_preimage_zero_c[123] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x3c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef};

static const uint8_t k_preimage_nz_c[123] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x00,
    0x00, 0x00, 0x3c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef};

static const uint8_t k_preimage_zero_d[123] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x3c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff};

static const uint8_t k_preimage_nz_d[123] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x00,
    0x00, 0x00, 0x3c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff};

static const uint8_t k_preimage_zero_e[123] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x3c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00};

static const uint8_t k_preimage_nz_e[123] = {
    0x73, 0x6f, 0x6c, 0x2d, 0x73, 0x70, 0x70, 0x2d, 0x64, 0x69, 0x61, 0x67,
    0x2d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2d, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x2f, 0x76, 0x31, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x00,
    0x00, 0x00, 0x3c, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00};

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
    f->event_type = SPP_DIAG_TRACE_PROVENANCE_EVENT_OPERATION_RETURN;
    f->payload_length = SPP_DIAG_TRACE_OPERATION_RETURN_PAYLOAD_SIZE;
    f->task_ordinal = 1;
    f->operation_ordinal = 1;
    f->phase = 1;
    store16(f->payload + 0, SPP_DIAG_TRACE_OPERATION_FILE_OPEN);
}

static void fill_distinct_a(struct spp_diag_trace_frame *f)
{
    fill_valid(f);
}

static void fill_distinct_b(struct spp_diag_trace_frame *f)
{
    fill_valid(f);
    store16(f->payload + 0, SPP_DIAG_TRACE_OPERATION_MMAP);
    store64(f->payload + 8, 1);
}

static void fill_distinct_c(struct spp_diag_trace_frame *f)
{
    fill_valid(f);
    store16(f->payload + 0, SPP_DIAG_TRACE_OPERATION_MPROTECT);
    store64(f->payload + 8, UINT64_C(0x0123456789abcdef));
}

static void fill_distinct_d(struct spp_diag_trace_frame *f)
{
    fill_valid(f);
    store16(f->payload + 0, SPP_DIAG_TRACE_OPERATION_CONNECT);
    store64(f->payload + 8, UINT64_C(0x7fffffffffffffff));
}

static void fill_distinct_e(struct spp_diag_trace_frame *f)
{
    fill_valid(f);
    store16(f->payload + 0, SPP_DIAG_TRACE_OPERATION_SENDMSG);
    store64(f->payload + 8, UINT64_C(0x8000000000000000));
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

static void fill_file_policy(struct spp_diag_trace_frame *f)
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

static void fill_exec_mapping(struct spp_diag_trace_frame *f)
{
    memset(f, 0, sizeof *f);
    f->event_type = SPP_DIAG_TRACE_PROVENANCE_EVENT_EXEC_MAPPING_POLICY_DECISION;
    f->payload_length = SPP_DIAG_TRACE_EXEC_MAPPING_POLICY_DECISION_PAYLOAD_SIZE;
    f->task_ordinal = 1;
    f->operation_ordinal = 1;
    f->phase = 1;
    store16(f->payload + 0, SPP_DIAG_TRACE_MAPPING_OPERATION_MMAP);
    store16(f->payload + 2, SPP_DIAG_TRACE_POLICY_ALLOW);
    store16(f->payload + 4, SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR);
    store16(f->payload + 6, SPP_DIAG_TRACE_MAPPING_MODE_SHARED);
    store32(f->payload + 12, SPP_DIAG_TRACE_MAPPING_PROT_EXEC);
    store64(f->payload + 40, 1);
    store64(f->payload + 48, 1);
}

static void fill_network_policy(struct spp_diag_trace_frame *f)
{
    memset(f, 0, sizeof *f);
    f->event_type = SPP_DIAG_TRACE_PROVENANCE_EVENT_NETWORK_POLICY_DECISION;
    f->payload_length = SPP_DIAG_TRACE_NETWORK_POLICY_DECISION_PAYLOAD_SIZE;
    f->task_ordinal = 1;
    f->operation_ordinal = 1;
    f->phase = 1;
    store16(f->payload + 0, SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT);
    store16(f->payload + 2, SPP_DIAG_TRACE_POLICY_ALLOW);
    store16(f->payload + 4, SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4);
    store16(f->payload + 6, SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT);
    store16(f->payload + 8, SPP_DIAG_TRACE_NETWORK_SOCKET_STREAM);
    store16(f->payload + 12, SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET);
    store16(f->payload + 14, 16);
    store64(f->payload + 28, 1);
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
    uint8_t out[60];
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
        int result = spp_diag_trace_provenance_frame_encode(f, out, 59, &written,
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
            f, chain, pre, 122, &written, &required);
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
    uint8_t out[80];
    uint8_t pre[160];
    uint8_t chain[32];
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    struct frame_box got, snap;
    size_t written, required, consumed;
    size_t n;

    n = decode_len_for(f);
    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(f, out, sizeof out,
                                                     &written, &required),
              expected);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(chain, 0x11, sizeof chain);
    memset(pre, CANARY, sizeof pre);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(
                  f, chain, pre, sizeof pre, &written, &required),
              expected);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(pre, sizeof pre));

    layout_frame(wire, f);
    memset(&got, CANARY2, sizeof got);
    snap = got;
    consumed = (size_t)-1;
    EXPECT_EQ(
        spp_diag_trace_provenance_frame_decode(wire, n, &got.f, &consumed),
        expected);
    EXPECT_EQ(consumed, 0);
    EXPECT(memcmp(&got, &snap, sizeof got) == 0);
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

static int expect_ok_or_fail(const struct spp_diag_trace_frame *f, int expected)
{
    if (expected == WIRE_OK) {
        return expect_ok_both_paths(f);
    }
    return cheap_fail_struct(f, expected);
}

static int expect_bytes_swap(const struct spp_diag_trace_frame *base,
                             size_t poff_a, size_t poff_b, size_t width,
                             int swapped_expect)
{
    struct spp_diag_trace_frame orig, swapped;
    uint8_t wo[60], ws[60];
    uint8_t ta[16], tb[16];

    orig = *base;
    swapped = *base;
    memcpy(ta, orig.payload + poff_a, width);
    memcpy(tb, orig.payload + poff_b, width);
    memcpy(swapped.payload + poff_a, tb, width);
    memcpy(swapped.payload + poff_b, ta, width);
    layout_frame(wo, &orig);
    layout_frame(ws, &swapped);
    EXPECT(memcmp(ws, wo, 60) != 0);
    EXPECT_MEM_EQ(ws + 44 + poff_a, wo + 44 + poff_b, width);
    EXPECT_MEM_EQ(ws + 44 + poff_b, wo + 44 + poff_a, width);
    CALL(expect_ok_or_fail(&swapped, swapped_expect));
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
static void hp_plen15(struct spp_diag_trace_frame *f) { f->payload_length = 15; }
static void hp_task_z(struct spp_diag_trace_frame *f) { f->task_ordinal = 0; }
static void hp_parent_nz(struct spp_diag_trace_frame *f)
{
    f->parent_task_ordinal = 1;
}
static void hp_op_z(struct spp_diag_trace_frame *f) { f->operation_ordinal = 0; }
static void hp_phase0(struct spp_diag_trace_frame *f) { f->phase = 0; }
static void hp_res(struct spp_diag_trace_frame *f) { f->reserved = 1; }
static void pp_kind0(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 0, 0);
}
static void pp_r16(struct spp_diag_trace_frame *f)
{
    store16(f->payload + 2, 1);
}
static void pp_r32(struct spp_diag_trace_frame *f)
{
    store32(f->payload + 4, 1);
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

static int fail_onehot16(const struct spp_diag_trace_frame *base, size_t off,
                         int err)
{
    unsigned bit;
    struct spp_diag_trace_frame f;

    for (bit = 0; bit < 16; bit++) {
        f = *base;
        store16(f.payload + off, (uint16_t)(1u << bit));
        CALL(cheap_fail_struct(&f, err));
    }
    return 0;
}

static int fail_onehot32(const struct spp_diag_trace_frame *base, size_t off,
                         int err)
{
    unsigned bit;
    struct spp_diag_trace_frame f;

    for (bit = 0; bit < 32; bit++) {
        f = *base;
        store32(f.payload + off, 1u << bit);
        CALL(cheap_fail_struct(&f, err));
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
    uint8_t frame_wire[60];
    uint8_t stream[4 + 192 + 4 + 60];
    size_t written, required, consumed;
    unsigned v;

    EXPECT_EQ(SPP_DIAG_TRACE_PROVENANCE_EVENT_OPERATION_RETURN, 0x0104);
    EXPECT_EQ(SPP_DIAG_TRACE_OPERATION_FILE_OPEN, 1);
    EXPECT_EQ(SPP_DIAG_TRACE_OPERATION_MMAP, 2);
    EXPECT_EQ(SPP_DIAG_TRACE_OPERATION_MPROTECT, 3);
    EXPECT_EQ(SPP_DIAG_TRACE_OPERATION_CONNECT, 4);
    EXPECT_EQ(SPP_DIAG_TRACE_OPERATION_SENDMSG, 5);
    EXPECT_EQ(SPP_DIAG_TRACE_OPERATION_RETURN_PAYLOAD_SIZE, 16);

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
    EXPECT_EQ(spp_diag_trace_frame_decode(out, 60, &f, &consumed), WIRE_EVENT);
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
    store32(stream + 196, 60);
    memcpy(stream + 200, frame_wire, 60);
    consumed = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_stream_validate(stream, sizeof stream, &sum,
                                             &consumed),
              WIRE_EVENT);
    EXPECT_EQ(consumed, 0);

    fill_valid(&f);
    f.event_type = 0x0106;
    CALL(api_fail_struct(&f, WIRE_EVENT, NULL, 0));

    for (v = 0; v <= 0xffffu; v++) {
        if (v == SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT) {
            fill_open_min(&f);
            CALL(expect_ok_both_paths(&f));
        } else if (v == SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION) {
            fill_file_policy(&f);
            CALL(expect_ok_both_paths(&f));
        } else if (v ==
                   SPP_DIAG_TRACE_PROVENANCE_EVENT_EXEC_MAPPING_POLICY_DECISION) {
            fill_exec_mapping(&f);
            CALL(expect_ok_both_paths(&f));
        } else if (v ==
                   SPP_DIAG_TRACE_PROVENANCE_EVENT_NETWORK_POLICY_DECISION) {
            fill_network_policy(&f);
            CALL(expect_ok_both_paths(&f));
        } else if (v == SPP_DIAG_TRACE_PROVENANCE_EVENT_OPERATION_RETURN) {
            fill_valid(&f);
            CALL(expect_ok_both_paths(&f));
#ifdef SPP_DIAG_TRACE_PROVENANCE_EVENT_TASK_EXIT
        } else if (v == SPP_DIAG_TRACE_PROVENANCE_EVENT_TASK_EXIT) {
            continue;
#endif
        } else {
            fill_valid(&f);
            f.event_type = (uint16_t)v;
            CALL(api_fail_struct(&f, WIRE_EVENT, NULL, 0));
        }
    }
    return 0;
}

static int roundtrip_literal(void (*fill)(struct spp_diag_trace_frame *),
                             const uint8_t *wire, const uint8_t *pre0,
                             const uint8_t *prenz)
{
    struct spp_diag_trace_frame f;
    uint8_t got[60];
    uint8_t pre[123];
    uint8_t chain[32];
    struct frame_box decoded;
    size_t written, required, consumed;
    size_t i;

    fill(&f);
    memset(got, CANARY, sizeof got);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, got, sizeof got,
                                                     &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)60);
    EXPECT_EQ(required, (size_t)60);
    EXPECT_MEM_EQ(got, wire, 60);

    memset(chain, 0, sizeof chain);
    written = required = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, pre, sizeof pre,
                                                       &written, &required),
              WIRE_OK);
    EXPECT_EQ(written, (size_t)123);
    EXPECT_EQ(required, (size_t)123);
    EXPECT_MEM_EQ(pre, pre0, 123);
    EXPECT_MEM_EQ(pre + 63, wire, 60);

    for (i = 0; i < 32; i++) {
        chain[i] = (uint8_t)(i + 1);
    }
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, pre, sizeof pre,
                                                       &written, &required),
              WIRE_OK);
    EXPECT_MEM_EQ(pre, prenz, 123);
    EXPECT_EQ(pre[27], 0x01);

    memset(&decoded, CANARY2, sizeof decoded);
    consumed = 0;
    EXPECT_EQ(spp_diag_trace_provenance_frame_decode(wire, 60, &decoded.f,
                                                     &consumed),
              WIRE_OK);
    EXPECT_EQ(consumed, (size_t)60);
    EXPECT_EQ(decoded.f.event_type, 0x0104);
    EXPECT_EQ(decoded.f.payload_length, 16);
    EXPECT_EQ(decoded.f.task_ordinal, 1);
    EXPECT_EQ(decoded.f.operation_ordinal, 1);
    EXPECT_EQ(decoded.f.phase, 1);
    EXPECT(frame_eq(&decoded.f, &f));
    for (i = 16; i < SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES; i++) {
        EXPECT_EQ(decoded.f.payload[i], 0);
    }
    return 0;
}

static int test_literals(void)
{
    struct spp_diag_trace_frame f;
    unsigned v;

    EXPECT_EQ(sizeof k_literal_a, (size_t)60);
    EXPECT_EQ(sizeof k_literal_b, (size_t)60);
    EXPECT_EQ(sizeof k_literal_c, (size_t)60);
    EXPECT_EQ(sizeof k_literal_d, (size_t)60);
    EXPECT_EQ(sizeof k_literal_e, (size_t)60);
    EXPECT_EQ(sizeof k_preimage_zero_a, (size_t)123);
    EXPECT_EQ(sizeof k_preimage_nz_a, (size_t)123);
    EXPECT_MEM_EQ(k_preimage_zero_a + 63, k_literal_a, 60);
    EXPECT_MEM_EQ(k_preimage_nz_a + 63, k_literal_a, 60);
    EXPECT_MEM_EQ(k_preimage_zero_b + 63, k_literal_b, 60);
    EXPECT_MEM_EQ(k_preimage_nz_b + 63, k_literal_b, 60);
    EXPECT_MEM_EQ(k_preimage_zero_c + 63, k_literal_c, 60);
    EXPECT_MEM_EQ(k_preimage_nz_c + 63, k_literal_c, 60);
    EXPECT_MEM_EQ(k_preimage_zero_d + 63, k_literal_d, 60);
    EXPECT_MEM_EQ(k_preimage_nz_d + 63, k_literal_d, 60);
    EXPECT_MEM_EQ(k_preimage_zero_e + 63, k_literal_e, 60);
    EXPECT_MEM_EQ(k_preimage_nz_e + 63, k_literal_e, 60);

    CALL(roundtrip_literal(fill_distinct_a, k_literal_a, k_preimage_zero_a,
                           k_preimage_nz_a));
    CALL(roundtrip_literal(fill_distinct_b, k_literal_b, k_preimage_zero_b,
                           k_preimage_nz_b));
    CALL(roundtrip_literal(fill_distinct_c, k_literal_c, k_preimage_zero_c,
                           k_preimage_nz_c));
    CALL(roundtrip_literal(fill_distinct_d, k_literal_d, k_preimage_zero_d,
                           k_preimage_nz_d));
    CALL(roundtrip_literal(fill_distinct_e, k_literal_e, k_preimage_zero_e,
                           k_preimage_nz_e));

    fill_distinct_a(&f);
    CALL(expect_bytes_swap(&f, 0, 2, 2, WIRE_STATE));
    fill_distinct_d(&f);
    CALL(expect_bytes_swap(&f, 4, 8, 4, WIRE_RESERVED));
    fill_distinct_c(&f);
    CALL(expect_bytes_swap(&f, 8, 12, 4, WIRE_OK));

    fill_distinct_a(&f);
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
    unsigned kind;
    unsigned ri;
    unsigned v;
    unsigned bit;
    static const uint64_t raws[] = {
        0,
        1,
        UINT64_C(0x0123456789abcdef),
        UINT64_C(0x7fffffffffffffff),
        UINT64_C(0x8000000000000000),
        UINT64_MAX};

    for (kind = 1; kind <= 5; kind++) {
        for (ri = 0; ri < sizeof raws / sizeof raws[0]; ri++) {
            fill_valid(&f);
            store16(f.payload + 0, (uint16_t)kind);
            store64(f.payload + 8, raws[ri]);
            CALL(expect_ok_both_paths(&f));
        }
    }

    for (v = 0; v <= 0xffffu; v++) {
        fill_valid(&f);
        store16(f.payload + 0, (uint16_t)v);
        if (v >= SPP_DIAG_TRACE_OPERATION_FILE_OPEN &&
            v <= SPP_DIAG_TRACE_OPERATION_SENDMSG) {
            CALL(expect_ok_both_paths(&f));
        } else {
            CALL(cheap_fail_struct(&f, WIRE_STATE));
        }
    }

    for (kind = 1; kind <= 5; kind++) {
        fill_valid(&f);
        store16(f.payload + 0, (uint16_t)kind);
        store64(f.payload + 8, 0);
        CALL(expect_ok_both_paths(&f));
        store64(f.payload + 8, UINT64_MAX);
        CALL(expect_ok_both_paths(&f));
        store64(f.payload + 8, UINT64_C(0x5555555555555555));
        CALL(expect_ok_both_paths(&f));
        for (bit = 0; bit < 64; bit++) {
            fill_valid(&f);
            store16(f.payload + 0, (uint16_t)kind);
            store64(f.payload + 8, UINT64_C(1) << bit);
            CALL(expect_ok_both_paths(&f));
            fill_valid(&f);
            store16(f.payload + 0, (uint16_t)kind);
            store64(f.payload + 8, UINT64_MAX ^ (UINT64_C(1) << bit));
            CALL(expect_ok_both_paths(&f));
        }
    }
    return 0;
}

static int expect_nulls(void)
{
    struct spp_diag_trace_frame f;
    uint8_t out[80];
    uint8_t chain[32];
    size_t written, required, consumed;
    struct frame_box box, snap;

    fill_valid(&f);
    memset(chain, 0x22, sizeof chain);

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(NULL, out, 60, &written,
                                                     &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, NULL, 60, &written,
                                                     &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);

    memset(out, CANARY, sizeof out);
    required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, out, 60, NULL, &required),
              WIRE_NULL);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, out, 60, &written, NULL),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(NULL, chain, out, 123,
                                                       &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, NULL, out, 123,
                                                       &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, NULL, 123,
                                                       &written, &required),
              WIRE_NULL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, 0);

    memset(out, CANARY, sizeof out);
    required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, out, 123, NULL,
                                                       &required),
              WIRE_NULL);
    EXPECT_EQ(required, 0);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, out, 123,
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

static int test_bounds(void)
{
    struct spp_diag_trace_frame f;
    const struct step steps[] = {
        {"event", hp_event0, WIRE_EVENT, 0, 2, SOFF(event_type), SL(event_type)},
        {"flags", hp_flags1, WIRE_FLAGS, 2, 2, SOFF(flags), SL(flags)},
        {"cap", hp_plen_cap, WIRE_CAP, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"plen", hp_plen15, WIRE_LENGTH, 4, 4, SOFF(payload_length),
         SL(payload_length)},
        {"task", hp_task_z, WIRE_VALUE, 16, 8, SOFF(task_ordinal),
         SL(task_ordinal)},
        {"parent", hp_parent_nz, WIRE_VALUE, 24, 8, SOFF(parent_task_ordinal),
         SL(parent_task_ordinal)},
        {"op", hp_op_z, WIRE_VALUE, 32, 8, SOFF(operation_ordinal),
         SL(operation_ordinal)},
        {"phase", hp_phase0, WIRE_STATE, 40, 2, SOFF(phase), SL(phase)},
        {"hres", hp_res, WIRE_RESERVED, 42, 2, SOFF(reserved), SL(reserved)},
        {"kind", pp_kind0, WIRE_STATE, 44, 2, SOFF(payload), 2},
        {"r16", pp_r16, WIRE_RESERVED, 46, 2, SOFF(payload) + 2, 2},
        {"r32", pp_r32, WIRE_RESERVED, 48, 4, SOFF(payload) + 4, 4},
    };
    uint8_t wire[SPP_DIAG_TRACE_MAX_FRAME_BYTES + 16];
    uint8_t buf[8 + SPP_DIAG_TRACE_MAX_FRAME_BYTES + 16];
    uint8_t chain[32];
    uint8_t out[200];
    struct frame_box box, snap;
    size_t written, required, consumed;
    size_t len;
    size_t i;
    uint32_t bad_len[] = {0, 15, 17, 1044};
    _Alignas(8) uint8_t sentinel[8];

    fill_valid(&f);
    CALL(run_pairs(&f, steps, sizeof steps / sizeof steps[0]));

    fill_valid(&f);
    store16(f.payload + 2, 1);
    store32(f.payload + 4, 1);
    CALL(api_fail_struct(&f, WIRE_RESERVED, NULL, 0));

    fill_valid(&f);
    CALL(fail_onehot16(&f, 2, WIRE_RESERVED));
    fill_valid(&f);
    CALL(fail_onehot32(&f, 4, WIRE_RESERVED));

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

    fill_valid(&f);
    f.task_ordinal = 0;
    memset(wire, CANARY, sizeof wire);
    layout_frame(wire, &f);
    wire[60] = 0x77;
    CALL(api_fail_decode_wire(wire, 61, WIRE_LENGTH, NULL, 0));

    fill_valid(&f);
    memset(wire, CANARY, sizeof wire);
    layout_frame(wire, &f);
    CALL(api_fail_decode_wire(wire, 61, WIRE_LENGTH, NULL, 0));

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
        memcpy(buf + 8, k_literal_a, len);
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
    for (len = 44; len < 60; len++) {
        memset(buf, CANARY, sizeof buf);
        memcpy(buf + 8, k_literal_a, len);
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
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, out, 0, &written,
                                                     &required),
              WIRE_BUFFER_TOO_SMALL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, (size_t)60);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_encode(&f, out, 59, &written,
                                                     &required),
              WIRE_BUFFER_TOO_SMALL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, (size_t)60);
    CALL(expect_canary(out, sizeof out));

    memset(chain, 0, sizeof chain);
    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, out, 0,
                                                       &written, &required),
              WIRE_BUFFER_TOO_SMALL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, (size_t)123);
    CALL(expect_canary(out, sizeof out));

    memset(out, CANARY, sizeof out);
    written = required = (size_t)-1;
    EXPECT_EQ(spp_diag_trace_provenance_frame_preimage(&f, chain, out, 122,
                                                       &written, &required),
              WIRE_BUFFER_TOO_SMALL);
    EXPECT_EQ(written, 0);
    EXPECT_EQ(required, (size_t)123);
    CALL(expect_canary(out, sizeof out));

    CALL(expect_nulls());

    fill_valid(&f);
    {
        size_t tail = SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES - f.payload_length;
        test_asan_poison(f.payload + f.payload_length, tail);
        EXPECT_ASAN_POISONED(f.payload + f.payload_length, 1);
        EXPECT_ASAN_POISONED(f.payload + 1043, 1);
        {
            uint8_t got[60];
            uint8_t preimg[123];
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
