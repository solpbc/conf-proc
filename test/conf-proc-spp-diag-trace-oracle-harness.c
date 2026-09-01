/* SPDX-License-Identifier: AGPL-3.0-only */
/* Thin raw-output caller for the independently authored Python oracle. */

#include "../conf_proc_spp_diag_trace.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int nibble(char value, uint8_t *out)
{
    if (value >= '0' && value <= '9') {
        *out = (uint8_t)(value - '0');
        return 1;
    }
    if (value >= 'a' && value <= 'f') {
        *out = (uint8_t)(value - 'a' + 10);
        return 1;
    }
    if (value >= 'A' && value <= 'F') {
        *out = (uint8_t)(value - 'A' + 10);
        return 1;
    }
    return 0;
}

static int parse_hex(const char *text, uint8_t *out, size_t len)
{
    size_t index;

    if (strlen(text) != len * 2u)
        return 0;
    for (index = 0; index < len; ++index) {
        uint8_t high;
        uint8_t low;

        if (!nibble(text[index * 2u], &high) ||
            !nibble(text[index * 2u + 1u], &low))
            return 0;
        out[index] = (uint8_t)((high << 4) | low);
    }
    return 1;
}

static int parse_frame_hex(const char *text, uint8_t *out, size_t *len)
{
    size_t text_len = strlen(text);

    if (text_len % 2u != 0 || text_len / 2u > SPP_DIAG_TRACE_MAX_FRAME_BYTES)
        return 0;
    *len = text_len / 2u;
    return parse_hex(text, out, *len);
}

static int parse_stream_hex(const char *text, uint8_t *out, size_t cap,
                            size_t *len)
{
    size_t text_len = strlen(text);

    if (text_len % 2u != 0 || text_len / 2u > cap)
        return 0;
    *len = text_len / 2u;
    return parse_hex(text, out, *len);
}

static void print_hex(const uint8_t *bytes, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    for (index = 0; index < len; ++index) {
        putchar(digits[bytes[index] >> 4]);
        putchar(digits[bytes[index] & 0x0fu]);
    }
}

static int print_encode(int result, size_t written, size_t required,
                        const uint8_t *bytes)
{
    printf("%d\t%zu\t%zu\t", result, written, required);
    if (result == WIRE_OK)
        print_hex(bytes, written);
    putchar('\n');
    return 0;
}

static int header_encode(const char *text)
{
    struct spp_diag_trace_header object;
    uint8_t raw[SPP_DIAG_TRACE_HEADER_SIZE];
    uint8_t encoded[SPP_DIAG_TRACE_HEADER_SIZE];
    size_t consumed = 0;
    size_t written = 0;
    size_t required = 0;
    int result;

    if (!parse_hex(text, raw, sizeof(raw)))
        return 2;
    result = spp_diag_trace_header_decode(raw, sizeof(raw), &object, &consumed);
    if (result != WIRE_OK)
        return print_encode(result, 0, 0, encoded);
    result = spp_diag_trace_header_encode(&object, encoded, sizeof(encoded),
                                          &written, &required);
    return print_encode(result, written, required, encoded);
}

static int header_decode(const char *text)
{
    struct spp_diag_trace_header object;
    uint8_t raw[SPP_DIAG_TRACE_HEADER_SIZE];
    size_t consumed = 0;
    int result;

    if (!parse_hex(text, raw, sizeof(raw)))
        return 2;
    result = spp_diag_trace_header_decode(raw, sizeof(raw), &object, &consumed);
    printf("%d\t%zu", result, consumed);
    if (result == WIRE_OK) {
        putchar('\t');
        print_hex(object.challenge, sizeof(object.challenge));
        putchar('\t');
        print_hex(object.run_identity, sizeof(object.run_identity));
        putchar('\t');
        print_hex(object.control_plan_address,
                  sizeof(object.control_plan_address));
        putchar('\t');
        print_hex(object.command_line_sha256,
                  sizeof(object.command_line_sha256));
    }
    putchar('\n');
    return 0;
}

static int header_preimage(const char *text)
{
    struct spp_diag_trace_header object;
    uint8_t raw[SPP_DIAG_TRACE_HEADER_SIZE];
    uint8_t encoded[SPP_DIAG_TRACE_PREIMAGE_SIZE];
    size_t consumed = 0;
    size_t written = 0;
    size_t required = 0;
    int result;

    if (!parse_hex(text, raw, sizeof(raw)))
        return 2;
    result = spp_diag_trace_header_decode(raw, sizeof(raw), &object, &consumed);
    if (result != WIRE_OK)
        return print_encode(result, 0, 0, encoded);
    result = spp_diag_trace_header_preimage(&object, encoded, sizeof(encoded),
                                            &written, &required);
    return print_encode(result, written, required, encoded);
}

static int command_encode(const char *text)
{
    struct spp_diag_trace_command object;
    uint8_t raw[SPP_DIAG_TRACE_COMMAND_SIZE];
    uint8_t encoded[SPP_DIAG_TRACE_COMMAND_SIZE];
    size_t consumed = 0;
    size_t written = 0;
    size_t required = 0;
    int result;

    if (!parse_hex(text, raw, sizeof(raw)))
        return 2;
    result = spp_diag_trace_command_decode(raw, sizeof(raw), &object, &consumed);
    if (result != WIRE_OK)
        return print_encode(result, 0, 0, encoded);
    result = spp_diag_trace_command_encode(&object, encoded, sizeof(encoded),
                                           &written, &required);
    return print_encode(result, written, required, encoded);
}

static int command_decode(const char *text)
{
    struct spp_diag_trace_command object;
    uint8_t raw[SPP_DIAG_TRACE_COMMAND_SIZE];
    size_t consumed = 0;
    int result;

    if (!parse_hex(text, raw, sizeof(raw)))
        return 2;
    result = spp_diag_trace_command_decode(raw, sizeof(raw), &object, &consumed);
    printf("%d\t%zu", result, consumed);
    if (result == WIRE_OK) {
        printf("\t%u\t%u\t", (unsigned)object.kind,
               (unsigned)object.requested_phase);
        print_hex(object.challenge, sizeof(object.challenge));
        putchar('\t');
        print_hex(object.run_identity, sizeof(object.run_identity));
        putchar('\t');
        print_hex(object.control_plan_address,
                  sizeof(object.control_plan_address));
    }
    putchar('\n');
    return 0;
}

static int ima_encode(const char *text)
{
    struct spp_diag_trace_ima object;
    uint8_t raw[SPP_DIAG_TRACE_IMA_SIZE];
    uint8_t encoded[SPP_DIAG_TRACE_IMA_SIZE];
    size_t consumed = 0;
    size_t written = 0;
    size_t required = 0;
    int result;

    if (!parse_hex(text, raw, sizeof(raw)))
        return 2;
    result = spp_diag_trace_ima_decode(raw, sizeof(raw), &object, &consumed);
    if (result != WIRE_OK)
        return print_encode(result, 0, 0, encoded);
    result = spp_diag_trace_ima_encode(&object, encoded, sizeof(encoded),
                                       &written, &required);
    return print_encode(result, written, required, encoded);
}

static int ima_decode(const char *text)
{
    struct spp_diag_trace_ima object;
    uint8_t raw[SPP_DIAG_TRACE_IMA_SIZE];
    size_t consumed = 0;
    int result;

    if (!parse_hex(text, raw, sizeof(raw)))
        return 2;
    result = spp_diag_trace_ima_decode(raw, sizeof(raw), &object, &consumed);
    printf("%d\t%zu", result, consumed);
    if (result == WIRE_OK) {
        printf("\t%u\t%u\t", (unsigned)object.kind, (unsigned)object.state);
        print_hex(object.challenge, sizeof(object.challenge));
        putchar('\t');
        print_hex(object.run_identity, sizeof(object.run_identity));
        putchar('\t');
        print_hex(object.control_plan_address,
                  sizeof(object.control_plan_address));
        putchar('\t');
        print_hex(object.command_line_sha256,
                  sizeof(object.command_line_sha256));
        printf("\t%" PRIu64 "\t%" PRIu64 "\t", object.frame_count,
               object.stream_byte_count);
        print_hex(object.chain, sizeof(object.chain));
        printf("\t%" PRIu64 "\t%" PRIu64, object.denied_exec_count,
               object.committed_exec_count);
    }
    putchar('\n');
    return 0;
}

static int ima_vocabulary(const char *record_text, const char *event_text)
{
    struct spp_diag_trace_ima object;
    uint8_t raw[SPP_DIAG_TRACE_IMA_SIZE];
    uint8_t event_name[256];
    size_t event_hex_len = strlen(event_text);
    size_t event_len;
    size_t consumed = 0;
    int result;

    if (event_hex_len % 2u != 0 || event_hex_len / 2u > sizeof(event_name))
        return 2;
    event_len = event_hex_len / 2u;
    if (!parse_hex(record_text, raw, sizeof(raw)) ||
        !parse_hex(event_text, event_name, event_len))
        return 2;
    result = spp_diag_trace_ima_decode(raw, sizeof(raw), &object, &consumed);
    if (result == WIRE_OK)
        result = spp_diag_trace_ima_validate(&object, event_name, event_len);
    printf("%d\n", result);
    return 0;
}

static int ima_label(void)
{
    printf("%d\t%u\t", WIRE_OK, (unsigned)SPP_DIAG_TRACE_IMA_LABEL_LEN);
    print_hex(SPP_DIAG_TRACE_IMA_LABEL, SPP_DIAG_TRACE_IMA_LABEL_LEN);
    putchar('\n');
    return 0;
}

static int frame_encode(const char *text)
{
    struct spp_diag_trace_frame object;
    uint8_t raw[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    uint8_t encoded[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    size_t raw_len = 0;
    size_t consumed = 0;
    size_t written = 0;
    size_t required = 0;
    int result;

    if (!parse_frame_hex(text, raw, &raw_len))
        return 2;
    result = spp_diag_trace_frame_decode(raw, raw_len, &object, &consumed);
    if (result != WIRE_OK)
        return print_encode(result, 0, 0, encoded);
    result = spp_diag_trace_frame_encode(&object, encoded, sizeof(encoded),
                                         &written, &required);
    return print_encode(result, written, required, encoded);
}

static int frame_decode(const char *text)
{
    struct spp_diag_trace_frame object;
    uint8_t raw[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    size_t raw_len = 0;
    size_t consumed = 0;
    int result;

    if (!parse_frame_hex(text, raw, &raw_len))
        return 2;
    result = spp_diag_trace_frame_decode(raw, raw_len, &object, &consumed);
    printf("%d\t%zu", result, consumed);
    if (result == WIRE_OK) {
        printf("\t%u\t%u\t%" PRIu32 "\t%" PRIu64 "\t%" PRIu64
               "\t%" PRIu64 "\t%" PRIu64 "\t%u\t",
               (unsigned)object.event_type, (unsigned)object.flags,
               object.payload_length, object.sequence, object.task_ordinal,
               object.parent_task_ordinal, object.operation_ordinal,
               (unsigned)object.phase);
        print_hex(object.payload, object.payload_length);
    }
    putchar('\n');
    return 0;
}

static int frame_preimage(const char *frame_text, const char *chain_text)
{
    struct spp_diag_trace_frame object;
    uint8_t raw[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    uint8_t chain[SPP_DIAG_TRACE_CHAIN_LEN];
    uint8_t encoded[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    size_t raw_len = 0;
    size_t consumed = 0;
    size_t written = 0;
    size_t required = 0;
    int result;

    if (!parse_frame_hex(frame_text, raw, &raw_len) ||
        !parse_hex(chain_text, chain, sizeof(chain)))
        return 2;
    result = spp_diag_trace_frame_decode(raw, raw_len, &object, &consumed);
    if (result != WIRE_OK)
        return print_encode(result, 0, 0, encoded);
    result = spp_diag_trace_frame_preimage(&object, chain, encoded,
                                           sizeof(encoded), &written,
                                           &required);
    return print_encode(result, written, required, encoded);
}

static uint16_t load_be16(const uint8_t *bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1]);
}

static uint32_t load_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static uint64_t load_be64(const uint8_t *bytes)
{
    return ((uint64_t)load_be32(bytes) << 32) | load_be32(bytes + 4);
}

static int load_provenance_object(const char *text,
                                  struct spp_diag_trace_frame *object)
{
    uint8_t raw[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    size_t raw_len = 0;
    size_t payload_available;
    size_t payload_copy;

    if (!parse_frame_hex(text, raw, &raw_len) || raw_len < 44u)
        return 0;
    memset(object, 0, sizeof(*object));
    object->event_type = load_be16(raw);
    object->flags = load_be16(raw + 2);
    object->payload_length = load_be32(raw + 4);
    object->sequence = load_be64(raw + 8);
    object->task_ordinal = load_be64(raw + 16);
    object->parent_task_ordinal = load_be64(raw + 24);
    object->operation_ordinal = load_be64(raw + 32);
    object->phase = load_be16(raw + 40);
    object->reserved = load_be16(raw + 42);
    payload_available = raw_len - 44u;
    payload_copy = payload_available < sizeof(object->payload)
                       ? payload_available
                       : sizeof(object->payload);
    memcpy(object->payload, raw + 44, payload_copy);
    return 1;
}

static int parse_capacity(const char *text, size_t maximum, size_t *capacity)
{
    size_t parsed = 0;
    char trailing = '\0';

    if (sscanf(text, "%zu%c", &parsed, &trailing) != 1 || parsed > maximum)
        return 0;
    *capacity = parsed;
    return 1;
}

static int provenance_encode(const char *text, const char *capacity_text)
{
    struct spp_diag_trace_frame object;
    uint8_t encoded[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    uint8_t before[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    size_t capacity = 0;
    size_t written = 777u;
    size_t required = 888u;
    int result;

    if (!load_provenance_object(text, &object) ||
        !parse_capacity(capacity_text, sizeof(encoded), &capacity))
        return 2;
    memset(encoded, 0xa5, sizeof(encoded));
    memcpy(before, encoded, sizeof(before));
    result = spp_diag_trace_provenance_frame_encode(
        &object, encoded, capacity, &written, &required);
    printf("%d\t%zu\t%zu\t%d\t", result, written, required,
           memcmp(encoded, before, sizeof(encoded)) == 0);
    if (result == WIRE_OK)
        print_hex(encoded, written);
    putchar('\n');
    return 0;
}

static int provenance_decode(const char *text)
{
    struct spp_diag_trace_frame object;
    struct spp_diag_trace_frame before;
    uint8_t raw[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    size_t raw_len = 0;
    size_t consumed = 777u;
    int result;

    if (!parse_frame_hex(text, raw, &raw_len))
        return 2;
    memset(&object, 0xa5, sizeof(object));
    memcpy(&before, &object, sizeof(before));
    result = spp_diag_trace_provenance_frame_decode(raw, raw_len, &object,
                                                     &consumed);
    printf("%d\t%zu\t%d", result, consumed,
           memcmp(&object, &before, sizeof(object)) == 0);
    if (result == WIRE_OK) {
        printf("\t%u\t%u\t%" PRIu32 "\t%" PRIu64 "\t%" PRIu64
               "\t%" PRIu64 "\t%" PRIu64 "\t%u\t",
               (unsigned)object.event_type, (unsigned)object.flags,
               object.payload_length, object.sequence, object.task_ordinal,
               object.parent_task_ordinal, object.operation_ordinal,
               (unsigned)object.phase);
        print_hex(object.payload, object.payload_length);
        putchar('\t');
        print_hex(object.payload + object.payload_length,
                  sizeof(object.payload) - object.payload_length);
    }
    putchar('\n');
    return 0;
}

static int provenance_preimage(const char *frame_text, const char *chain_text,
                               const char *capacity_text)
{
    struct spp_diag_trace_frame object;
    uint8_t chain[SPP_DIAG_TRACE_CHAIN_LEN];
    uint8_t encoded[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    uint8_t before[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
    size_t capacity = 0;
    size_t written = 777u;
    size_t required = 888u;
    int result;

    if (!load_provenance_object(frame_text, &object) ||
        !parse_hex(chain_text, chain, sizeof(chain)) ||
        !parse_capacity(capacity_text, sizeof(encoded), &capacity))
        return 2;
    memset(encoded, 0xa5, sizeof(encoded));
    memcpy(before, encoded, sizeof(before));
    result = spp_diag_trace_provenance_frame_preimage(
        &object, chain, encoded, capacity, &written, &required);
    printf("%d\t%zu\t%zu\t%d\t", result, written, required,
           memcmp(encoded, before, sizeof(encoded)) == 0);
    if (result == WIRE_OK)
        print_hex(encoded, written);
    putchar('\n');
    return 0;
}

static int stream_validate(const char *text)
{
    struct spp_diag_trace_stream_summary summary = {
        UINT64_C(0x1122334455667788),
        UINT64_C(0x99aabbccddeeff00),
    };
    uint8_t raw[4096];
    size_t raw_len = 0;
    size_t consumed = 1;
    int result;

    if (!parse_stream_hex(text, raw, sizeof(raw), &raw_len))
        return 2;
    result = spp_diag_trace_stream_validate(raw, raw_len, &summary, &consumed);
    printf("%d\t%zu\t%" PRIu64 "\t%" PRIu64 "\n", result, consumed,
           summary.frame_count, summary.stream_byte_count);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "header-encode") == 0)
        return header_encode(argv[2]);
    if (argc == 3 && strcmp(argv[1], "header-decode") == 0)
        return header_decode(argv[2]);
    if (argc == 3 && strcmp(argv[1], "header-preimage") == 0)
        return header_preimage(argv[2]);
    if (argc == 3 && strcmp(argv[1], "command-encode") == 0)
        return command_encode(argv[2]);
    if (argc == 3 && strcmp(argv[1], "command-decode") == 0)
        return command_decode(argv[2]);
    if (argc == 3 && strcmp(argv[1], "ima-encode") == 0)
        return ima_encode(argv[2]);
    if (argc == 3 && strcmp(argv[1], "ima-decode") == 0)
        return ima_decode(argv[2]);
    if (argc == 4 && strcmp(argv[1], "ima-vocabulary") == 0)
        return ima_vocabulary(argv[2], argv[3]);
    if (argc == 2 && strcmp(argv[1], "ima-label") == 0)
        return ima_label();
    if (argc == 3 && strcmp(argv[1], "frame-encode") == 0)
        return frame_encode(argv[2]);
    if (argc == 3 && strcmp(argv[1], "frame-decode") == 0)
        return frame_decode(argv[2]);
    if (argc == 4 && strcmp(argv[1], "frame-preimage") == 0)
        return frame_preimage(argv[2], argv[3]);
    if (argc == 4 && strcmp(argv[1], "provenance-encode") == 0)
        return provenance_encode(argv[2], argv[3]);
    if (argc == 3 && strcmp(argv[1], "provenance-decode") == 0)
        return provenance_decode(argv[2]);
    if (argc == 5 && strcmp(argv[1], "provenance-preimage") == 0)
        return provenance_preimage(argv[2], argv[3], argv[4]);
    if (argc == 3 && strcmp(argv[1], "stream-validate") == 0)
        return stream_validate(argv[2]);
    fputs("usage: trace-oracle-harness OP [HEX ...]\n", stderr);
    return 2;
}
