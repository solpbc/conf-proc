/* SPDX-License-Identifier: AGPL-3.0-only */
/* Thin raw-output caller for the independently authored Python field oracle. */

#include "../conf_proc_spp_diag_trace.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

static void print_hex(const uint8_t *bytes, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    for (index = 0; index < len; ++index) {
        putchar(digits[bytes[index] >> 4]);
        putchar(digits[bytes[index] & 0x0fu]);
    }
}

static int parse_u64(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;

    if (text == NULL || text[0] == '\0')
        return 0;
    value = strtoull(text, &end, 0);
    if (end == text || *end != '\0')
        return 0;
    *out = (uint64_t)value;
    return 1;
}

static int classify_one(uint16_t event, uint16_t flags, uint64_t task,
                        uint64_t parent, uint64_t operation, uint16_t phase,
                        const uint8_t *payload, size_t payload_length)
{
    struct spp_diag_trace_frame object;
    uint8_t encoded[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
    size_t written = 0;
    size_t required = 0;
    int result;

    memset(&object, 0, sizeof(object));
    object.event_type = event;
    object.flags = flags;
    object.payload_length = (uint32_t)payload_length;
    object.sequence = 0;
    object.task_ordinal = task;
    object.parent_task_ordinal = parent;
    object.operation_ordinal = operation;
    object.phase = phase;
    object.reserved = 0;
    if (payload_length)
        memcpy(object.payload, payload, payload_length);

    if (event >= SPP_DIAG_TRACE_EVENT_CORE_INIT &&
        event <= SPP_DIAG_TRACE_EVENT_TERMINAL) {
        result = spp_diag_trace_frame_encode(&object, encoded, sizeof(encoded),
                                             &written, &required);
    } else {
        result = spp_diag_trace_provenance_frame_encode(
            &object, encoded, sizeof(encoded), &written, &required);
    }

    printf("%d", result);
    if (result == WIRE_OK) {
        putchar('\t');
        print_hex(encoded, written);
    }
    putchar('\n');
    return 0;
}

static int classify_tokens(char **tok, int ntok)
{
    uint64_t event = 0;
    uint64_t flags = 0;
    uint64_t task = 0;
    uint64_t parent = 0;
    uint64_t operation = 0;
    uint64_t phase = 0;
    uint8_t payload[SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES];
    size_t payload_length = 0;
    const char *hex;

    if (ntok != 7)
        return 2;
    if (!parse_u64(tok[0], &event) || !parse_u64(tok[1], &flags) ||
        !parse_u64(tok[2], &task) || !parse_u64(tok[3], &parent) ||
        !parse_u64(tok[4], &operation) || !parse_u64(tok[5], &phase))
        return 2;
    if (event > 0xffffu || flags > 0xffffu || phase > 0xffffu)
        return 2;
    hex = tok[6];
    if (strcmp(hex, "-") != 0) {
        size_t text_len = strlen(hex);

        if (text_len % 2u != 0)
            return 2;
        payload_length = text_len / 2u;
        if (payload_length > SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES)
            return 2;
        if (!parse_hex(hex, payload, payload_length))
            return 2;
    }
    return classify_one((uint16_t)event, (uint16_t)flags, task, parent,
                        operation, (uint16_t)phase, payload, payload_length);
}

static int split_line(char *line, char **tok, int max_tok)
{
    int n = 0;
    char *cursor = line;

    while (*cursor == ' ' || *cursor == '\t')
        cursor++;
    while (*cursor != '\0' && n < max_tok) {
        tok[n++] = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' &&
               *cursor != '\n' && *cursor != '\r')
            cursor++;
        if (*cursor == '\0')
            break;
        *cursor = '\0';
        cursor++;
        while (*cursor == ' ' || *cursor == '\t')
            cursor++;
        if (*cursor == '\n' || *cursor == '\r')
            break;
    }
    return n;
}

static int classify_line(char *line)
{
    char *tok[8];
    int ntok = split_line(line, tok, 8);

    if (ntok == 8 && strcmp(tok[0], "classify") == 0)
        return classify_tokens(tok + 1, 7);
    return classify_tokens(tok, ntok);
}

int main(int argc, char **argv)
{
    char line[8192];

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 9 && strcmp(argv[1], "classify") == 0)
        return classify_tokens(argv + 2, 7);
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "batch") == 0)) {
        while (fgets(line, sizeof(line), stdin) != NULL) {
            if (classify_line(line) != 0)
                return 2;
        }
        return 0;
    }
    fputs("usage: field-classifier classify EVENT FLAGS TASK PARENT OP PHASE PAYLOADHEX\n"
          "       field-classifier batch  < lines of those 7 fields\n",
          stderr);
    return 2;
}
