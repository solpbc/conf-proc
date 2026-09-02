/* SPDX-License-Identifier: GPL-2.0-only */
/* Thin hex CLI for the kernel trace core. Test-harness encoding is not wire. */

#include "core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int nibble(char value, u8 *out)
{
	if (value >= '0' && value <= '9') {
		*out = (u8)(value - '0');
		return 1;
	}
	if (value >= 'a' && value <= 'f') {
		*out = (u8)(value - 'a' + 10);
		return 1;
	}
	if (value >= 'A' && value <= 'F') {
		*out = (u8)(value - 'A' + 10);
		return 1;
	}
	return 0;
}

static int parse_hex(const char *text, u8 *out, size_t len)
{
	size_t i;

	if (strlen(text) != len * 2u)
		return 0;
	for (i = 0; i < len; i++) {
		u8 high, low;

		if (!nibble(text[i * 2u], &high) || !nibble(text[i * 2u + 1u], &low))
			return 0;
		out[i] = (u8)((high << 4) | low);
	}
	return 1;
}

static u16 load_u16be(const u8 *p)
{
	return (u16)(((u16)p[0] << 8) | (u16)p[1]);
}

static u64 load_u64be(const u8 *p)
{
	return ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) |
	       ((u64)p[3] << 32) | ((u64)p[4] << 24) | ((u64)p[5] << 16) |
	       ((u64)p[6] << 8) | (u64)p[7];
}

static void print_hex(const u8 *bytes, size_t len)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		putchar(digits[bytes[i] >> 4]);
		putchar(digits[bytes[i] & 0x0fu]);
	}
}

static void print_snapshot(int result, const struct spp_diag_trace_core_snapshot *snap,
			  const u8 *frames, const size_t *frame_lens, size_t frame_n)
{
	size_t i;

	printf("%d\t%d\t%d\t%d\t%llu\t%llu\t%llu\t", result, snap->failed,
	       snap->reason, snap->initialized,
	       (unsigned long long)snap->frame_count,
	       (unsigned long long)snap->stream_byte_count,
	       (unsigned long long)snap->sequence);
	print_hex(snap->header, SPP_DIAG_TRACE_HEADER_SIZE);
	putchar('\t');
	print_hex(snap->core_init_frame, SPP_DIAG_TRACE_FRAME_HEADER_SIZE);
	putchar('\t');
	print_hex(snap->header_chain, SPP_DIAG_TRACE_CHAIN_LEN);
	putchar('\t');
	print_hex(snap->chain, SPP_DIAG_TRACE_CHAIN_LEN);
	for (i = 0; i < frame_n; i++) {
		putchar('\t');
		print_hex(frames + i * SPP_DIAG_TRACE_MAX_FRAME_BYTES, frame_lens[i]);
	}
	putchar('\n');
}

struct parsed_frame {
	u16 event_type;
	u16 flags;
	u64 task;
	u64 parent;
	u64 operation;
	u16 phase;
	u8 payload[SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES];
	size_t payload_length;
};

static int parse_frame_tuple(const char *text, struct parsed_frame *out)
{
	size_t text_len = strlen(text);
	u8 raw[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
	size_t raw_len;

	if (text_len < 60 || text_len % 2u != 0)
		return 0;
	raw_len = text_len / 2u;
	if (raw_len > 30u + SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES)
		return 0;
	if (!parse_hex(text, raw, raw_len))
		return 0;
	memset(out, 0, sizeof(*out));
	out->event_type = load_u16be(raw);
	out->flags = load_u16be(raw + 2);
	out->task = load_u64be(raw + 4);
	out->parent = load_u64be(raw + 12);
	out->operation = load_u64be(raw + 20);
	out->phase = load_u16be(raw + 28);
	out->payload_length = raw_len - 30u;
	if (out->payload_length)
		memcpy(out->payload, raw + 30, out->payload_length);
	return 1;
}

static int parse_identities(char **argv, u8 challenge[32], u8 run[32], u8 control[32],
			    u8 cmdline[32])
{
	return parse_hex(argv[0], challenge, 32) && parse_hex(argv[1], run, 32) &&
	       parse_hex(argv[2], control, 32) && parse_hex(argv[3], cmdline, 32);
}

static int run_sequence(int mark, int argc, char **argv)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	u8 challenge[32], run[32], control[32], cmdline[32];
	u8 frames[16][SPP_DIAG_TRACE_MAX_FRAME_BYTES];
	size_t frame_lens[16];
	size_t frame_n = 0;
	int result;
	int reason = 0;
	int i;
	int frame_argc_off;

	memset(&core, 0, sizeof(core));
	memset(&snap, 0, sizeof(snap));
	if (!parse_identities(argv, challenge, run, control, cmdline))
		return 2;
	result = spp_diag_trace_core_init(&core, challenge, run, control, cmdline);
	spp_diag_trace_core_snapshot(&core, &snap);
	if (result == WIRE_OK) {
		memcpy(frames[0], snap.core_init_frame,
		       SPP_DIAG_TRACE_FRAME_HEADER_SIZE);
		frame_lens[0] = SPP_DIAG_TRACE_FRAME_HEADER_SIZE;
		frame_n = 1;
	}
	frame_argc_off = 4;
	if (mark) {
		char *end = NULL;

		if (argc < 5)
			return 2;
		reason = (int)strtol(argv[4], &end, 10);
		if (end == argv[4] || *end != '\0')
			return 2;
		if (result == WIRE_OK)
			result = spp_diag_trace_core_mark_failure(&core, reason);
		spp_diag_trace_core_snapshot(&core, &snap);
		frame_argc_off = 5;
	}
	for (i = frame_argc_off; i < argc; i++) {
		struct parsed_frame parsed;

		if (frame_n >= 16)
			return 2;
		if (!parse_frame_tuple(argv[i], &parsed))
			return 2;
		result = spp_diag_trace_core_append(&core, parsed.event_type,
						    parsed.flags, parsed.task,
						    parsed.parent, parsed.operation,
						    parsed.phase,
						    parsed.payload_length
							    ? parsed.payload
							    : NULL,
						    parsed.payload_length);
		spp_diag_trace_core_snapshot(&core, &snap);
		if (result == WIRE_OK) {
			memcpy(frames[frame_n], snap.last_frame, snap.last_frame_len);
			frame_lens[frame_n] = snap.last_frame_len;
			frame_n++;
		}
	}
	print_snapshot(result, &snap, frames[0], frame_lens, frame_n);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 6 && strcmp(argv[1], "init") == 0)
		return run_sequence(0, 4, argv + 2);
	if (argc >= 6 && strcmp(argv[1], "run") == 0)
		return run_sequence(0, argc - 2, argv + 2);
	if (argc >= 7 && strcmp(argv[1], "mark") == 0)
		return run_sequence(1, argc - 2, argv + 2);
	fputs("usage: core-oracle-harness init|run|mark CH RUN CTL CMD [REASON] [FRAME...]\n",
	      stderr);
	return 2;
}
