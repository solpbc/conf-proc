/* SPDX-License-Identifier: GPL-2.0-only */

#include <crypto/sha2.h>
#include <linux/init.h>
#include <linux/panic.h>
#include <linux/string.h>

#include <linux/spp_diag_trace_bootstrap.h>

#include "core.h"

static const u8 bootstrap_magic[8] = { SPP_DIAG_TRACE_MAGIC_HEADER_BYTES };
static const u8 bootstrap_source_commit[SPP_DIAG_TRACE_SOURCE_COMMIT_LEN] = {
	SPP_DIAG_TRACE_SOURCE_COMMIT_BYTES
};
static const u8 bootstrap_header_domain[28] = {
	SPP_DIAG_TRACE_PREIMAGE_DOMAIN_BYTES
};
static const u8 bootstrap_frame_domain[27] = {
	SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_BYTES
};

struct spp_diag_trace_bootstrap_state {
	u8 challenge[32];
	u8 run[32];
	u8 control_plan[32];
	u8 command_line[32];
	u8 chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u64 frame_count;
	u64 stream_bytes;
	u64 sequence;
};

static struct spp_diag_trace_bootstrap_state bootstrap_state;

static void store_u16be(u8 *p, u16 value)
{
	p[0] = (u8)(value >> 8);
	p[1] = (u8)value;
}

static void store_u32be(u8 *p, u32 value)
{
	p[0] = (u8)(value >> 24);
	p[1] = (u8)(value >> 16);
	p[2] = (u8)(value >> 8);
	p[3] = (u8)value;
}

static void store_u64be(u8 *p, u64 value)
{
	p[0] = (u8)(value >> 56);
	p[1] = (u8)(value >> 48);
	p[2] = (u8)(value >> 40);
	p[3] = (u8)(value >> 32);
	p[4] = (u8)(value >> 24);
	p[5] = (u8)(value >> 16);
	p[6] = (u8)(value >> 8);
	p[7] = (u8)value;
}

static void encode_frame(u8 *out, u16 event_type, u16 flags,
			 u32 payload_length, u64 sequence, u64 task,
			 u64 parent, u64 operation, u16 phase,
			 const void *payload)
{
	store_u16be(out, event_type);
	store_u16be(out + 2, flags);
	store_u32be(out + 4, payload_length);
	store_u64be(out + 8, sequence);
	store_u64be(out + 16, task);
	store_u64be(out + 24, parent);
	store_u64be(out + 32, operation);
	store_u16be(out + 40, phase);
	store_u16be(out + 42, 0);
	if (payload_length)
		memcpy(out + SPP_DIAG_TRACE_FRAME_HEADER_SIZE, payload,
		       payload_length);
}

static void hash_frame(const u8 previous[32], const u8 *frame, u32 frame_len,
		       u8 out[32])
{
	u8 preimage[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
	u32 size = 27u + SPP_DIAG_TRACE_CHAIN_LEN + 4u + frame_len;

	memcpy(preimage, bootstrap_frame_domain, 27);
	memcpy(preimage + 27, previous, SPP_DIAG_TRACE_CHAIN_LEN);
	store_u32be(preimage + 27 + SPP_DIAG_TRACE_CHAIN_LEN, frame_len);
	memcpy(preimage + 27 + SPP_DIAG_TRACE_CHAIN_LEN + 4, frame, frame_len);
	sha256(preimage, size, out);
}

static int hex_value(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	return -1;
}

static int decode_identity(const char *value, size_t value_len, u8 out[32])
{
	size_t i;

	if (value_len != 64)
		return -1;
	for (i = 0; i < 32; i++) {
		int high = hex_value(value[i * 2]);
		int low = hex_value(value[i * 2 + 1]);

		if (high < 0 || low < 0)
			return -1;
		out[i] = (u8)((high << 4) | low);
	}
	return 0;
}

static int whitespace(char value)
{
	return value == ' ' || value == '\t' || value == '\n' || value == '\r';
}

static int set_identity(const char *token, size_t token_len, const char *name,
			int *seen, u8 out[32])
{
	size_t name_len = strlen(name);

	if (token_len < name_len || memcmp(token, name, name_len) != 0)
		return 0;
	if (*seen || decode_identity(token + name_len, token_len - name_len, out))
		return -1;
	*seen = 1;
	return 1;
}

static int parse_identities(const char *command_line, size_t command_line_len,
			    u8 challenge[32], u8 run[32], u8 control_plan[32])
{
	size_t start = 0;
	int after_double_dash = 0;
	int challenge_seen = 0, run_seen = 0, control_plan_seen = 0;

	while (start < command_line_len) {
		size_t end;
		int result;

		while (start < command_line_len && whitespace(command_line[start]))
			start++;
		end = start;
		while (end < command_line_len && !whitespace(command_line[end]))
			end++;
		if (start == end)
			break;
		if (!after_double_dash && end - start == 2 &&
		    command_line[start] == '-' && command_line[start + 1] == '-') {
			after_double_dash = 1;
			start = end;
			continue;
		}
		if (!after_double_dash) {
			result = set_identity(command_line + start, end - start,
					      "sol_spp_diag.challenge=",
					      &challenge_seen, challenge);
			if (result < 0)
				return -1;
			if (!result) {
				result = set_identity(command_line + start, end - start,
						      "sol_spp_diag.run=", &run_seen,
						      run);
				if (result < 0)
					return -1;
			}
			if (!result) {
				result = set_identity(command_line + start, end - start,
						      "sol_spp_diag.control_plan=",
						      &control_plan_seen, control_plan);
				if (result < 0)
					return -1;
			}
			if (!result && end - start >= 13 &&
			    memcmp(command_line + start, "sol_spp_diag.", 13) == 0)
				return -1;
		}
		start = end;
	}
	return challenge_seen && run_seen && control_plan_seen ? 0 : -1;
}

static void initialise_state(const u8 challenge[32], const u8 run[32],
			     const u8 control_plan[32], const u8 command_line[32])
{
	u8 header[SPP_DIAG_TRACE_HEADER_SIZE];
	u8 core_init[SPP_DIAG_TRACE_FRAME_HEADER_SIZE];
	u8 header_preimage[SPP_DIAG_TRACE_PREIMAGE_SIZE];
	u8 header_chain[SPP_DIAG_TRACE_CHAIN_LEN];

	memset(&bootstrap_state, 0, sizeof(bootstrap_state));
	memcpy(bootstrap_state.challenge, challenge, 32);
	memcpy(bootstrap_state.run, run, 32);
	memcpy(bootstrap_state.control_plan, control_plan, 32);
	memcpy(bootstrap_state.command_line, command_line, 32);
	memset(header, 0, sizeof(header));
	memcpy(header, bootstrap_magic, sizeof(bootstrap_magic));
	store_u16be(header + 8, SPP_DIAG_TRACE_WIRE_VERSION);
	store_u16be(header + 10, SPP_DIAG_TRACE_HEADER_SIZE);
	store_u16be(header + 12, SPP_DIAG_TRACE_POLICY_VERSION_PROVENANCE);
	store_u16be(header + 14, SPP_DIAG_TRACE_HASH_SHA256);
	store_u32be(header + 16, SPP_DIAG_TRACE_MAX_FRAMES);
	store_u64be(header + 20, SPP_DIAG_TRACE_MAX_STREAM_BYTES);
	store_u32be(header + 28, SPP_DIAG_TRACE_MAX_FRAME_BYTES);
	memcpy(header + 32, bootstrap_source_commit, sizeof(bootstrap_source_commit));
	memcpy(header + 52, challenge, 32);
	memcpy(header + 84, run, 32);
	memcpy(header + 116, control_plan, 32);
	memcpy(header + 148, command_line, 32);
	store_u64be(header + 180, SPP_DIAG_TRACE_HOOK_MASK_PROVENANCE);
	memcpy(header_preimage, bootstrap_header_domain, 28);
	store_u32be(header_preimage + 28, SPP_DIAG_TRACE_HEADER_SIZE);
	memcpy(header_preimage + 32, header, sizeof(header));
	sha256(header_preimage, sizeof(header_preimage), header_chain);
	encode_frame(core_init, SPP_DIAG_TRACE_EVENT_CORE_INIT, 0, 0, 0, 0, 0,
		     0, SPP_DIAG_TRACE_PHASE_PRE_RELEASE, NULL);
	hash_frame(header_chain, core_init, sizeof(core_init), bootstrap_state.chain);
	bootstrap_state.frame_count = 1;
	bootstrap_state.stream_bytes = SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE +
		SPP_DIAG_TRACE_STREAM_PREFIX_SIZE + SPP_DIAG_TRACE_FRAME_HEADER_SIZE;
	bootstrap_state.sequence = 1;
}

void spp_diag_trace_bootstrap_note_frame(u16 event_type, u16 flags,
					 u64 task_ordinal, u64 parent_task_ordinal,
					 u64 operation_ordinal, u16 phase,
					 const void *payload, size_t payload_length)
{
	u8 frame[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
	u8 next_chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u32 frame_len = SPP_DIAG_TRACE_FRAME_HEADER_SIZE + (u32)payload_length;

	encode_frame(frame, event_type, flags, (u32)payload_length,
		     bootstrap_state.sequence, task_ordinal, parent_task_ordinal,
		     operation_ordinal, phase, payload);
	hash_frame(bootstrap_state.chain, frame, frame_len, next_chain);
	memcpy(bootstrap_state.chain, next_chain, sizeof(next_chain));
	bootstrap_state.frame_count++;
	bootstrap_state.stream_bytes += SPP_DIAG_TRACE_STREAM_PREFIX_SIZE + frame_len;
	bootstrap_state.sequence++;
}

void spp_diag_trace_bootstrap_ima_record(u16 kind, u64 denied_count, u8 out[256])
{
	memset(out, 0, SPP_DIAG_TRACE_IMA_SIZE);
	memcpy(out, "SPPIMA1\0", 8);
	store_u16be(out + 8, SPP_DIAG_TRACE_WIRE_VERSION);
	store_u16be(out + 10, kind);
	store_u32be(out + 12, SPP_DIAG_TRACE_IMA_SIZE);
	store_u16be(out + 16, SPP_DIAG_TRACE_POLICY_VERSION_PROVENANCE);
	store_u16be(out + 18, SPP_DIAG_TRACE_HASH_SHA256);
	store_u16be(out + 20, kind == SPP_DIAG_TRACE_IMA_KIND_READY ?
		     SPP_DIAG_TRACE_IMA_STATE_LIST_READY :
		     SPP_DIAG_TRACE_IMA_STATE_LIST_RELEASED);
	memcpy(out + 24, bootstrap_source_commit, sizeof(bootstrap_source_commit));
	memcpy(out + 44, bootstrap_state.challenge, 32);
	memcpy(out + 76, bootstrap_state.run, 32);
	memcpy(out + 108, bootstrap_state.control_plan, 32);
	memcpy(out + 140, bootstrap_state.command_line, 32);
	store_u64be(out + 172, bootstrap_state.frame_count);
	store_u64be(out + 180, bootstrap_state.stream_bytes);
	memcpy(out + 188, bootstrap_state.chain, SPP_DIAG_TRACE_CHAIN_LEN);
	store_u64be(out + 228, SPP_DIAG_TRACE_HOOK_MASK_PROVENANCE);
	store_u64be(out + 236, denied_count);
}

void __init spp_diag_trace_bootstrap_init(void)
{
	u8 challenge[32], run[32], control_plan[32], command_line[32];

	if (!saved_command_line ||
	    parse_identities(saved_command_line, saved_command_line_len,
			     challenge, run, control_plan)) {
		panic("spp diag trace bootstrap command line");
		return;
	}
	sha256((const u8 *)saved_command_line, saved_command_line_len, command_line);
	if (spp_diag_trace_core_init(challenge, run, control_plan, command_line)) {
		panic("spp diag trace bootstrap core init");
		return;
	}
	initialise_state(challenge, run, control_plan, command_line);
}

#if IS_ENABLED(CONFIG_KUNIT)
void spp_diag_trace_bootstrap_test_reset(void)
{
	memset(&bootstrap_state, 0, sizeof(bootstrap_state));
}
#endif
