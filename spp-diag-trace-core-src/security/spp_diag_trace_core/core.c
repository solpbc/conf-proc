/* SPDX-License-Identifier: GPL-2.0-only */

#include <crypto/sha2.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

#include "core.h"

static const u8 k_magic_header[8] = { SPP_DIAG_TRACE_MAGIC_HEADER_BYTES };
static const u8 k_source_commit[SPP_DIAG_TRACE_SOURCE_COMMIT_LEN] = {
	SPP_DIAG_TRACE_SOURCE_COMMIT_BYTES
};
static const u8 k_header_domain[28] = { SPP_DIAG_TRACE_PREIMAGE_DOMAIN_BYTES };
static const u8 k_frame_domain[27] = { SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_BYTES };

static void store_u16be(u8 *p, u16 v)
{
	p[0] = (u8)(v >> 8);
	p[1] = (u8)v;
}

static void store_u32be(u8 *p, u32 v)
{
	p[0] = (u8)(v >> 24);
	p[1] = (u8)(v >> 16);
	p[2] = (u8)(v >> 8);
	p[3] = (u8)v;
}

static void store_u64be(u8 *p, u64 v)
{
	p[0] = (u8)(v >> 56);
	p[1] = (u8)(v >> 48);
	p[2] = (u8)(v >> 40);
	p[3] = (u8)(v >> 32);
	p[4] = (u8)(v >> 24);
	p[5] = (u8)(v >> 16);
	p[6] = (u8)(v >> 8);
	p[7] = (u8)v;
}

static void encode_header(u8 *out, const u8 challenge[32],
			  const u8 run_identity[32],
			  const u8 control_plan_address[32],
			  const u8 command_line_sha256[32])
{
	memcpy(out, k_magic_header, 8);
	store_u16be(out + 8, SPP_DIAG_TRACE_WIRE_VERSION);
	store_u16be(out + 10, SPP_DIAG_TRACE_HEADER_SIZE);
	store_u16be(out + 12, SPP_DIAG_TRACE_POLICY_VERSION_PROVENANCE);
	store_u16be(out + 14, SPP_DIAG_TRACE_HASH_SHA256);
	store_u32be(out + 16, SPP_DIAG_TRACE_MAX_FRAMES);
	store_u64be(out + 20, SPP_DIAG_TRACE_MAX_STREAM_BYTES);
	store_u32be(out + 28, SPP_DIAG_TRACE_MAX_FRAME_BYTES);
	memcpy(out + 32, k_source_commit, SPP_DIAG_TRACE_SOURCE_COMMIT_LEN);
	memcpy(out + 52, challenge, 32);
	memcpy(out + 84, run_identity, 32);
	memcpy(out + 116, control_plan_address, 32);
	memcpy(out + 148, command_line_sha256, 32);
	store_u64be(out + 180, SPP_DIAG_TRACE_HOOK_MASK_PROVENANCE);
	store_u32be(out + 188, 0);
}

static void encode_frame(u8 *out, u16 event_type, u16 flags, u32 payload_length,
			 u64 sequence, u64 task, u64 parent, u64 operation,
			 u16 phase, const void *payload)
{
	store_u16be(out + 0, event_type);
	store_u16be(out + 2, flags);
	store_u32be(out + 4, payload_length);
	store_u64be(out + 8, sequence);
	store_u64be(out + 16, task);
	store_u64be(out + 24, parent);
	store_u64be(out + 32, operation);
	store_u16be(out + 40, phase);
	store_u16be(out + 42, 0);
	if (payload_length)
		memcpy(out + 44, payload, payload_length);
}

static void hash_header_preimage(const u8 *header, u8 *out)
{
	u8 preimage[SPP_DIAG_TRACE_PREIMAGE_SIZE];

	memcpy(preimage, k_header_domain, 28);
	store_u32be(preimage + 28, SPP_DIAG_TRACE_HEADER_SIZE);
	memcpy(preimage + 32, header, SPP_DIAG_TRACE_HEADER_SIZE);
	sha256(preimage, SPP_DIAG_TRACE_PREIMAGE_SIZE, out);
}

static void hash_frame_preimage(const u8 *prev_chain, const u8 *frame,
				u32 frame_len, u8 *out)
{
	u8 preimage[SPP_DIAG_TRACE_FRAME_PREIMAGE_MAX_SIZE];
	unsigned int n;

	memcpy(preimage, k_frame_domain, 27);
	memcpy(preimage + 27, prev_chain, SPP_DIAG_TRACE_CHAIN_LEN);
	store_u32be(preimage + 27 + SPP_DIAG_TRACE_CHAIN_LEN, frame_len);
	memcpy(preimage + 27 + SPP_DIAG_TRACE_CHAIN_LEN + 4, frame, frame_len);
	n = 27u + SPP_DIAG_TRACE_CHAIN_LEN + 4u + frame_len;
	sha256(preimage, n, out);
}

static void fill_snapshot_locked(const struct spp_diag_trace_core *core,
				 struct spp_diag_trace_core_snapshot *out)
{
	memset(out, 0, sizeof(*out));
	out->initialized = core->initialized;
	out->failed = core->failed;
	out->reason = core->reason;
	memcpy(out->header, core->header, SPP_DIAG_TRACE_HEADER_SIZE);
	memcpy(out->core_init_frame, core->core_init_frame,
	       SPP_DIAG_TRACE_FRAME_HEADER_SIZE);
	memcpy(out->header_chain, core->header_chain, SPP_DIAG_TRACE_CHAIN_LEN);
	memcpy(out->chain, core->chain, SPP_DIAG_TRACE_CHAIN_LEN);
	out->frame_count = core->frame_count;
	out->stream_byte_count = core->stream_byte_count;
	out->sequence = core->sequence;
	out->max_frames_op = SPP_DIAG_TRACE_CORE_OP_MAX_FRAMES;
	out->max_stream_bytes_op = SPP_DIAG_TRACE_CORE_OP_MAX_STREAM_BYTES;
	out->last_frame_len = core->last_frame_len;
	if (core->last_frame_len)
		memcpy(out->last_frame, core->last_frame, core->last_frame_len);
}

static void ensure_lock(struct spp_diag_trace_core *core)
{
	if (!core->lock_inited) {
		spin_lock_init(&core->lock);
		core->lock_inited = 1;
	}
}

static void run_barrier(struct spp_diag_trace_core *core)
{
#if IS_ENABLED(CONFIG_KUNIT)
	if (core->pre_lock_barrier)
		core->pre_lock_barrier(core->pre_lock_barrier_arg);
#else
	(void)core;
#endif
}

static int sticky_or_fault(struct spp_diag_trace_core *core)
{
	if (core->failed)
		return core->reason;
#if IS_ENABLED(CONFIG_KUNIT)
	if (core->fault_inject) {
		core->failed = 1;
		core->reason = core->fault_inject;
		core->fault_inject = 0;
		return core->reason;
	}
#endif
	return WIRE_OK;
}

static int fail_sticky(struct spp_diag_trace_core *core, int reason)
{
	if (!core->failed) {
		core->failed = 1;
		core->reason = reason;
	}
	return core->reason;
}

static int core_event(u16 event)
{
	return event >= SPP_DIAG_TRACE_EVENT_CORE_INIT &&
	       event <= SPP_DIAG_TRACE_EVENT_TERMINAL;
}

static int provenance_event(u16 event)
{
	switch (event) {
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT:
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION:
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_EXEC_MAPPING_POLICY_DECISION:
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_NETWORK_POLICY_DECISION:
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_OPERATION_RETURN:
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_TASK_EXIT:
		return 1;
	default:
		return 0;
	}
}

static int check_flags(u16 event, u16 flags)
{
	if (event == SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT)
		return (flags & ~1u) == 0 ? WIRE_OK : WIRE_FLAGS;
	return flags == 0 ? WIRE_OK : WIRE_FLAGS;
}

static int check_payload_length(u16 event, size_t n)
{
	if (n > SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES)
		return WIRE_CAP;
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
		return (n >= 21 && n <= SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES)
			       ? WIRE_OK
			       : WIRE_LENGTH;
	case SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT:
		return (n >= 17 &&
			n <= 16u + SPP_DIAG_TRACE_MAX_PATH_BYTES)
			       ? WIRE_OK
			       : WIRE_LENGTH;
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT:
		return (n >= SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_MIN_PAYLOAD &&
			n <= SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_MAX_PAYLOAD)
			       ? WIRE_OK
			       : WIRE_LENGTH;
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION:
		return n == SPP_DIAG_TRACE_FILE_POLICY_DECISION_PAYLOAD_SIZE
			       ? WIRE_OK
			       : WIRE_LENGTH;
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_EXEC_MAPPING_POLICY_DECISION:
		return n == SPP_DIAG_TRACE_EXEC_MAPPING_POLICY_DECISION_PAYLOAD_SIZE
			       ? WIRE_OK
			       : WIRE_LENGTH;
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_NETWORK_POLICY_DECISION:
		return n == SPP_DIAG_TRACE_NETWORK_POLICY_DECISION_PAYLOAD_SIZE
			       ? WIRE_OK
			       : WIRE_LENGTH;
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_OPERATION_RETURN:
		return n == SPP_DIAG_TRACE_OPERATION_RETURN_PAYLOAD_SIZE
			       ? WIRE_OK
			       : WIRE_LENGTH;
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_TASK_EXIT:
		return n == SPP_DIAG_TRACE_TASK_EXIT_PAYLOAD_SIZE ? WIRE_OK
								 : WIRE_LENGTH;
	default:
		return WIRE_EVENT;
	}
}

static int check_task(u16 event, u64 task)
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
		return task != 0 ? WIRE_OK : WIRE_VALUE;
	}
}

static int check_parent(u16 event, u64 task, u64 parent)
{
	if (event == SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT ||
	    event == SPP_DIAG_TRACE_EVENT_TASK_CREATED) {
		if (parent == 0 || parent == task)
			return WIRE_VALUE;
		return WIRE_OK;
	}
	if (event == SPP_DIAG_TRACE_PROVENANCE_EVENT_TASK_EXIT)
		return parent != 0 && parent != task ? WIRE_OK : WIRE_VALUE;
	return parent == 0 ? WIRE_OK : WIRE_VALUE;
}

static int check_operation(u16 event, u64 operation)
{
	switch (event) {
	case SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED:
	case SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT:
	case SPP_DIAG_TRACE_EVENT_EXEC_COMMIT:
	case SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT:
	case SPP_DIAG_TRACE_EVENT_TASK_CREATED:
		return operation != 0 ? WIRE_OK : WIRE_VALUE;
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_TASK_EXIT:
		return operation == 0 ? WIRE_OK : WIRE_VALUE;
	case SPP_DIAG_TRACE_EVENT_CORE_INIT:
	case SPP_DIAG_TRACE_EVENT_IMA_READY:
	case SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE:
	case SPP_DIAG_TRACE_EVENT_PHASE_MARKER:
	case SPP_DIAG_TRACE_EVENT_TERMINAL:
		return operation == 0 ? WIRE_OK : WIRE_VALUE;
	default:
		return operation != 0 ? WIRE_OK : WIRE_VALUE;
	}
}

static int check_phase(u16 event, u16 flags, u16 phase)
{
	switch (event) {
	case SPP_DIAG_TRACE_EVENT_CORE_INIT:
	case SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED:
	case SPP_DIAG_TRACE_EVENT_IMA_READY:
	case SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE:
		return phase == SPP_DIAG_TRACE_PHASE_PRE_RELEASE ? WIRE_OK
								 : WIRE_STATE;
	case SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT:
		if ((flags & 1u) != 0)
			return phase == SPP_DIAG_TRACE_PHASE_PRE_RELEASE
				       ? WIRE_OK
				       : WIRE_STATE;
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
		return phase == SPP_DIAG_TRACE_PHASE_SEALED ? WIRE_OK
							    : WIRE_STATE;
	default:
		return (phase >= SPP_DIAG_TRACE_PHASE_INIT &&
			phase <= SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE)
			       ? WIRE_OK
			       : WIRE_STATE;
	}
}

static int check_append_fields(u16 event, u16 flags, u64 task, u64 parent,
			       u64 operation, u16 phase, const void *payload,
			       size_t payload_length)
{
	int err;

	if (event == SPP_DIAG_TRACE_EVENT_CORE_INIT)
		return WIRE_EVENT;
	if (payload == NULL && payload_length > 0)
		return WIRE_NULL;
	if (!core_event(event) && !provenance_event(event))
		return WIRE_EVENT;
	err = check_flags(event, flags);
	if (err)
		return err;
	err = check_payload_length(event, payload_length);
	if (err)
		return err;
	err = check_task(event, task);
	if (err)
		return err;
	err = check_parent(event, task, parent);
	if (err)
		return err;
	err = check_operation(event, operation);
	if (err)
		return err;
	return check_phase(event, flags, phase);
}

int spp_diag_trace_core_init(struct spp_diag_trace_core *core,
			     const u8 challenge[32],
			     const u8 run_identity[32],
			     const u8 control_plan_address[32],
			     const u8 command_line_sha256[32])
{
	unsigned long flags;
	u8 header[SPP_DIAG_TRACE_HEADER_SIZE];
	u8 core_init[SPP_DIAG_TRACE_FRAME_HEADER_SIZE];
	u8 header_chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u8 chain[SPP_DIAG_TRACE_CHAIN_LEN];
	int err;

	if (core == NULL)
		return WIRE_NULL;
	ensure_lock(core);
	spin_lock_irqsave(&core->lock, flags);
	run_barrier(core);
	err = sticky_or_fault(core);
	if (err) {
		spin_unlock_irqrestore(&core->lock, flags);
		return err;
	}
	if (core->initialized) {
		err = fail_sticky(core, WIRE_STATE);
		spin_unlock_irqrestore(&core->lock, flags);
		return err;
	}
	if (challenge == NULL || run_identity == NULL ||
	    control_plan_address == NULL || command_line_sha256 == NULL) {
		err = fail_sticky(core, WIRE_NULL);
		spin_unlock_irqrestore(&core->lock, flags);
		return err;
	}
	encode_header(header, challenge, run_identity, control_plan_address,
		      command_line_sha256);
	hash_header_preimage(header, header_chain);
	encode_frame(core_init, SPP_DIAG_TRACE_EVENT_CORE_INIT, 0, 0, 0, 0, 0, 0,
		     SPP_DIAG_TRACE_PHASE_PRE_RELEASE, NULL);
	hash_frame_preimage(header_chain, core_init,
			    SPP_DIAG_TRACE_FRAME_HEADER_SIZE, chain);
	memcpy(core->header, header, SPP_DIAG_TRACE_HEADER_SIZE);
	memcpy(core->core_init_frame, core_init,
	       SPP_DIAG_TRACE_FRAME_HEADER_SIZE);
	memcpy(core->header_chain, header_chain, SPP_DIAG_TRACE_CHAIN_LEN);
	memcpy(core->chain, chain, SPP_DIAG_TRACE_CHAIN_LEN);
	memcpy(core->last_frame, core_init, SPP_DIAG_TRACE_FRAME_HEADER_SIZE);
	core->last_frame_len = SPP_DIAG_TRACE_FRAME_HEADER_SIZE;
	core->frame_count = 1;
	core->stream_byte_count = SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE +
				  SPP_DIAG_TRACE_STREAM_PREFIX_SIZE +
				  SPP_DIAG_TRACE_FRAME_HEADER_SIZE;
	core->sequence = 1;
	core->initialized = 1;
	core->failed = 0;
	core->reason = 0;
	spin_unlock_irqrestore(&core->lock, flags);
	return WIRE_OK;
}

int spp_diag_trace_core_append(struct spp_diag_trace_core *core,
			       u16 event_type, u16 flags,
			       u64 task_ordinal, u64 parent_task_ordinal,
			       u64 operation_ordinal, u16 phase,
			       const void *payload, size_t payload_length)
{
	unsigned long irqflags;
	u8 frame[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
	u8 next_chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u32 frame_len;
	int err;

	if (core == NULL)
		return WIRE_NULL;
	ensure_lock(core);
	spin_lock_irqsave(&core->lock, irqflags);
	run_barrier(core);
	err = sticky_or_fault(core);
	if (err) {
		spin_unlock_irqrestore(&core->lock, irqflags);
		return err;
	}
	if (!core->initialized) {
		err = fail_sticky(core, WIRE_STATE);
		spin_unlock_irqrestore(&core->lock, irqflags);
		return err;
	}
	err = check_append_fields(event_type, flags, task_ordinal,
				  parent_task_ordinal, operation_ordinal, phase,
				  payload, payload_length);
	if (err) {
		err = fail_sticky(core, err);
		spin_unlock_irqrestore(&core->lock, irqflags);
		return err;
	}
	frame_len = SPP_DIAG_TRACE_FRAME_HEADER_SIZE + (u32)payload_length;
	if (core->frame_count >= SPP_DIAG_TRACE_CORE_OP_MAX_FRAMES) {
		err = fail_sticky(core, WIRE_CAP);
		spin_unlock_irqrestore(&core->lock, irqflags);
		return err;
	}
	if (core->stream_byte_count + SPP_DIAG_TRACE_STREAM_PREFIX_SIZE +
		    frame_len >
	    SPP_DIAG_TRACE_CORE_OP_MAX_STREAM_BYTES) {
		err = fail_sticky(core, WIRE_CAP);
		spin_unlock_irqrestore(&core->lock, irqflags);
		return err;
	}
	encode_frame(frame, event_type, flags, (u32)payload_length,
		     core->sequence, task_ordinal, parent_task_ordinal,
		     operation_ordinal, phase, payload);
	hash_frame_preimage(core->chain, frame, frame_len, next_chain);
	memcpy(core->chain, next_chain, SPP_DIAG_TRACE_CHAIN_LEN);
	memcpy(core->last_frame, frame, frame_len);
	core->last_frame_len = frame_len;
	core->frame_count += 1;
	core->stream_byte_count += SPP_DIAG_TRACE_STREAM_PREFIX_SIZE + frame_len;
	core->sequence += 1;
	spin_unlock_irqrestore(&core->lock, irqflags);
	return WIRE_OK;
}

int spp_diag_trace_core_snapshot(struct spp_diag_trace_core *core,
				 struct spp_diag_trace_core_snapshot *out)
{
	unsigned long flags;

	if (core == NULL || out == NULL)
		return WIRE_NULL;
	ensure_lock(core);
	spin_lock_irqsave(&core->lock, flags);
	fill_snapshot_locked(core, out);
	spin_unlock_irqrestore(&core->lock, flags);
	return WIRE_OK;
}

int spp_diag_trace_core_mark_failure(struct spp_diag_trace_core *core,
				     int reason)
{
	unsigned long flags;
	int err;

	if (core == NULL)
		return WIRE_NULL;
	ensure_lock(core);
	spin_lock_irqsave(&core->lock, flags);
	run_barrier(core);
	err = sticky_or_fault(core);
	if (err) {
		spin_unlock_irqrestore(&core->lock, flags);
		return err;
	}
	err = fail_sticky(core, reason);
	spin_unlock_irqrestore(&core->lock, flags);
	return err;
}

#if IS_ENABLED(CONFIG_KUNIT)
void spp_diag_trace_core_reset(struct spp_diag_trace_core *core)
{
	unsigned long flags;

	if (core == NULL)
		return;
	ensure_lock(core);
	spin_lock_irqsave(&core->lock, flags);
	core->initialized = 0;
	core->failed = 0;
	core->reason = 0;
	memset(core->header, 0, sizeof(core->header));
	memset(core->core_init_frame, 0, sizeof(core->core_init_frame));
	memset(core->header_chain, 0, sizeof(core->header_chain));
	memset(core->chain, 0, sizeof(core->chain));
	core->frame_count = 0;
	core->stream_byte_count = 0;
	core->sequence = 0;
	memset(core->last_frame, 0, sizeof(core->last_frame));
	core->last_frame_len = 0;
	core->fault_inject = 0;
	core->pre_lock_barrier = NULL;
	core->pre_lock_barrier_arg = NULL;
	spin_unlock_irqrestore(&core->lock, flags);
}

void spp_diag_trace_core_inject_fault(struct spp_diag_trace_core *core, int fault)
{
	unsigned long flags;

	if (core == NULL)
		return;
	ensure_lock(core);
	spin_lock_irqsave(&core->lock, flags);
	core->fault_inject = fault;
	spin_unlock_irqrestore(&core->lock, flags);
}

void spp_diag_trace_core_set_pre_lock_barrier(struct spp_diag_trace_core *core,
					      void (*fn)(void *), void *arg)
{
	unsigned long flags;

	if (core == NULL)
		return;
	ensure_lock(core);
	spin_lock_irqsave(&core->lock, flags);
	core->pre_lock_barrier = fn;
	core->pre_lock_barrier_arg = arg;
	spin_unlock_irqrestore(&core->lock, flags);
}
#endif
