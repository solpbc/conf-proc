/* SPDX-License-Identifier: GPL-2.0-only */

#include <crypto/sha2.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/ima.h>

#include "core.h"

static const u8 k_magic_header[8] = { SPP_DIAG_TRACE_MAGIC_HEADER_BYTES };
#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
static const u8 k_magic_command[8] = { SPP_DIAG_TRACE_MAGIC_COMMAND_BYTES };
static const u8 k_magic_ima[8] = { SPP_DIAG_TRACE_MAGIC_IMA_BYTES };
#endif
static const u8 k_source_commit[SPP_DIAG_TRACE_SOURCE_COMMIT_LEN] = {
	SPP_DIAG_TRACE_SOURCE_COMMIT_BYTES
};
static const u8 k_header_domain[28] = { SPP_DIAG_TRACE_PREIMAGE_DOMAIN_BYTES };
static const u8 k_frame_domain[27] = { SPP_DIAG_TRACE_FRAME_PREIMAGE_DOMAIN_BYTES };

static DEFINE_SPINLOCK(spp_diag_trace_core_lock);

static struct {
	int initialized;
	int failed;
	int reason;
	u8 *stream;
	size_t stream_cap;
	size_t stream_len;
	u8 header[SPP_DIAG_TRACE_HEADER_SIZE];
	u8 core_init_frame[SPP_DIAG_TRACE_FRAME_HEADER_SIZE];
	u8 header_chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u8 chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u64 frame_count;
	u64 stream_byte_count;
	u64 sequence;
	u8 last_frame[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
	u32 last_frame_len;
	u32 max_frames_op;
	u64 max_stream_bytes_op;
	u64 bootstrap_denial_count;
	u32 bootstrap_stage;
	int bootstrap_released;
#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
	struct spp_diag_trace_task_record *runtime_tasks;
	struct spp_diag_trace_operation_record *runtime_ops;
	size_t runtime_task_cap;
	size_t runtime_op_cap;
	u64 runtime_next_task_ordinal;
	u64 runtime_next_op_ordinal;
	u32 runtime_next_exec_reservation_token;
	u64 committed_exec_count;
	u16 runtime_phase;
	int runtime_ready;
	int runtime_sealing;
	int runtime_sealed;
#endif
#if IS_ENABLED(CONFIG_KUNIT)
	int fault_inject;
	int init_fault;
	void (*pre_lock_barrier)(void *);
	void *pre_lock_barrier_arg;
	void (*read_copy_hook)(bool lock_held);
#endif
} core = {
	.max_frames_op = SPP_DIAG_TRACE_CORE_OP_MAX_FRAMES,
	.max_stream_bytes_op = SPP_DIAG_TRACE_CORE_OP_MAX_STREAM_BYTES,
#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
	.runtime_next_task_ordinal = 1,
	.runtime_next_op_ordinal = 2,
	.runtime_next_exec_reservation_token = 1,
	.runtime_phase = SPP_DIAG_TRACE_PHASE_PRE_RELEASE,
#endif
};

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

static u16 load_u16be(const u8 *p)
{
	return (u16)(((u16)p[0] << 8) | (u16)p[1]);
}

static u32 load_u32be(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) |
	       (u32)p[3];
}

static u64 load_u64be(const u8 *p)
{
	return ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) |
	       ((u64)p[3] << 32) | ((u64)p[4] << 24) | ((u64)p[5] << 16) |
	       ((u64)p[6] << 8) | (u64)p[7];
}

static int add_u64(u64 a, u64 b, u64 *out)
{
	if (a > ~0ull - b)
		return WIRE_ARITHMETIC;
	*out = a + b;
	return WIRE_OK;
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

#if IS_ENABLED(CONFIG_KUNIT)
static void fill_snapshot_meta(struct spp_diag_trace_core_snapshot *out)
{
	memset(out, 0, sizeof(*out));
	out->initialized = core.initialized;
	out->failed = core.failed;
	out->reason = core.reason;
	memcpy(out->header, core.header, SPP_DIAG_TRACE_HEADER_SIZE);
	memcpy(out->core_init_frame, core.core_init_frame,
	       SPP_DIAG_TRACE_FRAME_HEADER_SIZE);
	memcpy(out->header_chain, core.header_chain, SPP_DIAG_TRACE_CHAIN_LEN);
	memcpy(out->chain, core.chain, SPP_DIAG_TRACE_CHAIN_LEN);
	out->frame_count = core.frame_count;
	out->stream_byte_count = core.stream_byte_count;
	out->sequence = core.sequence;
	out->max_frames_op = core.max_frames_op;
	out->max_stream_bytes_op = core.max_stream_bytes_op;
	out->last_frame_len = core.last_frame_len;
	if (core.last_frame_len)
		memcpy(out->last_frame, core.last_frame, core.last_frame_len);
	out->stream_len = core.stream_len;
	out->bootstrap_denial_count = core.bootstrap_denial_count;
	out->bootstrap_stage = core.bootstrap_stage;
	out->bootstrap_released = core.bootstrap_released;
}
#endif

static void run_barrier(void)
{
#if IS_ENABLED(CONFIG_KUNIT)
	if (core.pre_lock_barrier)
		core.pre_lock_barrier(core.pre_lock_barrier_arg);
#endif
}

static int sticky_or_fault(void)
{
	if (core.failed)
		return core.reason;
#if IS_ENABLED(CONFIG_KUNIT)
	if (core.fault_inject) {
		core.failed = 1;
		core.reason = core.fault_inject;
		core.fault_inject = 0;
		return core.reason;
	}
#endif
	return WIRE_OK;
}

static int fail_sticky(int reason)
{
	if (!core.failed) {
		core.failed = 1;
		core.reason = reason;
	}
	return core.reason;
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

static int check_path_len(u16 path_len, size_t payload_length, u32 prefix)
{
	if (path_len == 0)
		return WIRE_LENGTH;
	if (path_len > SPP_DIAG_TRACE_MAX_PATH_BYTES)
		return WIRE_CAP;
	if (payload_length != (size_t)prefix + (size_t)path_len)
		return WIRE_LENGTH;
	return WIRE_OK;
}

static int check_path_bytes(const u8 *path, u16 n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (path[i] == 0)
			return WIRE_VALUE;
	}
	return WIRE_OK;
}

static int check_zero_bytes(const u8 *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (p[i] != 0)
			return WIRE_VALUE;
	}
	return WIRE_OK;
}

static int check_policy_result(u16 decision, u32 result)
{
	if (decision == SPP_DIAG_TRACE_POLICY_ALLOW) {
		if (result != 0)
			return WIRE_VALUE;
	} else if (decision == SPP_DIAG_TRACE_POLICY_DENY) {
		if ((result >> 31) == 0)
			return WIRE_VALUE;
	}
	return WIRE_OK;
}

static int check_pre_release_payload(const u8 *p, size_t n)
{
	u16 path_len;
	int err;

	if (load_u16be(p) != 13u)
		return WIRE_VALUE;
	path_len = load_u16be(p + 2);
	err = check_path_len(path_len, n, 20u);
	if (err)
		return err;
	if (load_u32be(p + 4) == 0 || load_u32be(p + 8) == 0)
		return WIRE_VALUE;
	return check_path_bytes(p + 20, path_len);
}

static int check_userspace_release_payload(const u8 *p)
{
	return load_u32be(p) != 0 && load_u32be(p + 4) != 0 ? WIRE_OK
							       : WIRE_VALUE;
}

static int check_exec_attempt_payload(const u8 *p, size_t n)
{
	u16 path_len;
	int err;

	if (load_u32be(p) == 0)
		return WIRE_VALUE;
	path_len = load_u16be(p + 4);
	err = check_path_len(path_len, n, 16u);
	if (err)
		return err;
	if (load_u16be(p + 6) != 0)
		return WIRE_RESERVED;
	if (load_u32be(p + 8) == 0 || load_u32be(p + 12) == 0)
		return WIRE_VALUE;
	return check_path_bytes(p + 16, path_len);
}

static int check_exec_commit_payload(const u8 *p)
{
	if (load_u32be(p) == 0 || load_u32be(p + 4) == 0 ||
	    load_u32be(p + 8) == 0)
		return WIRE_VALUE;
	return load_u32be(p + 12) == 0 ? WIRE_OK : WIRE_RESERVED;
}

static int check_task_created_payload(const u8 *p)
{
	return load_u32be(p) != 0 && load_u32be(p + 4) != 0 ? WIRE_OK
							       : WIRE_VALUE;
}

static int check_phase_marker_payload(const u8 *p, u16 frame_phase)
{
	u16 prev = load_u16be(p);
	u16 next = load_u16be(p + 2);

	if (prev < SPP_DIAG_TRACE_PHASE_INIT ||
	    prev > SPP_DIAG_TRACE_PHASE_JIT_CACHE || next != (u16)(prev + 1u) ||
	    frame_phase != next)
		return WIRE_STATE;
	return load_u32be(p + 4) == 0 ? WIRE_OK : WIRE_RESERVED;
}

static int check_file_open_payload(const u8 *p, size_t n)
{
	u16 action;
	u16 path_len;
	u16 access;
	u16 modifiers;
	u32 reserved;
	int err;

	action = load_u16be(p);
	if (action != 1u)
		return WIRE_STATE;
	path_len = load_u16be(p + 2);
	err = check_path_len(path_len, n,
			     SPP_DIAG_TRACE_FILE_OPEN_ATTEMPT_PREFIX_SIZE);
	if (err)
		return err;
	access = load_u16be(p + 4);
	if (access < SPP_DIAG_TRACE_FILE_ACCESS_READ ||
	    access > SPP_DIAG_TRACE_FILE_ACCESS_PATH_ONLY)
		return WIRE_STATE;
	modifiers = load_u16be(p + 6);
	if ((modifiers & ~SPP_DIAG_TRACE_FILE_MOD_MASK) != 0)
		return WIRE_FLAGS;
	reserved = load_u32be(p + 12);
	if (reserved != 0)
		return WIRE_RESERVED;
	return check_path_bytes(p + 16, path_len);
}

static int check_file_policy_payload(const u8 *p, size_t n)
{
	u16 access;
	u16 modifiers;
	u16 decision;
	u16 object_kind;
	u32 result;
	u64 inode;
	u64 mount_identity;
	int err;

	(void)n;
	access = load_u16be(p);
	if (access < SPP_DIAG_TRACE_FILE_ACCESS_READ ||
	    access > SPP_DIAG_TRACE_FILE_ACCESS_PATH_ONLY)
		return WIRE_STATE;
	modifiers = load_u16be(p + 2);
	if ((modifiers & ~SPP_DIAG_TRACE_FILE_MOD_MASK) != 0)
		return WIRE_FLAGS;
	decision = load_u16be(p + 4);
	if (decision != SPP_DIAG_TRACE_POLICY_ALLOW &&
	    decision != SPP_DIAG_TRACE_POLICY_DENY)
		return WIRE_STATE;
	object_kind = load_u16be(p + 6);
	if (object_kind < SPP_DIAG_TRACE_FILE_OBJECT_REGULAR ||
	    object_kind > SPP_DIAG_TRACE_FILE_OBJECT_OTHER)
		return WIRE_STATE;
	result = load_u32be(p + 8);
	err = check_policy_result(decision, result);
	if (err)
		return err;
	inode = load_u64be(p + 24);
	if (inode == 0)
		return WIRE_VALUE;
	mount_identity = load_u64be(p + 32);
	if (mount_identity == 0)
		return WIRE_VALUE;
	return WIRE_OK;
}

static int check_mapping_payload(const u8 *p, size_t n)
{
	u16 operation;
	u16 decision;
	u16 backing;
	u16 mode;
	u32 requested;
	u32 effective;
	u32 prior;
	u32 result;
	u32 fs_magic;
	u32 dev_major;
	u32 dev_minor;
	u32 seals;
	u64 inode;
	u64 mount_identity;
	u64 observed_size;
	int anonymous;
	int err;

	(void)n;
	operation = load_u16be(p);
	if (operation != SPP_DIAG_TRACE_MAPPING_OPERATION_MMAP &&
	    operation != SPP_DIAG_TRACE_MAPPING_OPERATION_MPROTECT)
		return WIRE_STATE;
	decision = load_u16be(p + 2);
	if (decision != SPP_DIAG_TRACE_POLICY_ALLOW &&
	    decision != SPP_DIAG_TRACE_POLICY_DENY)
		return WIRE_STATE;
	backing = load_u16be(p + 4);
	if (backing < SPP_DIAG_TRACE_MAPPING_BACKING_ANONYMOUS ||
	    backing > SPP_DIAG_TRACE_MAPPING_BACKING_OTHER)
		return WIRE_STATE;
	mode = load_u16be(p + 6);
	if (mode != SPP_DIAG_TRACE_MAPPING_MODE_SHARED &&
	    mode != SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE)
		return WIRE_STATE;
	requested = load_u32be(p + 8);
	if ((requested & ~SPP_DIAG_TRACE_MAPPING_PROT_MASK) != 0)
		return WIRE_FLAGS;
	effective = load_u32be(p + 12);
	if ((effective & ~SPP_DIAG_TRACE_MAPPING_PROT_MASK) != 0)
		return WIRE_FLAGS;
	prior = load_u32be(p + 16);
	if ((prior & ~SPP_DIAG_TRACE_MAPPING_PROT_MASK) != 0)
		return WIRE_FLAGS;
	if ((effective & SPP_DIAG_TRACE_MAPPING_PROT_EXEC) == 0)
		return WIRE_STATE;
	if (operation == SPP_DIAG_TRACE_MAPPING_OPERATION_MMAP && prior != 0)
		return WIRE_STATE;
	result = load_u32be(p + 20);
	err = check_policy_result(decision, result);
	if (err)
		return err;
	anonymous = backing == SPP_DIAG_TRACE_MAPPING_BACKING_ANONYMOUS;
	fs_magic = load_u32be(p + 24);
	if (anonymous && fs_magic != 0)
		return WIRE_VALUE;
	dev_major = load_u32be(p + 28);
	if (anonymous && dev_major != 0)
		return WIRE_VALUE;
	dev_minor = load_u32be(p + 32);
	if (anonymous && dev_minor != 0)
		return WIRE_VALUE;
	seals = load_u32be(p + 36);
	if (backing != SPP_DIAG_TRACE_MAPPING_BACKING_MEMFD && seals != 0)
		return WIRE_FLAGS;
	inode = load_u64be(p + 40);
	if (anonymous) {
		if (inode != 0)
			return WIRE_VALUE;
	} else if (inode == 0) {
		return WIRE_VALUE;
	}
	mount_identity = load_u64be(p + 48);
	if (anonymous) {
		if (mount_identity != 0)
			return WIRE_VALUE;
	} else if (mount_identity == 0) {
		return WIRE_VALUE;
	}
	observed_size = load_u64be(p + 56);
	if (anonymous && observed_size != 0)
		return WIRE_VALUE;
	return WIRE_OK;
}

static int check_network_relation(u16 operation, u16 kind, u16 source,
				  u16 family, u16 addrlen)
{
	int inet = family == SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET;
	int inet6 = family == SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET6;
	int zero = family == 0;
	int other = !zero && !inet && !inet6;

	switch (kind) {
	case SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4:
		if (!inet)
			return WIRE_STATE;
		if (source == SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT)
			return addrlen == 16 ? WIRE_OK : WIRE_STATE;
		return addrlen == 0 ? WIRE_OK : WIRE_STATE;
	case SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV6:
		if (!inet6)
			return WIRE_STATE;
		if (source == SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT)
			return addrlen == 28 ? WIRE_OK : WIRE_STATE;
		return addrlen == 0 ? WIRE_OK : WIRE_STATE;
	case SPP_DIAG_TRACE_NETWORK_ENDPOINT_UNSUPPORTED:
		if (source == SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT) {
			if (inet || inet6)
				return WIRE_STATE;
			return (addrlen >= 2 && addrlen <= 128) ? WIRE_OK
								: WIRE_STATE;
		}
		if (!other)
			return WIRE_STATE;
		return addrlen == 0 ? WIRE_OK : WIRE_STATE;
	case SPP_DIAG_TRACE_NETWORK_ENDPOINT_MALFORMED:
		if (source != SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT)
			return WIRE_STATE;
		if ((addrlen == 0 || addrlen == 1) && zero)
			return WIRE_OK;
		if (inet && addrlen >= 2 && addrlen <= 128 && addrlen != 16)
			return WIRE_OK;
		if (inet6 && addrlen >= 2 && addrlen <= 128 && addrlen != 28)
			return WIRE_OK;
		return WIRE_STATE;
	case SPP_DIAG_TRACE_NETWORK_ENDPOINT_UNRESOLVED:
		if (operation != SPP_DIAG_TRACE_NETWORK_OPERATION_SENDMSG)
			return WIRE_STATE;
		if (source !=
		    SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_CONNECTED)
			return WIRE_STATE;
		if (!zero)
			return WIRE_STATE;
		return addrlen == 0 ? WIRE_OK : WIRE_STATE;
	default:
		return WIRE_STATE;
	}
}

static int check_network_content(const u8 *p, u16 kind)
{
	u16 port;
	u32 scope;
	u32 flow;

	switch (kind) {
	case SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4:
		if (load_u32be(p + 40) != 0)
			return WIRE_VALUE;
		if (load_u32be(p + 44) != 0)
			return WIRE_VALUE;
		return check_zero_bytes(p + 48, 12);
	case SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV6:
		return WIRE_OK;
	case SPP_DIAG_TRACE_NETWORK_ENDPOINT_UNSUPPORTED:
	case SPP_DIAG_TRACE_NETWORK_ENDPOINT_MALFORMED:
	case SPP_DIAG_TRACE_NETWORK_ENDPOINT_UNRESOLVED:
		port = load_u16be(p + 36);
		if (port != 0)
			return WIRE_VALUE;
		scope = load_u32be(p + 40);
		if (scope != 0)
			return WIRE_VALUE;
		flow = load_u32be(p + 44);
		if (flow != 0)
			return WIRE_VALUE;
		return check_zero_bytes(p + 48, 16);
	default:
		return WIRE_STATE;
	}
}

static int check_network_payload(const u8 *p, size_t n)
{
	u16 operation;
	u16 decision;
	u16 kind;
	u16 source;
	u16 socket_kind;
	u16 family;
	u16 addrlen;
	u16 reserved;
	u32 result;
	u32 flags;
	u32 size;
	u64 cookie;
	int err;

	(void)n;
	operation = load_u16be(p);
	if (operation != SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT &&
	    operation != SPP_DIAG_TRACE_NETWORK_OPERATION_SENDMSG)
		return WIRE_STATE;
	decision = load_u16be(p + 2);
	if (decision != SPP_DIAG_TRACE_POLICY_ALLOW &&
	    decision != SPP_DIAG_TRACE_POLICY_DENY)
		return WIRE_STATE;
	kind = load_u16be(p + 4);
	if (kind < SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4 ||
	    kind > SPP_DIAG_TRACE_NETWORK_ENDPOINT_UNRESOLVED)
		return WIRE_STATE;
	source = load_u16be(p + 6);
	if (source != SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT &&
	    source != SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_CONNECTED)
		return WIRE_STATE;
	socket_kind = load_u16be(p + 8);
	if (socket_kind < SPP_DIAG_TRACE_NETWORK_SOCKET_STREAM ||
	    socket_kind > SPP_DIAG_TRACE_NETWORK_SOCKET_OTHER)
		return WIRE_STATE;
	addrlen = load_u16be(p + 14);
	if (addrlen > 128)
		return WIRE_LENGTH;
	cookie = load_u64be(p + 28);
	if (cookie == 0)
		return WIRE_VALUE;
	reserved = load_u16be(p + 38);
	if (reserved != 0)
		return WIRE_RESERVED;
	flags = load_u32be(p + 20);
	size = load_u32be(p + 24);
	if (operation == SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT) {
		if (source != SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT)
			return WIRE_STATE;
		if (flags != 0)
			return WIRE_STATE;
		if (size != 0)
			return WIRE_STATE;
	} else if ((size >> 31) != 0) {
		return WIRE_VALUE;
	}
	result = load_u32be(p + 16);
	err = check_policy_result(decision, result);
	if (err)
		return err;
	family = load_u16be(p + 12);
	err = check_network_relation(operation, kind, source, family, addrlen);
	if (err)
		return err;
	return check_network_content(p, kind);
}

static int check_operation_return_payload(const u8 *p, size_t n)
{
	u16 kind;
	u16 reserved16;
	u32 reserved32;

	(void)n;
	kind = load_u16be(p);
	if (kind < SPP_DIAG_TRACE_OPERATION_FILE_OPEN ||
	    kind > SPP_DIAG_TRACE_OPERATION_EXEC)
		return WIRE_STATE;
	reserved16 = load_u16be(p + 2);
	if (reserved16 != 0)
		return WIRE_RESERVED;
	reserved32 = load_u32be(p + 4);
	if (reserved32 != 0)
		return WIRE_RESERVED;
	return WIRE_OK;
}

static int check_task_exit_payload(const u8 *p, size_t n)
{
	u32 reserved32;

	(void)n;
	reserved32 = load_u32be(p + 4);
	if (reserved32 != 0)
		return WIRE_RESERVED;
	return WIRE_OK;
}

static int check_payload_content(u16 event, u16 phase, const void *payload,
				 size_t n)
{
	const u8 *p = payload;

	switch (event) {
	case SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED:
		return check_pre_release_payload(p, n);
	case SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE:
		return check_userspace_release_payload(p);
	case SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT:
		return check_exec_attempt_payload(p, n);
	case SPP_DIAG_TRACE_EVENT_EXEC_COMMIT:
		return check_exec_commit_payload(p);
	case SPP_DIAG_TRACE_EVENT_TASK_CREATED:
		return check_task_created_payload(p);
	case SPP_DIAG_TRACE_EVENT_PHASE_MARKER:
		return check_phase_marker_payload(p, phase);
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT:
		return check_file_open_payload(p, n);
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION:
		return check_file_policy_payload(p, n);
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_EXEC_MAPPING_POLICY_DECISION:
		return check_mapping_payload(p, n);
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_NETWORK_POLICY_DECISION:
		return check_network_payload(p, n);
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_OPERATION_RETURN:
		return check_operation_return_payload(p, n);
	case SPP_DIAG_TRACE_PROVENANCE_EVENT_TASK_EXIT:
		return check_task_exit_payload(p, n);
	default:
		return WIRE_OK;
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
	err = check_phase(event, flags, phase);
	if (err)
		return err;
	return check_payload_content(event, phase, payload, payload_length);
}

static void clear_unpublished_meta(void)
{
	memset(core.header, 0, sizeof(core.header));
	memset(core.core_init_frame, 0, sizeof(core.core_init_frame));
	memset(core.header_chain, 0, sizeof(core.header_chain));
	memset(core.chain, 0, sizeof(core.chain));
	memset(core.last_frame, 0, sizeof(core.last_frame));
	core.last_frame_len = 0;
	core.frame_count = 0;
	core.stream_byte_count = 0;
	core.sequence = 0;
	core.stream = NULL;
	core.stream_cap = 0;
	core.stream_len = 0;
	core.bootstrap_denial_count = 0;
	core.bootstrap_stage = SPP_DIAG_TRACE_BOOTSTRAP_NONE;
	core.bootstrap_released = 0;
}

int spp_diag_trace_core_init(const u8 challenge[32],
			     const u8 run_identity[32],
			     const u8 control_plan_address[32],
			     const u8 command_line_sha256[32])
{
	unsigned long flags;
	u8 header[SPP_DIAG_TRACE_HEADER_SIZE];
	u8 core_init[SPP_DIAG_TRACE_FRAME_HEADER_SIZE];
	u8 header_chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u8 chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u8 *buf = NULL;
	size_t cap;
	u64 prefix_bytes = 0;
	int err;
	int init_fault = 0;
	u64 a, b, c, ab, abc;

	if (challenge == NULL || run_identity == NULL ||
	    control_plan_address == NULL || command_line_sha256 == NULL) {
		run_barrier();
		spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
		if (core.initialized)
			err = fail_sticky(WIRE_STATE);
		else
			err = fail_sticky(WIRE_NULL);
		spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
		return err;
	}

	/*
	 * Cap is test-single-threaded setup via set_op_caps; read without the
	 * publication lock so vmalloc stays outside the critical section.
	 */
	cap = core.max_stream_bytes_op;
#if IS_ENABLED(CONFIG_KUNIT)
	init_fault = core.init_fault;
	core.init_fault = 0;
#endif

	if (init_fault ==
#if IS_ENABLED(CONFIG_KUNIT)
	    SPP_DIAG_TRACE_CORE_INIT_FAULT_ALLOCATION
#else
	    -1
#endif
	) {
		buf = NULL;
	} else {
		/* Process-context: real kernel vmalloc() calls might_sleep(). */
		buf = vmalloc(cap);
	}
	if (buf == NULL) {
		err = WIRE_CAP;
		goto fail_prelock;
	}

	encode_header(header, challenge, run_identity, control_plan_address,
		      command_line_sha256);
	encode_frame(core_init, SPP_DIAG_TRACE_EVENT_CORE_INIT, 0, 0, 0, 0, 0, 0,
		     SPP_DIAG_TRACE_PHASE_PRE_RELEASE, NULL);
	hash_header_preimage(header, header_chain);
	hash_frame_preimage(header_chain, core_init,
			    SPP_DIAG_TRACE_FRAME_HEADER_SIZE, chain);

#if IS_ENABLED(CONFIG_KUNIT)
	if (init_fault == SPP_DIAG_TRACE_CORE_INIT_FAULT_HEADER_ENCODING)
		header[0] ^= 0xffu;
	if (init_fault == SPP_DIAG_TRACE_CORE_INIT_FAULT_HEADER_INVARIANT)
		store_u32be(header + 188, 1);
	if (init_fault == SPP_DIAG_TRACE_CORE_INIT_FAULT_CORE_INIT_ENCODING)
		store_u32be(core_init + 4, 1);
	if (init_fault == SPP_DIAG_TRACE_CORE_INIT_FAULT_CORE_INIT_INVARIANT)
		store_u64be(core_init + 8, 1);
#endif

	if (memcmp(header, k_magic_header, 8) != 0) {
		err = WIRE_MAGIC;
		goto fail_prelock;
	}
	if (load_u32be(header + 188) != 0) {
		err = WIRE_RESERVED;
		goto fail_prelock;
	}
	if (load_u32be(core_init + 4) != 0) {
		err = WIRE_LENGTH;
		goto fail_prelock;
	}
	if (load_u64be(core_init + 8) != 0) {
		err = WIRE_SEQUENCE;
		goto fail_prelock;
	}

	a = SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE;
	b = SPP_DIAG_TRACE_STREAM_PREFIX_SIZE;
	c = SPP_DIAG_TRACE_FRAME_HEADER_SIZE;
#if IS_ENABLED(CONFIG_KUNIT)
	if (init_fault == SPP_DIAG_TRACE_CORE_INIT_FAULT_INITIAL_ARITHMETIC)
		a = ~0ull;
#endif
	if (add_u64(a, b, &ab) != WIRE_OK || add_u64(ab, c, &abc) != WIRE_OK ||
	    abc != (u64)SPP_DIAG_TRACE_STREAM_HEADER_ENTRY_SIZE +
			   (u64)SPP_DIAG_TRACE_STREAM_PREFIX_SIZE +
			   (u64)SPP_DIAG_TRACE_FRAME_HEADER_SIZE) {
		err = WIRE_ARITHMETIC;
		goto fail_prelock;
	}
	prefix_bytes = abc;

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = sticky_or_fault();
	if (err)
		goto fail_locked;
	if (core.initialized) {
		err = fail_sticky(WIRE_STATE);
		goto fail_locked;
	}

	store_u32be(buf, SPP_DIAG_TRACE_HEADER_SIZE);
	memcpy(buf + 4, header, SPP_DIAG_TRACE_HEADER_SIZE);
	store_u32be(buf + 4 + SPP_DIAG_TRACE_HEADER_SIZE,
		    SPP_DIAG_TRACE_FRAME_HEADER_SIZE);
	memcpy(buf + 4 + SPP_DIAG_TRACE_HEADER_SIZE + 4, core_init,
	       SPP_DIAG_TRACE_FRAME_HEADER_SIZE);

	memcpy(core.header, header, SPP_DIAG_TRACE_HEADER_SIZE);
	memcpy(core.core_init_frame, core_init, SPP_DIAG_TRACE_FRAME_HEADER_SIZE);
	memcpy(core.header_chain, header_chain, SPP_DIAG_TRACE_CHAIN_LEN);
	memcpy(core.chain, chain, SPP_DIAG_TRACE_CHAIN_LEN);
	memcpy(core.last_frame, core_init, SPP_DIAG_TRACE_FRAME_HEADER_SIZE);
	core.last_frame_len = SPP_DIAG_TRACE_FRAME_HEADER_SIZE;
	core.stream = buf;
	core.stream_cap = cap;
	core.stream_len = (size_t)prefix_bytes;
	core.frame_count = 1;
	core.stream_byte_count = prefix_bytes;
	core.sequence = 1;
	core.bootstrap_denial_count = 0;
	core.bootstrap_stage = SPP_DIAG_TRACE_BOOTSTRAP_CORE_READY;
	core.bootstrap_released = 0;

#if IS_ENABLED(CONFIG_KUNIT)
	if (init_fault == SPP_DIAG_TRACE_CORE_INIT_FAULT_PRE_PUBLICATION)
		core.frame_count = 0;
#endif
	if (core.frame_count != 1 || core.stream_byte_count != prefix_bytes) {
		clear_unpublished_meta();
		err = fail_sticky(WIRE_STATE);
		goto fail_locked;
	}

	core.initialized = 1;
	core.failed = 0;
	core.reason = 0;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return WIRE_OK;

fail_prelock:
	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = fail_sticky(err);
fail_locked:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	vfree(buf);
	return err;
}

int spp_diag_trace_core_is_green(void)
{
	unsigned long flags;
	int green;

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	green = core.initialized && !core.failed;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return green;
}

static int append_locked(u16 event_type, u16 flags, u64 task_ordinal,
			 u64 parent_task_ordinal, u64 operation_ordinal,
			 u16 phase, const void *payload, size_t payload_length,
			 int field_err)
{
	u8 frame[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
	u8 next_chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u32 frame_len;
	u64 prefix_plus_frame;
	u64 next_bytes;
	int err;

	err = sticky_or_fault();
	if (err)
		return err;
	if (!core.initialized) {
		err = fail_sticky(WIRE_STATE);
		return err;
	}
	if (field_err) {
		err = fail_sticky(field_err);
		return err;
	}
	if (payload_length >
	    (size_t)(~0u - SPP_DIAG_TRACE_FRAME_HEADER_SIZE)) {
		err = fail_sticky(WIRE_ARITHMETIC);
		return err;
	}
	frame_len = SPP_DIAG_TRACE_FRAME_HEADER_SIZE + (u32)payload_length;
	if (core.frame_count >= core.max_frames_op) {
		err = fail_sticky(WIRE_CAP);
		return err;
	}
	if (add_u64(SPP_DIAG_TRACE_STREAM_PREFIX_SIZE, frame_len,
		    &prefix_plus_frame) != WIRE_OK ||
	    add_u64(core.stream_byte_count, prefix_plus_frame, &next_bytes) !=
		    WIRE_OK) {
		err = fail_sticky(WIRE_ARITHMETIC);
		return err;
	}
	if (next_bytes > core.max_stream_bytes_op) {
		err = fail_sticky(WIRE_CAP);
		return err;
	}

	encode_frame(frame, event_type, flags, (u32)payload_length,
		     core.sequence, task_ordinal, parent_task_ordinal,
		     operation_ordinal, phase, payload);
	hash_frame_preimage(core.chain, frame, frame_len, next_chain);
	store_u32be(core.stream + core.stream_len, frame_len);
	memcpy(core.stream + core.stream_len + 4, frame, frame_len);
	core.stream_len += 4u + frame_len;
	memcpy(core.chain, next_chain, SPP_DIAG_TRACE_CHAIN_LEN);
	memcpy(core.last_frame, frame, frame_len);
	core.last_frame_len = frame_len;
	core.frame_count += 1;
	core.stream_byte_count = next_bytes;
	core.sequence += 1;
	return WIRE_OK;
}

#if !IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME) || IS_ENABLED(CONFIG_KUNIT)
int spp_diag_trace_core_append(u16 event_type, u16 flags, u64 task_ordinal,
			       u64 parent_task_ordinal, u64 operation_ordinal,
			       u16 phase, const void *payload,
			       size_t payload_length)
{
	unsigned long irqflags;
	u8 payload_copy[SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES];
	const void *payload_src = NULL;
	int field_err;
	int err;

	if (payload == NULL && payload_length > 0)
		field_err = WIRE_NULL;
	else if (payload_length > SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES)
		field_err = WIRE_CAP;
	else {
		if (payload_length && payload != NULL) {
			memcpy(payload_copy, payload, payload_length);
			payload_src = payload_copy;
		}
		field_err = check_append_fields(event_type, flags, task_ordinal,
						parent_task_ordinal,
						operation_ordinal, phase,
						payload_src, payload_length);
	}

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, irqflags);
	err = append_locked(event_type, flags, task_ordinal, parent_task_ordinal,
			    operation_ordinal, phase, payload_src, payload_length,
			    field_err);
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, irqflags);
	return err;
}
#endif

#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP)
static void encode_bootstrap_record_locked(u16 kind, u8 out[256])
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
	memcpy(out + 24, core.header + 32, SPP_DIAG_TRACE_SOURCE_COMMIT_LEN);
	memcpy(out + 44, core.header + 52, 32);
	memcpy(out + 76, core.header + 84, 32);
	memcpy(out + 108, core.header + 116, 32);
	memcpy(out + 140, core.header + 148, 32);
	store_u64be(out + 172, core.frame_count);
	store_u64be(out + 180, core.stream_byte_count);
	memcpy(out + 188, core.chain, SPP_DIAG_TRACE_CHAIN_LEN);
	store_u64be(out + 228, SPP_DIAG_TRACE_HOOK_MASK_PROVENANCE);
	store_u64be(out + 236, core.bootstrap_denial_count);
}

int spp_diag_trace_core_bootstrap_ima_available(void)
{
	unsigned long flags;
	int err;

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = sticky_or_fault();
	if (!err && (!core.initialized ||
		     core.bootstrap_stage != SPP_DIAG_TRACE_BOOTSTRAP_CORE_READY))
		err = fail_sticky(WIRE_STATE);
	if (!err)
		core.bootstrap_stage = SPP_DIAG_TRACE_BOOTSTRAP_IMA_AVAILABLE;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_bootstrap_gate(const char *path, size_t path_length,
				       u32 pid, u32 tgid)
{
	static const char canary[] = SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH;
	unsigned long flags;
	u8 payload[20 + sizeof(canary) - 1];
	u8 path_copy[sizeof(canary) - 1];
	int field_err = WIRE_OK;
	int err;

	if (!path)
		field_err = WIRE_NULL;
	else if (!path_length)
		field_err = WIRE_LENGTH;
	else if (path_length != sizeof(path_copy))
		field_err = WIRE_STATE;
	else
		memcpy(path_copy, path, path_length);

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = sticky_or_fault();
	if (err)
		goto deny;
	if (core.bootstrap_released &&
	    core.bootstrap_stage == SPP_DIAG_TRACE_BOOTSTRAP_RELEASED) {
		spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
		return 0;
	}
	if (!core.initialized || core.bootstrap_released ||
	    core.bootstrap_stage != SPP_DIAG_TRACE_BOOTSTRAP_IMA_AVAILABLE ||
	    core.bootstrap_denial_count != 0 || field_err || pid == 0 || tgid == 0 ||
	    path_length != sizeof(canary) - 1 ||
	    memcmp(path_copy, canary, sizeof(canary) - 1)) {
		fail_sticky(field_err ? field_err : WIRE_STATE);
		goto deny;
	}

	store_u16be(payload, 13);
	store_u16be(payload + 2, (u16)path_length);
	store_u32be(payload + 4, pid);
	store_u32be(payload + 8, tgid);
	memset(payload + 12, 0, 8);
	memcpy(payload + 20, path_copy, path_length);
	field_err = check_append_fields(
		SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED, 0, 0, 0, 1,
		SPP_DIAG_TRACE_PHASE_PRE_RELEASE, payload, 20 + path_length);
	err = append_locked(SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED, 0, 0, 0,
			    1, SPP_DIAG_TRACE_PHASE_PRE_RELEASE, payload,
			    20 + path_length, field_err);
	if (!err) {
		core.bootstrap_denial_count = 1;
		core.bootstrap_stage = SPP_DIAG_TRACE_BOOTSTRAP_DENIED;
	}

deny:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return -EACCES;
}

int spp_diag_trace_core_bootstrap_prepare_ready(u8 record[256])
{
	unsigned long flags;
	u8 payload[8];
	int field_err;
	int err;

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = sticky_or_fault();
	if (!err && (!record || !core.initialized || core.bootstrap_released ||
		     core.bootstrap_stage != SPP_DIAG_TRACE_BOOTSTRAP_DENIED ||
		     core.bootstrap_denial_count != 1))
		err = fail_sticky(record ? WIRE_STATE : WIRE_NULL);
	if (!err) {
		store_u64be(payload, core.bootstrap_denial_count);
		field_err = check_append_fields(
			SPP_DIAG_TRACE_EVENT_IMA_READY, 0, 0, 0, 0,
			SPP_DIAG_TRACE_PHASE_PRE_RELEASE, payload, sizeof(payload));
		err = append_locked(SPP_DIAG_TRACE_EVENT_IMA_READY, 0, 0, 0, 0,
				    SPP_DIAG_TRACE_PHASE_PRE_RELEASE, payload,
				    sizeof(payload), field_err);
	}
	if (!err) {
		core.bootstrap_stage = SPP_DIAG_TRACE_BOOTSTRAP_READY_APPENDED;
		encode_bootstrap_record_locked(SPP_DIAG_TRACE_IMA_KIND_READY,
					       record);
	}
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_bootstrap_ready_measured(void)
{
	unsigned long flags;
	int err;

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = sticky_or_fault();
	if (!err && (core.bootstrap_stage !=
			     SPP_DIAG_TRACE_BOOTSTRAP_READY_APPENDED ||
		     core.bootstrap_denial_count != 1 || core.bootstrap_released))
		err = fail_sticky(WIRE_STATE);
	if (!err)
		core.bootstrap_stage = SPP_DIAG_TRACE_BOOTSTRAP_READY_MEASURED;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_bootstrap_prepare_release(u32 pid, u32 tgid,
					  u8 record[256])
{
	unsigned long flags;
	u8 payload[16];
	int field_err;
	int err;

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = sticky_or_fault();
	if (!err && (!record || pid != 1 || tgid != 1 ||
		     core.bootstrap_stage !=
			     SPP_DIAG_TRACE_BOOTSTRAP_READY_MEASURED ||
		     core.bootstrap_denial_count != 1 || core.bootstrap_released))
		err = fail_sticky(record ? WIRE_STATE : WIRE_NULL);
	if (!err) {
		store_u32be(payload, pid);
		store_u32be(payload + 4, tgid);
		store_u64be(payload + 8, core.bootstrap_denial_count);
		field_err = check_append_fields(
			SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE, 0, 1, 0, 0,
			SPP_DIAG_TRACE_PHASE_PRE_RELEASE, payload, sizeof(payload));
		err = append_locked(SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE, 0, 1, 0,
				    0, SPP_DIAG_TRACE_PHASE_PRE_RELEASE, payload,
				    sizeof(payload), field_err);
	}
	if (!err) {
		core.bootstrap_stage = SPP_DIAG_TRACE_BOOTSTRAP_RELEASE_APPENDED;
		encode_bootstrap_record_locked(SPP_DIAG_TRACE_IMA_KIND_RELEASED,
					       record);
	}
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_bootstrap_release_measured(void)
{
	unsigned long flags;
	int err;

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = sticky_or_fault();
	if (!err && (core.bootstrap_stage !=
			     SPP_DIAG_TRACE_BOOTSTRAP_RELEASE_APPENDED ||
		     core.bootstrap_denial_count != 1 || core.bootstrap_released))
		err = fail_sticky(WIRE_STATE);
	if (!err)
		core.bootstrap_stage = SPP_DIAG_TRACE_BOOTSTRAP_RELEASE_MEASURED;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_bootstrap_publish(void)
{
	unsigned long flags;
	int err;

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = sticky_or_fault();
	if (!err && (core.bootstrap_stage !=
			     SPP_DIAG_TRACE_BOOTSTRAP_RELEASE_MEASURED ||
		     core.bootstrap_denial_count != 1 || core.bootstrap_released))
		err = fail_sticky(WIRE_STATE);
	if (!err) {
		core.bootstrap_released = 1;
		core.bootstrap_stage = SPP_DIAG_TRACE_BOOTSTRAP_RELEASED;
	}
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}
#endif

#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
int spp_diag_trace_core_runtime_install_arrays(
	struct spp_diag_trace_task_record *tasks, size_t task_cap,
	struct spp_diag_trace_operation_record *ops, size_t op_cap)
{
	unsigned long flags;
	int err = 0;

	if (!tasks || !ops || !task_cap || !op_cap)
		return WIRE_NULL;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	if (core.failed) {
		err = fail_sticky(core.reason ? core.reason : WIRE_STATE);
		goto out;
	}
	if (core.runtime_ready || core.runtime_tasks || core.runtime_ops) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	core.runtime_tasks = tasks;
	core.runtime_task_cap = task_cap;
	core.runtime_ops = ops;
	core.runtime_op_cap = op_cap;
	core.runtime_next_task_ordinal = 1;
	core.runtime_next_op_ordinal = 2;
	core.runtime_next_exec_reservation_token = 1;
	core.runtime_phase = SPP_DIAG_TRACE_PHASE_PRE_RELEASE;
	core.runtime_ready = 1;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

bool spp_diag_trace_core_runtime_is_ready(void)
{
	unsigned long flags;
	bool ready;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	ready = (core.runtime_ready && !core.failed);
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return ready;
}

static struct spp_diag_trace_task_record *
spp_diag_trace_core_runtime_find_task_locked(const void *task_token)
{
	size_t i;

	if (!task_token || !core.runtime_tasks)
		return NULL;
	for (i = 0; i < core.runtime_task_cap; i++) {
		if (core.runtime_tasks[i].task_token == task_token &&
		    (core.runtime_tasks[i].flags & SPP_DIAG_TRACE_TASK_FLAG_LIVE))
			return &core.runtime_tasks[i];
	}
	return NULL;
}

static int
spp_diag_trace_core_runtime_open_op_locked(struct spp_diag_trace_task_record *task,
					  u16 kind,
					  struct spp_diag_trace_operation_record **out_op)
{
	size_t j;
	u64 slot;
	u64 op_ordinal;
	struct spp_diag_trace_operation_record *op;

	if (core.failed)
		return core.reason ? core.reason : WIRE_STATE;
	if (!task || !(task->flags & SPP_DIAG_TRACE_TASK_FLAG_LIVE))
		return fail_sticky(WIRE_STATE);

	for (j = 0; j < core.runtime_op_cap; j++) {
		if (core.runtime_ops[j].task_ordinal == task->task_ordinal &&
		    core.runtime_ops[j].kind == kind &&
		    (core.runtime_ops[j].state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN ||
		     core.runtime_ops[j].state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_COMMITTED))
			return fail_sticky(WIRE_STATE);
	}

	slot = core.runtime_next_op_ordinal - 2;
	if (slot >= core.runtime_op_cap)
		return fail_sticky(WIRE_CAP);

	op_ordinal = core.runtime_next_op_ordinal++;
	op = &core.runtime_ops[slot];
	memset(op, 0, sizeof(*op));
	op->operation_ordinal = op_ordinal;
	op->task_ordinal = task->task_ordinal;
	op->kind = kind;
	op->phase = core.runtime_phase;
	op->state = SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN;
	task->open_op_count++;
	*out_op = op;
	return WIRE_OK;
}

static int spp_diag_trace_core_runtime_interval_status_locked(void)
{
	if (core.runtime_sealed)
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (core.runtime_sealing)
		return fail_sticky(WIRE_STATE);
	if (core.failed)
		return fail_sticky(core.reason ? core.reason : WIRE_STATE);
	if (core.runtime_phase < SPP_DIAG_TRACE_PHASE_INIT)
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (core.runtime_phase > SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE)
		return fail_sticky(WIRE_STATE);
	return WIRE_OK;
}

static int spp_diag_trace_core_runtime_find_active_op_locked(
	struct spp_diag_trace_task_record *task, u16 kind, bool allow_committed,
	struct spp_diag_trace_operation_record **out_op)
{
	size_t j;

	if (!task || !out_op)
		return fail_sticky(WIRE_STATE);

	for (j = 0; j < core.runtime_op_cap; j++) {
		struct spp_diag_trace_operation_record *op = &core.runtime_ops[j];

		if (op->task_ordinal != task->task_ordinal || op->kind != kind)
			continue;
		if (op->state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN ||
		    (allow_committed &&
		     op->state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_COMMITTED)) {
			*out_op = op;
			return WIRE_OK;
		}
	}
	return -ENOENT;
}

#if IS_ENABLED(CONFIG_KUNIT)
int spp_diag_trace_core_runtime_open_operation(u64 task_ordinal, u16 kind, u64 *out_op_ordinal)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op = NULL;

	if (!out_op_ordinal || kind == SPP_DIAG_TRACE_RUNTIME_OP_NONE || kind > SPP_DIAG_TRACE_RUNTIME_OP_KINDS)
		return fail_sticky(WIRE_STATE);

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	if (core.failed) {
		err = fail_sticky(core.reason ? core.reason : WIRE_STATE);
		goto out;
	}
	if (task_ordinal < 1 || task_ordinal >= core.runtime_next_task_ordinal ||
	    task_ordinal - 1 >= core.runtime_task_cap) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	task = &core.runtime_tasks[task_ordinal - 1];
	if (task->task_ordinal != task_ordinal || !(task->flags & SPP_DIAG_TRACE_TASK_FLAG_LIVE)) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	err = spp_diag_trace_core_runtime_open_op_locked(task, kind, &op);
	if (err == 0 && op)
		*out_op_ordinal = op->operation_ordinal;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_close_operation(u64 task_ordinal, u64 op_ordinal, u16 kind)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op;
	u64 op_slot;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	if (core.failed) {
		err = fail_sticky(core.reason ? core.reason : WIRE_STATE);
		goto out;
	}
	if (task_ordinal < 1 || task_ordinal >= core.runtime_next_task_ordinal ||
	    task_ordinal - 1 >= core.runtime_task_cap) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	task = &core.runtime_tasks[task_ordinal - 1];
	if (task->task_ordinal != task_ordinal || !(task->flags & SPP_DIAG_TRACE_TASK_FLAG_LIVE)) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	if (op_ordinal < 2 || op_ordinal >= core.runtime_next_op_ordinal) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	op_slot = op_ordinal - 2;
	if (op_slot >= core.runtime_op_cap) {
		err = fail_sticky(WIRE_CAP);
		goto out;
	}
	op = &core.runtime_ops[op_slot];
	if (op->operation_ordinal != op_ordinal || op->task_ordinal != task_ordinal ||
	    op->kind != kind || (op->state != SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN &&
				 op->state != SPP_DIAG_TRACE_RUNTIME_OP_STATE_COMMITTED)) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	op->state = SPP_DIAG_TRACE_RUNTIME_OP_STATE_CLOSED;
	if (task->open_op_count > 0)
		task->open_op_count--;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}
#endif

int spp_diag_trace_core_runtime_bind_root(const void *task_token)
{
	unsigned long flags;
	int err = 0;
	struct spp_diag_trace_task_record *root;

	if (!task_token)
		return WIRE_NULL;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	if (core.runtime_sealed) {
		err = SPP_DIAG_TRACE_ERR_INACTIVE;
		goto out;
	}
	if (core.runtime_sealing) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	if (core.failed) {
		err = fail_sticky(core.reason ? core.reason : WIRE_STATE);
		goto out;
	}
	if (!core.initialized || !core.bootstrap_released || !core.runtime_ready ||
	    !core.runtime_tasks || core.runtime_phase != SPP_DIAG_TRACE_PHASE_PRE_RELEASE) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	root = &core.runtime_tasks[0];
	memset(root, 0, sizeof(*root));
	root->task_token = task_token;
	root->task_ordinal = 1;
	root->parent_task_ordinal = 0;
	root->pid = 1;
	root->tgid = 1;
	root->mint_phase = SPP_DIAG_TRACE_PHASE_INIT;
	root->flags = SPP_DIAG_TRACE_TASK_FLAG_LIVE;
	root->creation_sequence = 0;
	root->exit_sequence = 0;
	root->exit_code = 0;
	root->open_op_count = 0;

	core.runtime_next_task_ordinal = 2;
	core.runtime_phase = SPP_DIAG_TRACE_PHASE_INIT;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_task_alloc_attempt(
	const void *parent_token, u64 clone_flags)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *parent;
	struct spp_diag_trace_task_record *child;
	struct spp_diag_trace_operation_record *op = NULL;
	int field_err;
	u64 child_slot;
	u64 child_task_ordinal;
	u8 payload[8];

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;

	parent = spp_diag_trace_core_runtime_find_task_locked(parent_token);
	if (!parent) {
		const struct task_struct *parent_ts = parent_token;
		if (parent_ts && (parent_ts->flags & PF_KTHREAD))
			goto out;
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	child_slot = core.runtime_next_task_ordinal - 1;
	if (child_slot >= core.runtime_task_cap) {
		err = fail_sticky(WIRE_CAP);
		goto out;
	}

	err = spp_diag_trace_core_runtime_open_op_locked(
		parent, SPP_DIAG_TRACE_RUNTIME_OP_TASK_ALLOC, &op);
	if (err)
		goto out;

	child_task_ordinal = core.runtime_next_task_ordinal++;
	op->child_task_ordinal = child_task_ordinal;

	child = &core.runtime_tasks[child_slot];
	memset(child, 0, sizeof(*child));
	child->task_ordinal = child_task_ordinal;
	child->parent_task_ordinal = parent->task_ordinal;
	child->mint_phase = core.runtime_phase;
	child->flags = 0;

	store_u64be(payload, clone_flags);
	field_err = check_append_fields(
		SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT, 0,
		child_task_ordinal, parent->task_ordinal,
		op->operation_ordinal, core.runtime_phase,
		payload, sizeof(payload));
	err = append_locked(SPP_DIAG_TRACE_EVENT_TASK_ALLOC_ATTEMPT, 0,
			    child_task_ordinal, parent->task_ordinal,
			    op->operation_ordinal, core.runtime_phase,
			    payload, sizeof(payload), field_err);

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_task_created(
	const void *parent_token, const void *child_token,
	u32 pid, u32 tgid, u64 clone_flags)
{
	unsigned long flags;
	int err = WIRE_OK;
	int field_err;
	struct spp_diag_trace_task_record *parent;
	struct spp_diag_trace_task_record *child;
	struct spp_diag_trace_operation_record *op = NULL;
	const struct task_struct *parent_ts = parent_token;
	const struct task_struct *child_ts = child_token;
	size_t j;
	u64 child_slot;
	u8 payload[16];

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;

	parent = spp_diag_trace_core_runtime_find_task_locked(parent_token);
	if (!parent) {
		if (parent_ts && child_ts &&
		    (parent_ts->flags & PF_KTHREAD) &&
		    (child_ts->flags & PF_KTHREAD))
			goto out;
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	if (child_ts && (child_ts->flags & PF_KTHREAD)) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	for (j = 0; j < core.runtime_op_cap; j++) {
		if (core.runtime_ops[j].task_ordinal == parent->task_ordinal &&
		    core.runtime_ops[j].kind == SPP_DIAG_TRACE_RUNTIME_OP_TASK_ALLOC &&
		    core.runtime_ops[j].state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN) {
			op = &core.runtime_ops[j];
			break;
		}
	}
	if (!op) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	child_slot = op->child_task_ordinal - 1;
	if (child_slot >= core.runtime_task_cap) {
		err = fail_sticky(WIRE_CAP);
		goto out;
	}
	child = &core.runtime_tasks[child_slot];
	if (child->task_ordinal != op->child_task_ordinal ||
	    child->parent_task_ordinal != parent->task_ordinal ||
	    child->flags != 0) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	child->task_token = child_token;
	child->pid = pid;
	child->tgid = tgid;
	child->flags = SPP_DIAG_TRACE_TASK_FLAG_LIVE;
	child->creation_sequence = core.sequence + 1;

	op->state = SPP_DIAG_TRACE_RUNTIME_OP_STATE_CLOSED;
	if (parent->open_op_count > 0)
		parent->open_op_count--;

	store_u32be(payload, pid);
	store_u32be(payload + 4, tgid);
	store_u64be(payload + 8, clone_flags);

	field_err = check_append_fields(
		SPP_DIAG_TRACE_EVENT_TASK_CREATED, 0,
		child->task_ordinal, parent->task_ordinal,
		op->operation_ordinal, core.runtime_phase,
		payload, sizeof(payload));
	err = append_locked(SPP_DIAG_TRACE_EVENT_TASK_CREATED, 0,
			    child->task_ordinal, parent->task_ordinal,
			    op->operation_ordinal, core.runtime_phase,
			    payload, sizeof(payload), field_err);

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_task_exit(
	const void *task_token, u32 exit_code)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	const struct task_struct *ts = task_token;
	int field_err;
	u8 payload[8];

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;

	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		if (ts && (ts->flags & PF_KTHREAD))
			goto out;
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	if (task->open_op_count != 0 || task->exec_reservation_token) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	task->flags = SPP_DIAG_TRACE_TASK_FLAG_EXITED;
	task->exit_code = exit_code;
	task->exit_sequence = core.sequence + 1;

	store_u32be(payload, exit_code);
	store_u32be(payload + 4, 0);

	field_err = check_append_fields(
		SPP_DIAG_TRACE_PROVENANCE_EVENT_TASK_EXIT, 0,
		task->task_ordinal, task->parent_task_ordinal,
		0, core.runtime_phase, payload, sizeof(payload));
	err = append_locked(SPP_DIAG_TRACE_PROVENANCE_EVENT_TASK_EXIT, 0,
			    task->task_ordinal, task->parent_task_ordinal,
			    0, core.runtime_phase, payload, sizeof(payload), field_err);

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

static int spp_diag_trace_core_runtime_append_exec_attempt_locked(
	struct spp_diag_trace_task_record *task,
	struct spp_diag_trace_operation_record *op, const char *local_path,
	size_t path_len, u32 pid, u32 tgid)
{
	int field_err;
	u8 payload[16 + SPP_DIAG_TRACE_MAX_PATH_BYTES];

	op->pass_count++;
	op->last_sequence = core.sequence + 1;

	store_u32be(payload, op->pass_count);
	store_u16be(payload + 4, (u16)path_len);
	store_u16be(payload + 6, 0);
	store_u32be(payload + 8, pid);
	store_u32be(payload + 12, tgid);
	memcpy(payload + 16, local_path, path_len);

	field_err = check_append_fields(
		SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT, 0,
		task->task_ordinal, 0, op->operation_ordinal,
		core.runtime_phase, payload, 16 + path_len);
	return append_locked(SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT, 0,
			     task->task_ordinal, 0, op->operation_ordinal,
			     core.runtime_phase, payload, 16 + path_len, field_err);
}

int spp_diag_trace_core_runtime_exec_attempt(
	const void *task_token, const char *local_path, size_t path_len,
	u32 pid, u32 tgid)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op = NULL;
	size_t j;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;

	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	for (j = 0; j < core.runtime_op_cap; j++) {
		if (core.runtime_ops[j].task_ordinal == task->task_ordinal &&
			core.runtime_ops[j].kind == SPP_DIAG_TRACE_RUNTIME_OP_EXEC &&
			core.runtime_ops[j].state != SPP_DIAG_TRACE_RUNTIME_OP_STATE_FREE &&
			core.runtime_ops[j].state != SPP_DIAG_TRACE_RUNTIME_OP_STATE_CLOSED) {
			op = &core.runtime_ops[j];
			break;
		}
	}

	if (!op) {
		err = spp_diag_trace_core_runtime_open_op_locked(
			task, SPP_DIAG_TRACE_RUNTIME_OP_EXEC, &op);
		if (err)
			goto out;
		op->first_sequence = core.sequence + 1;
	} else if (op->state != SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	err = spp_diag_trace_core_runtime_append_exec_attempt_locked(
		task, op, local_path, path_len, pid, tgid);

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_exec_reserve(
	const void *task_token, const char *local_path, size_t path_len,
	u32 pid, u32 tgid, u32 *out_reservation_token)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op = NULL;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	if (!out_reservation_token) {
		err = fail_sticky(WIRE_NULL);
		goto out;
	}

	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	if (task->exec_reservation_token) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	err = spp_diag_trace_core_runtime_find_active_op_locked(
		task, SPP_DIAG_TRACE_RUNTIME_OP_EXEC, true, &op);
	if (!err) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	if (err != -ENOENT)
		goto out;
	if (!core.runtime_next_exec_reservation_token) {
		err = fail_sticky(WIRE_CAP);
		goto out;
	}
	task->exec_reservation_token = core.runtime_next_exec_reservation_token++;
	*out_reservation_token = task->exec_reservation_token;
	(void)local_path;
	(void)path_len;
	(void)pid;
	(void)tgid;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_exec_pass(
	const void *task_token, const char *local_path, size_t path_len,
	u32 pid, u32 tgid)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	err = spp_diag_trace_core_runtime_find_active_op_locked(
		task, SPP_DIAG_TRACE_RUNTIME_OP_EXEC, false, &op);
	if (err == -ENOENT) {
		if (!task->exec_reservation_token) {
			err = fail_sticky(WIRE_STATE);
			goto out;
		}
		err = spp_diag_trace_core_runtime_open_op_locked(
			task, SPP_DIAG_TRACE_RUNTIME_OP_EXEC, &op);
		if (err)
			goto out;
		op->reservation_token = task->exec_reservation_token;
		task->exec_reservation_token = 0;
		op->first_sequence = core.sequence + 1;
	}
	if (err)
		goto out;
	err = spp_diag_trace_core_runtime_append_exec_attempt_locked(
		task, op, local_path, path_len, pid, tgid);

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_exec_active_operation(
	const void *task_token, u64 *out_op_ordinal)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	if (!out_op_ordinal) {
		err = fail_sticky(WIRE_NULL);
		goto out;
	}
	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	if (task->exec_reservation_token) {
		*out_op_ordinal = 0;
		goto out;
	}
	err = spp_diag_trace_core_runtime_find_active_op_locked(
		task, SPP_DIAG_TRACE_RUNTIME_OP_EXEC, true, &op);
	if (!err)
		*out_op_ordinal = op->operation_ordinal;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_exec_return(
	const void *task_token, u32 reservation_token, s64 result)
{
	unsigned long flags;
	int err = WIRE_OK;
	u64 op_ordinal = 0;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	if (!reservation_token) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	if (task->exec_reservation_token) {
		if (task->exec_reservation_token != reservation_token) {
			err = fail_sticky(WIRE_STATE);
			goto out;
		}
		task->exec_reservation_token = 0;
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	err = spp_diag_trace_core_runtime_find_active_op_locked(
		task, SPP_DIAG_TRACE_RUNTIME_OP_EXEC, true, &op);
	if (err == -ENOENT)
		err = fail_sticky(WIRE_STATE);
	if (err)
		goto out;
	if (reservation_token == 0 || op->reservation_token != reservation_token) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	op_ordinal = op->operation_ordinal;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	if (err)
		return err;
	return spp_diag_trace_core_runtime_operation_return(task_token, op_ordinal,
							      result);
}

int spp_diag_trace_core_runtime_exec_unsupported(const void *task_token)
{
	unsigned long flags;
	int err = WIRE_OK;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	(void)task_token;
	fail_sticky(WIRE_STATE);
	err = -EIO;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_exec_commit(
	const void *task_token, u32 pid, u32 tgid)
{
	unsigned long flags;
	int err = WIRE_OK;
	int field_err;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op = NULL;
	size_t j;
	u8 payload[16];

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;

	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	for (j = 0; j < core.runtime_op_cap; j++) {
		if (core.runtime_ops[j].task_ordinal == task->task_ordinal &&
		    core.runtime_ops[j].kind == SPP_DIAG_TRACE_RUNTIME_OP_EXEC &&
		    core.runtime_ops[j].state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN) {
			op = &core.runtime_ops[j];
			break;
		}
	}
	if (!op || op->pass_count == 0) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	op->state = SPP_DIAG_TRACE_RUNTIME_OP_STATE_COMMITTED;
	op->last_sequence = core.sequence + 1;

	store_u32be(payload, op->pass_count);
	store_u32be(payload + 4, pid);
	store_u32be(payload + 8, tgid);
	store_u32be(payload + 12, 0);

	field_err = check_append_fields(
		SPP_DIAG_TRACE_EVENT_EXEC_COMMIT, 0,
		task->task_ordinal, 0, op->operation_ordinal,
		core.runtime_phase, payload, sizeof(payload));
	err = append_locked(SPP_DIAG_TRACE_EVENT_EXEC_COMMIT, 0,
			    task->task_ordinal, 0, op->operation_ordinal,
			    core.runtime_phase, payload, sizeof(payload), field_err);
	if (!err)
		core.committed_exec_count++;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_file_open_attempt(
	const void *task_token, const char *local_path, size_t path_len,
	u16 access, u16 modifiers, u32 dirfd, u64 *out_op_ordinal)
{
	unsigned long flags;
	int err = WIRE_OK;
	int field_err;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op = NULL;
	u8 payload[16 + SPP_DIAG_TRACE_MAX_PATH_BYTES];

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;

	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	err = spp_diag_trace_core_runtime_open_op_locked(
		task, SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN, &op);
	if (err)
		goto out;

	op->file_access = access;
	op->file_modifiers = modifiers;
	op->policy_count = 0;
	op->first_sequence = core.sequence + 1;
	op->last_sequence = core.sequence + 1;

	store_u16be(payload, 1);
	store_u16be(payload + 2, (u16)path_len);
	store_u16be(payload + 4, access);
	store_u16be(payload + 6, modifiers);
	store_u32be(payload + 8, dirfd);
	store_u32be(payload + 12, 0);
	if (path_len && local_path)
		memcpy(payload + 16, local_path, path_len);

	field_err = check_append_fields(
		SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT, 0,
		task->task_ordinal, 0, op->operation_ordinal,
		core.runtime_phase, payload, 16 + path_len);
	err = append_locked(SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT, 0,
			    task->task_ordinal, 0, op->operation_ordinal,
			    core.runtime_phase, payload, 16 + path_len, field_err);

	if (!err && out_op_ordinal)
		*out_op_ordinal = op->operation_ordinal;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_file_policy_decision(
	const void *task_token, u64 operation_ordinal,
	const struct spp_diag_trace_fact_file_policy *fact)
{
	unsigned long flags;
	int err = WIRE_OK;
	int field_err;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op = NULL;
	u64 op_slot;
	u8 payload[48];

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;

	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	if (!fact) {
		err = fail_sticky(WIRE_NULL);
		goto out;
	}

	if (operation_ordinal < 2 || operation_ordinal >= core.runtime_next_op_ordinal) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	op_slot = operation_ordinal - 2;
	if (op_slot >= core.runtime_op_cap) {
		err = fail_sticky(WIRE_CAP);
		goto out;
	}
	op = &core.runtime_ops[op_slot];
	if (op->operation_ordinal != operation_ordinal ||
	    op->task_ordinal != task->task_ordinal ||
	    op->kind != SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN ||
	    op->state != SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	/* Exactly ONE FILE_POLICY_DECISION allowed per file_open operation */
	if (op->policy_count > 0) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	/* Access and modifiers MUST match what was recorded at file_open_attempt */
	if (fact->access != op->file_access || fact->modifiers != op->file_modifiers) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	store_u16be(payload, fact->access);
	store_u16be(payload + 2, fact->modifiers);
	store_u16be(payload + 4, fact->decision);
	store_u16be(payload + 6, fact->object_kind);
	store_u32be(payload + 8, fact->result);
	store_u32be(payload + 12, fact->fs_magic);
	store_u32be(payload + 16, fact->dev_major);
	store_u32be(payload + 20, fact->dev_minor);
	store_u64be(payload + 24, fact->inode);
	store_u64be(payload + 32, fact->mount_identity);
	store_u64be(payload + 40, fact->observed_size);

	field_err = check_append_fields(
		SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION, 0,
		task->task_ordinal, 0, op->operation_ordinal,
		core.runtime_phase, payload, sizeof(payload));
	err = append_locked(SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION, 0,
			    task->task_ordinal, 0, op->operation_ordinal,
			    core.runtime_phase, payload, sizeof(payload), field_err);

	if (!err) {
		op->policy_count++;
		op->last_sequence = core.sequence;
		if (fact->decision == SPP_DIAG_TRACE_POLICY_DENY)
			op->flags |= SPP_DIAG_TRACE_OP_FLAG_DENIED;
	}

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_file_gate_observation(
	const void *task_token, const void *file_token, u64 operation_ordinal,
	const struct spp_diag_trace_fact_file_policy *fact)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op = NULL;
	u64 op_slot;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	if (!file_token || !fact) {
		err = fail_sticky(WIRE_NULL);
		goto out;
	}
	if (operation_ordinal < 2 || operation_ordinal >= core.runtime_next_op_ordinal) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	op_slot = operation_ordinal - 2;
	if (op_slot >= core.runtime_op_cap) {
		err = fail_sticky(WIRE_CAP);
		goto out;
	}
	op = &core.runtime_ops[op_slot];
	if (op->operation_ordinal != operation_ordinal ||
	    op->task_ordinal != task->task_ordinal ||
	    op->kind != SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN ||
	    op->state != SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN ||
	    op->policy_count || fact->access != op->file_access ||
	    fact->modifiers != op->file_modifiers ||
	    fact->decision != SPP_DIAG_TRACE_POLICY_ALLOW || fact->result != 0) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	op->file_token = file_token;
	op->file_object_kind = fact->object_kind;
	op->file_fs_magic = fact->fs_magic;
	op->file_dev_major = fact->dev_major;
	op->file_dev_minor = fact->dev_minor;
	op->file_inode = fact->inode;
	op->file_mount_identity = fact->mount_identity;
	op->file_observed_size = fact->observed_size;
	op->policy_count = 1;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_mapping_policy_decision(
	const void *task_token,
	const struct spp_diag_trace_fact_mapping_policy *fact,
	u64 *out_op_ordinal)
{
	unsigned long flags;
	int err = WIRE_OK;
	int field_err;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op = NULL;
	size_t j;
	u8 payload[64];

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;

	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	if (!fact) {
		err = fail_sticky(WIRE_NULL);
		goto out;
	}

	if (fact->operation == SPP_DIAG_TRACE_MAPPING_OPERATION_MMAP) {
		/* MMAP always opens a brand new operation */
		err = spp_diag_trace_core_runtime_open_op_locked(
			task, SPP_DIAG_TRACE_RUNTIME_OP_MMAP, &op);
		if (err)
			goto out;
		op->first_sequence = core.sequence + 1;
		op->policy_count = 0;
	} else if (fact->operation == SPP_DIAG_TRACE_MAPPING_OPERATION_MPROTECT) {
		/* MPROTECT reuses open op if one exists, else opens new */
		for (j = 0; j < core.runtime_op_cap; j++) {
			if (core.runtime_ops[j].task_ordinal == task->task_ordinal &&
			    core.runtime_ops[j].kind == SPP_DIAG_TRACE_RUNTIME_OP_MPROTECT &&
			    core.runtime_ops[j].state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN) {
				op = &core.runtime_ops[j];
				break;
			}
		}
		if (!op) {
			err = spp_diag_trace_core_runtime_open_op_locked(
				task, SPP_DIAG_TRACE_RUNTIME_OP_MPROTECT, &op);
			if (err)
				goto out;
			op->first_sequence = core.sequence + 1;
			op->policy_count = 0;
		} else {
			/* Once any row has decision==DENY, no further rows may be appended */
			if ((op->flags & SPP_DIAG_TRACE_OP_FLAG_DENIED) != 0) {
				err = fail_sticky(WIRE_STATE);
				goto out;
			}
		}
	} else {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	store_u16be(payload, fact->operation);
	store_u16be(payload + 2, fact->decision);
	store_u16be(payload + 4, fact->backing);
	store_u16be(payload + 6, fact->mode);
	store_u32be(payload + 8, fact->requested);
	store_u32be(payload + 12, fact->effective);
	store_u32be(payload + 16, fact->prior);
	store_u32be(payload + 20, fact->result);
	store_u32be(payload + 24, fact->fs_magic);
	store_u32be(payload + 28, fact->dev_major);
	store_u32be(payload + 32, fact->dev_minor);
	store_u32be(payload + 36, fact->seals);
	store_u64be(payload + 40, fact->inode);
	store_u64be(payload + 48, fact->mount_identity);
	store_u64be(payload + 56, fact->observed_size);

	field_err = check_append_fields(
		SPP_DIAG_TRACE_PROVENANCE_EVENT_EXEC_MAPPING_POLICY_DECISION, 0,
		task->task_ordinal, 0, op->operation_ordinal,
		core.runtime_phase, payload, sizeof(payload));
	err = append_locked(SPP_DIAG_TRACE_PROVENANCE_EVENT_EXEC_MAPPING_POLICY_DECISION, 0,
			    task->task_ordinal, 0, op->operation_ordinal,
			    core.runtime_phase, payload, sizeof(payload), field_err);

	if (!err) {
		op->policy_count++;
		op->last_sequence = core.sequence;
		if (fact->decision == SPP_DIAG_TRACE_POLICY_DENY)
			op->flags |= SPP_DIAG_TRACE_OP_FLAG_DENIED;
		if (out_op_ordinal)
			*out_op_ordinal = op->operation_ordinal;
	}

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_network_policy_decision(
	const void *task_token,
	const struct spp_diag_trace_fact_network_policy *fact,
	u64 *out_op_ordinal)
{
	unsigned long flags;
	int err = WIRE_OK;
	int field_err;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op = NULL;
	u16 op_kind;
	u8 payload[64];

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;

	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	if (!fact) {
		err = fail_sticky(WIRE_NULL);
		goto out;
	}

	if (fact->operation == SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT)
		op_kind = SPP_DIAG_TRACE_RUNTIME_OP_CONNECT;
	else if (fact->operation == SPP_DIAG_TRACE_NETWORK_OPERATION_SENDMSG)
		op_kind = SPP_DIAG_TRACE_RUNTIME_OP_SENDMSG;
	else {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	/* NETWORK_POLICY_DECISION always opens a brand new operation */
	err = spp_diag_trace_core_runtime_open_op_locked(task, op_kind, &op);
	if (err)
		goto out;

	op->first_sequence = core.sequence + 1;
	op->policy_count = 0;

	store_u16be(payload, fact->operation);
	store_u16be(payload + 2, fact->decision);
	store_u16be(payload + 4, fact->kind);
	store_u16be(payload + 6, fact->source);
	store_u16be(payload + 8, fact->socket_kind);
	store_u16be(payload + 10, fact->protocol);
	store_u16be(payload + 12, fact->family);
	store_u16be(payload + 14, fact->addrlen);
	store_u32be(payload + 16, fact->result);
	store_u32be(payload + 20, fact->flags);
	store_u32be(payload + 24, fact->size);
	store_u64be(payload + 28, fact->cookie);
	store_u16be(payload + 36, fact->port);
	store_u16be(payload + 38, fact->reserved);
	store_u32be(payload + 40, fact->scope);
	store_u32be(payload + 44, fact->flow);
	memcpy(payload + 48, fact->address, 16);

	field_err = check_append_fields(
		SPP_DIAG_TRACE_PROVENANCE_EVENT_NETWORK_POLICY_DECISION, 0,
		task->task_ordinal, 0, op->operation_ordinal,
		core.runtime_phase, payload, sizeof(payload));
	err = append_locked(SPP_DIAG_TRACE_PROVENANCE_EVENT_NETWORK_POLICY_DECISION, 0,
			    task->task_ordinal, 0, op->operation_ordinal,
			    core.runtime_phase, payload, sizeof(payload), field_err);

	if (!err) {
		op->policy_count++;
		op->last_sequence = core.sequence;
		if (fact->decision == SPP_DIAG_TRACE_POLICY_DENY)
			op->flags |= SPP_DIAG_TRACE_OP_FLAG_DENIED;
		if (out_op_ordinal)
			*out_op_ordinal = op->operation_ordinal;
	}

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

static int spp_diag_trace_core_runtime_active_operation(
	const void *task_token, u16 kind, bool allow_committed,
	u64 *out_op_ordinal)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	if (!out_op_ordinal) {
		err = fail_sticky(WIRE_NULL);
		goto out;
	}
	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	err = spp_diag_trace_core_runtime_find_active_op_locked(task, kind,
								allow_committed, &op);
	if (!err)
		*out_op_ordinal = op->operation_ordinal;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_file_open_active_operation(
	const void *task_token, u64 *out_op_ordinal,
	u16 *out_access, u16 *out_modifiers)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	if (!out_op_ordinal || !out_access || !out_modifiers) {
		err = fail_sticky(WIRE_NULL);
		goto out;
	}
	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	err = spp_diag_trace_core_runtime_find_active_op_locked(
		task, SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN, false, &op);
	if (!err) {
		*out_op_ordinal = op->operation_ordinal;
		*out_access = op->file_access;
		*out_modifiers = op->file_modifiers;
	}

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_mmap_active_operation(
	const void *task_token, u64 *out_op_ordinal)
{
	return spp_diag_trace_core_runtime_active_operation(
		task_token, SPP_DIAG_TRACE_RUNTIME_OP_MMAP, false,
		out_op_ordinal);
}

int spp_diag_trace_core_runtime_mprotect_active_operation(
	const void *task_token, u64 *out_op_ordinal)
{
	return spp_diag_trace_core_runtime_active_operation(
		task_token, SPP_DIAG_TRACE_RUNTIME_OP_MPROTECT, false,
		out_op_ordinal);
}

int spp_diag_trace_core_runtime_connect_active_operation(
	const void *task_token, u64 *out_op_ordinal)
{
	return spp_diag_trace_core_runtime_active_operation(
		task_token, SPP_DIAG_TRACE_RUNTIME_OP_CONNECT, false,
		out_op_ordinal);
}

int spp_diag_trace_core_runtime_sendmsg_active_operation(
	const void *task_token, u64 *out_op_ordinal)
{
	return spp_diag_trace_core_runtime_active_operation(
		task_token, SPP_DIAG_TRACE_RUNTIME_OP_SENDMSG, false,
		out_op_ordinal);
}

static int spp_diag_trace_core_runtime_unsupported(const void *task_token)
{
	unsigned long flags;
	int err = WIRE_OK;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	(void)task_token;
	fail_sticky(WIRE_STATE);
	err = -EIO;

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_mapping_unsupported(const void *task_token)
{
	return spp_diag_trace_core_runtime_unsupported(task_token);
}

int spp_diag_trace_core_runtime_network_unsupported(const void *task_token)
{
	return spp_diag_trace_core_runtime_unsupported(task_token);
}

int spp_diag_trace_core_runtime_operation_unsupported(const void *task_token)
{
	return spp_diag_trace_core_runtime_unsupported(task_token);
}

static int spp_diag_trace_core_runtime_append_return_locked(
	struct spp_diag_trace_task_record *task,
	struct spp_diag_trace_operation_record *op, u64 result_bits)
{
	int field_err;
	int err;
	u8 payload[16];

	store_u16be(payload, op->kind);
	store_u16be(payload + 2, 0);
	store_u32be(payload + 4, 0);
	store_u64be(payload + 8, result_bits);

	field_err = check_append_fields(
		SPP_DIAG_TRACE_PROVENANCE_EVENT_OPERATION_RETURN, 0,
		task->task_ordinal, 0, op->operation_ordinal,
		core.runtime_phase, payload, sizeof(payload));
	err = append_locked(SPP_DIAG_TRACE_PROVENANCE_EVENT_OPERATION_RETURN, 0,
			    task->task_ordinal, 0, op->operation_ordinal,
			    core.runtime_phase, payload, sizeof(payload), field_err);

	op->state = SPP_DIAG_TRACE_RUNTIME_OP_STATE_CLOSED;
	op->last_sequence = core.sequence;
	if (task->open_op_count > 0)
		task->open_op_count--;
	return err;
}

int spp_diag_trace_core_runtime_operation_return(
	const void *task_token, u64 operation_ordinal, s64 result)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op = NULL;
	u64 op_slot;
	u16 kind;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;

	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	if (operation_ordinal < 2 || operation_ordinal >= core.runtime_next_op_ordinal) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	op_slot = operation_ordinal - 2;
	if (op_slot >= core.runtime_op_cap) {
		err = fail_sticky(WIRE_CAP);
		goto out;
	}
	op = &core.runtime_ops[op_slot];
	if (op->operation_ordinal != operation_ordinal ||
	    op->task_ordinal != task->task_ordinal) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	kind = op->kind;
	if (kind < SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN ||
	    kind > SPP_DIAG_TRACE_RUNTIME_OP_EXEC) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}

	if (kind == SPP_DIAG_TRACE_RUNTIME_OP_EXEC) {
		if (op->state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_COMMITTED) {
			/* Allowed with any result */
		} else if (op->state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN) {
			if (result >= 0) {
				err = fail_sticky(WIRE_STATE);
				goto out;
			}
		} else {
			err = fail_sticky(WIRE_STATE);
			goto out;
		}
	} else {
		if (op->state != SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN) {
			err = fail_sticky(WIRE_STATE);
			goto out;
		}
	}

	err = spp_diag_trace_core_runtime_append_return_locked(task, op, (u64)result);

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_operation_return_raw(
	const void *task_token, u64 operation_ordinal, u64 result_bits)
{
	unsigned long flags;
	int err = WIRE_OK;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op;
	u64 op_slot;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	if (operation_ordinal < 2 || operation_ordinal >= core.runtime_next_op_ordinal) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	op_slot = operation_ordinal - 2;
	if (op_slot >= core.runtime_op_cap) {
		err = fail_sticky(WIRE_CAP);
		goto out;
	}
	op = &core.runtime_ops[op_slot];
	if (op->operation_ordinal != operation_ordinal ||
	    op->task_ordinal != task->task_ordinal ||
	    op->kind != SPP_DIAG_TRACE_RUNTIME_OP_MMAP ||
	    op->state != SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	err = spp_diag_trace_core_runtime_append_return_locked(
		task, op, result_bits);

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

int spp_diag_trace_core_runtime_file_open_return(
	const void *task_token, const void *file_token, s64 result)
{
	unsigned long flags;
	int err = WIRE_OK;
	int field_err;
	struct spp_diag_trace_task_record *task;
	struct spp_diag_trace_operation_record *op;
	u8 payload[48];

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = spp_diag_trace_core_runtime_interval_status_locked();
	if (err)
		goto out;
	task = spp_diag_trace_core_runtime_find_task_locked(task_token);
	if (!task) {
		err = fail_sticky(WIRE_STATE);
		goto out;
	}
	err = spp_diag_trace_core_runtime_find_active_op_locked(
		task, SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN, false, &op);
	if (err == -ENOENT)
		err = fail_sticky(WIRE_STATE);
	if (err)
		goto out;

	if (result < 0) {
		if (file_token || op->policy_count) {
			err = fail_sticky(WIRE_STATE);
			goto out;
		}
	} else {
		if (!file_token || op->policy_count != 1 ||
		    op->file_token != file_token) {
			err = fail_sticky(WIRE_STATE);
			goto out;
		}

		store_u16be(payload, op->file_access);
		store_u16be(payload + 2, op->file_modifiers);
		store_u16be(payload + 4, SPP_DIAG_TRACE_POLICY_ALLOW);
		store_u16be(payload + 6, op->file_object_kind);
		store_u32be(payload + 8, 0);
		store_u32be(payload + 12, op->file_fs_magic);
		store_u32be(payload + 16, op->file_dev_major);
		store_u32be(payload + 20, op->file_dev_minor);
		store_u64be(payload + 24, op->file_inode);
		store_u64be(payload + 32, op->file_mount_identity);
		store_u64be(payload + 40, op->file_observed_size);

		field_err = check_append_fields(
			SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION, 0,
			task->task_ordinal, 0, op->operation_ordinal,
			core.runtime_phase, payload, sizeof(payload));
		err = append_locked(
			SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION, 0,
			task->task_ordinal, 0, op->operation_ordinal,
			core.runtime_phase, payload, sizeof(payload), field_err);
		if (err)
			goto out;
	}

	err = spp_diag_trace_core_runtime_append_return_locked(task, op, (u64)result);

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

static void encode_sealed_record_locked(u8 out[256])
{
	memset(out, 0, SPP_DIAG_TRACE_IMA_SIZE);
	memcpy(out, k_magic_ima, 8);
	store_u16be(out + 8, SPP_DIAG_TRACE_WIRE_VERSION);
	store_u16be(out + 10, SPP_DIAG_TRACE_IMA_KIND_SEALED);
	store_u32be(out + 12, SPP_DIAG_TRACE_IMA_SIZE);
	store_u16be(out + 16, SPP_DIAG_TRACE_POLICY_VERSION_PROVENANCE);
	store_u16be(out + 18, SPP_DIAG_TRACE_HASH_SHA256);
	store_u16be(out + 20, SPP_DIAG_TRACE_IMA_STATE_LIST_SEALED);
	/* 22..23 reserved */
	memcpy(out + 24, core.header + 32, SPP_DIAG_TRACE_SOURCE_COMMIT_LEN);
	memcpy(out + 44, core.header + 52, 32);
	memcpy(out + 76, core.header + 84, 32);
	memcpy(out + 108, core.header + 116, 32);
	memcpy(out + 140, core.header + 148, 32);
	store_u64be(out + 172, core.frame_count);
	store_u64be(out + 180, core.stream_byte_count);
	memcpy(out + 188, core.chain, SPP_DIAG_TRACE_CHAIN_LEN);
	store_u64be(out + 220, SPP_DIAG_TRACE_HOOK_MASK_PROVENANCE);
	store_u64be(out + 228, core.bootstrap_denial_count);
	store_u64be(out + 236, core.committed_exec_count);
	store_u32be(out + 244, 0);
	store_u32be(out + 248, 0);
	store_u32be(out + 252, 0);
}

static bool is_quiescent_locked(void)
{
	size_t i;

	for (i = 0; i < core.runtime_task_cap; i++) {
		if (core.runtime_tasks[i].exec_reservation_token)
			return false;
	}

	for (i = 1; i < core.runtime_task_cap; i++) {
		if ((core.runtime_tasks[i].flags & SPP_DIAG_TRACE_TASK_FLAG_LIVE) != 0)
			return false;
	}

	for (i = 0; i < core.runtime_op_cap; i++) {
		if (core.runtime_ops[i].state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN ||
		    core.runtime_ops[i].state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_COMMITTED)
			return false;
	}

	return true;
}

bool spp_diag_trace_core_runtime_is_sealed(void)
{
	unsigned long flags;
	bool sealed;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	sealed = (core.runtime_sealed != 0);
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return sealed;
}

int spp_diag_trace_core_runtime_handle_command(const u8 *cmd_raw, size_t len)
{
	unsigned long flags;
	u16 version;
	u16 kind;
	u32 cmd_len;
	u16 requested_phase;
	int err = 0;
	int ret_errno = -EINVAL;
	size_t i;

	if (!cmd_raw || len != SPP_DIAG_TRACE_COMMAND_SIZE)
		return spp_diag_trace_core_mark_failure(WIRE_LENGTH);

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);

	if (core.runtime_sealed) {
		spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
		return -ESHUTDOWN;
	}

	if (core.failed) {
		err = fail_sticky(core.reason ? core.reason : WIRE_STATE);
		ret_errno = -EINVAL;
		goto out;
	}

	if (!core.initialized || !core.runtime_ready || core.runtime_sealing) {
		err = fail_sticky(WIRE_STATE);
		ret_errno = -EINVAL;
		goto out;
	}

	/* Independent GPL decode of 128-byte command struct */
	if (memcmp(cmd_raw, k_magic_command, 8) != 0) {
		err = fail_sticky(WIRE_MAGIC);
		ret_errno = -EINVAL;
		goto out;
	}

	version = load_u16be(cmd_raw + 8);
	if (version != SPP_DIAG_TRACE_WIRE_VERSION) {
		err = fail_sticky(WIRE_VERSION);
		ret_errno = -EINVAL;
		goto out;
	}

	kind = load_u16be(cmd_raw + 10);
	if (kind != SPP_DIAG_TRACE_CMD_ADVANCE_PHASE &&
	    kind != SPP_DIAG_TRACE_CMD_SEAL) {
		err = fail_sticky(WIRE_STATE);
		ret_errno = -EINVAL;
		goto out;
	}

	cmd_len = load_u32be(cmd_raw + 12);
	if (cmd_len != SPP_DIAG_TRACE_COMMAND_SIZE) {
		err = fail_sticky(WIRE_LENGTH);
		ret_errno = -EINVAL;
		goto out;
	}

	/* Compare challenge, run_identity, control_plan_address directly with core.header */
	if (memcmp(cmd_raw + 16, core.header + 52, 32) != 0 ||
	    memcmp(cmd_raw + 48, core.header + 84, 32) != 0 ||
	    memcmp(cmd_raw + 80, core.header + 116, 32) != 0) {
		err = fail_sticky(WIRE_VALUE);
		ret_errno = -EINVAL;
		goto out;
	}

	requested_phase = load_u16be(cmd_raw + 112);

	/* Check 14-byte reserved region */
	for (i = 0; i < 14; i++) {
		if (cmd_raw[114 + i] != 0) {
			err = fail_sticky(WIRE_RESERVED);
			ret_errno = -EINVAL;
			goto out;
		}
	}

	/* Root identity check: caller must be the exact originally-bound root task object */
	if (!core.runtime_tasks || core.runtime_task_cap == 0 ||
	    core.runtime_tasks[0].task_token == NULL ||
	    core.runtime_tasks[0].task_token != current ||
	    !(core.runtime_tasks[0].flags & SPP_DIAG_TRACE_TASK_FLAG_LIVE)) {
		err = fail_sticky(WIRE_STATE);
		ret_errno = -EPERM;
		goto out;
	}

	if (kind == SPP_DIAG_TRACE_CMD_ADVANCE_PHASE) {
		u8 marker_payload[8];
		int field_err;

		if (requested_phase < SPP_DIAG_TRACE_CMD_ADVANCE_PHASE_MIN ||
		    requested_phase > SPP_DIAG_TRACE_CMD_ADVANCE_PHASE_MAX) {
			err = fail_sticky(WIRE_STATE);
			ret_errno = -EINVAL;
			goto out;
		}

		if (core.runtime_phase + 1u != requested_phase) {
			err = fail_sticky(WIRE_STATE);
			ret_errno = -EINVAL;
			goto out;
		}

		if (!is_quiescent_locked()) {
			err = fail_sticky(WIRE_STATE);
			ret_errno = -EBUSY;
			goto out;
		}

		store_u16be(marker_payload, core.runtime_phase);
		store_u16be(marker_payload + 2, requested_phase);
		store_u32be(marker_payload + 4, 0);

		field_err = check_append_fields(
			SPP_DIAG_TRACE_EVENT_PHASE_MARKER, 0,
			1, 0, 0, requested_phase,
			marker_payload, sizeof(marker_payload));
		if (field_err) {
			err = fail_sticky(field_err);
			ret_errno = -EINVAL;
			goto out;
		}

		err = append_locked(SPP_DIAG_TRACE_EVENT_PHASE_MARKER, 0,
				    1, 0, 0, requested_phase,
				    marker_payload, sizeof(marker_payload),
				    field_err);
		if (err) {
			err = fail_sticky(err);
			ret_errno = -EINVAL;
			goto out;
		}

		core.runtime_phase = requested_phase;
	} else if (kind == SPP_DIAG_TRACE_CMD_SEAL) {
		u8 sealed_record[256];
		u64 saved_seq;
		u64 saved_frames;
		u64 saved_bytes;
		int field_err;
		int ima_err;

		if (requested_phase != SPP_DIAG_TRACE_CMD_SEAL_PHASE ||
		    core.runtime_phase != SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE) {
			err = fail_sticky(WIRE_STATE);
			ret_errno = -EINVAL;
			goto out;
		}

		if (!is_quiescent_locked()) {
			err = fail_sticky(WIRE_STATE);
			ret_errno = -EBUSY;
			goto out;
		}

		core.runtime_sealing = 1;

		field_err = check_append_fields(
			SPP_DIAG_TRACE_EVENT_TERMINAL, 0,
			0, 0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
			NULL, 0);
		if (field_err) {
			core.runtime_sealing = 0;
			err = fail_sticky(field_err);
			ret_errno = -EINVAL;
			goto out;
		}

		err = append_locked(SPP_DIAG_TRACE_EVENT_TERMINAL, 0,
				    0, 0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
				    NULL, 0, field_err);
		if (err) {
			core.runtime_sealing = 0;
			err = fail_sticky(err);
			ret_errno = -EINVAL;
			goto out;
		}

		core.runtime_phase = SPP_DIAG_TRACE_PHASE_SEALED;
		encode_sealed_record_locked(sealed_record);

		saved_seq = core.sequence;
		saved_frames = core.frame_count;
		saved_bytes = core.stream_byte_count;

		spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);

		ima_err = ima_measure_critical_data(
			"sol_spp_diag_trace", "sol-spp-diag-terminal-v1",
			sealed_record, sizeof(sealed_record), false, NULL, 0);

		spin_lock_irqsave(&spp_diag_trace_core_lock, flags);

		core.runtime_sealing = 0;

		if (core.failed || ima_err != 0 ||
		    core.sequence != saved_seq ||
		    core.frame_count != saved_frames ||
		    core.stream_byte_count != saved_bytes) {
			err = fail_sticky(WIRE_STATE);
			ret_errno = ima_err ? ima_err : -EINVAL;
			goto out;
		}

		core.runtime_sealed = 1;
	}

out:
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err ? ret_errno : 0;
}

ssize_t spp_diag_trace_core_runtime_stream_read(char *ubuf, size_t count, loff_t *ppos)
{
	unsigned long flags;
	const u8 *stream_buf;
	size_t stream_len;
	size_t avail;
	size_t to_copy;

	if (!ubuf || !ppos)
		return -EINVAL;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	if (!core.runtime_sealed) {
		spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
		return -EAGAIN;
	}
	stream_buf = core.stream;
	stream_len = core.stream_len;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);

	if (*ppos < 0)
		return -EINVAL;
	if ((size_t)*ppos >= stream_len)
		return 0;

	avail = stream_len - (size_t)*ppos;
	to_copy = count < avail ? count : avail;

#if IS_ENABLED(CONFIG_KUNIT)
	if (core.read_copy_hook)
		core.read_copy_hook(spp_diag_trace_core_lock_is_held());
#endif

	if (copy_to_user(ubuf, stream_buf + *ppos, to_copy))
		return -EFAULT;

	*ppos += (loff_t)to_copy;
	return (ssize_t)to_copy;
}

loff_t spp_diag_trace_core_runtime_stream_llseek(struct file *file, loff_t offset, int whence)
{
	unsigned long flags;
	size_t stream_len;
	loff_t new_pos;

	if (!file)
		return -EINVAL;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	if (!core.runtime_sealed) {
		spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
		return -EAGAIN;
	}
	stream_len = core.stream_len;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);

	if (file->f_pos < 0 || file->f_pos > (loff_t)stream_len)
		return -EINVAL;

	switch (whence) {
	case SEEK_SET:
		if (offset < 0 || offset > (loff_t)stream_len)
			return -EINVAL;
		new_pos = offset;
		break;
	case SEEK_CUR:
		if (offset < -file->f_pos ||
		    offset > (loff_t)stream_len - file->f_pos)
			return -EINVAL;
		new_pos = file->f_pos + offset;
		break;
	case SEEK_END:
		if (offset > 0 || offset < -(loff_t)stream_len)
			return -EINVAL;
		new_pos = (loff_t)stream_len + offset;
		break;
	default:
		return -EINVAL;
	}

	file->f_pos = new_pos;
	return new_pos;
}
#endif

int spp_diag_trace_core_mark_failure(int reason)
{
	unsigned long flags;
	int err;
	int mapped = reason;

	if (reason < WIRE_NULL || reason > WIRE_SEQUENCE)
		mapped = WIRE_VALUE;

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	err = sticky_or_fault();
	if (err) {
		spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
		return err;
	}
	err = fail_sticky(mapped);
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return err;
}

#if IS_ENABLED(CONFIG_KUNIT)
int spp_diag_trace_core_snapshot(void *out, size_t out_cap, size_t *required_cap)
{
	unsigned long flags;
	size_t need;
	struct spp_diag_trace_core_snapshot meta;

	if (required_cap == NULL)
		return WIRE_NULL;

	run_barrier();
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	fill_snapshot_meta(&meta);
	need = sizeof(meta) + (size_t)meta.stream_len;
	if (out == NULL) {
		*required_cap = need;
		spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
		return WIRE_NULL;
	}
	if (out_cap < need) {
		*required_cap = need;
		spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
		return WIRE_BUFFER_TOO_SMALL;
	}
	memcpy(out, &meta, sizeof(meta));
	if (meta.stream_len && core.stream)
		memcpy((u8 *)out + sizeof(meta), core.stream,
		       (size_t)meta.stream_len);
	*required_cap = need;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return WIRE_OK;
}

void spp_diag_trace_core_reset(void)
{
	unsigned long flags;
	u8 *detached;
#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
	struct spp_diag_trace_task_record *detached_tasks;
	struct spp_diag_trace_operation_record *detached_ops;
#endif

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	detached = core.stream;
	core.stream = NULL;
	core.initialized = 0;
	core.failed = 0;
	core.reason = 0;
	memset(core.header, 0, sizeof(core.header));
	memset(core.core_init_frame, 0, sizeof(core.core_init_frame));
	memset(core.header_chain, 0, sizeof(core.header_chain));
	memset(core.chain, 0, sizeof(core.chain));
	core.frame_count = 0;
	core.stream_byte_count = 0;
	core.sequence = 0;
	memset(core.last_frame, 0, sizeof(core.last_frame));
	core.last_frame_len = 0;
	core.stream_cap = 0;
	core.stream_len = 0;
	core.bootstrap_denial_count = 0;
	core.bootstrap_stage = SPP_DIAG_TRACE_BOOTSTRAP_NONE;
	core.bootstrap_released = 0;
	core.max_frames_op = SPP_DIAG_TRACE_CORE_OP_MAX_FRAMES;
	core.max_stream_bytes_op = SPP_DIAG_TRACE_CORE_OP_MAX_STREAM_BYTES;
	core.fault_inject = 0;
	core.init_fault = 0;
	core.pre_lock_barrier = NULL;
	core.pre_lock_barrier_arg = NULL;
	core.read_copy_hook = NULL;
#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
	detached_tasks = core.runtime_tasks;
	detached_ops = core.runtime_ops;
	core.runtime_tasks = NULL;
	core.runtime_ops = NULL;
	core.runtime_task_cap = 0;
	core.runtime_op_cap = 0;
	core.runtime_next_task_ordinal = 1;
	core.runtime_next_op_ordinal = 2;
	core.runtime_next_exec_reservation_token = 1;
	core.committed_exec_count = 0;
	core.runtime_phase = SPP_DIAG_TRACE_PHASE_PRE_RELEASE;
	core.runtime_ready = 0;
	core.runtime_sealing = 0;
	core.runtime_sealed = 0;
#endif
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	vfree(detached);
#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
	vfree(detached_tasks);
	vfree(detached_ops);
	spp_diag_trace_runtime_fs_exit();
	host_securityfs_reset();
#endif
}

void spp_diag_trace_core_inject_fault(int reason)
{
	unsigned long flags;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	core.fault_inject = reason;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
}

void spp_diag_trace_core_inject_init_fault(int stage)
{
	unsigned long flags;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	core.init_fault = stage;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
}

void spp_diag_trace_core_set_pre_lock_barrier(void (*fn)(void *), void *arg)
{
	unsigned long flags;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	core.pre_lock_barrier = fn;
	core.pre_lock_barrier_arg = arg;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
}

void spp_diag_trace_core_set_op_caps(u32 max_frames, u64 max_stream_bytes)
{
	unsigned long flags;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	core.max_frames_op = max_frames;
	core.max_stream_bytes_op = max_stream_bytes;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
}

int spp_diag_trace_core_test_checked_add_u64(u64 a, u64 b, u64 *out)
{
	return add_u64(a, b, out);
}

int spp_diag_trace_core_test_get_task_record(size_t index, struct spp_diag_trace_task_record *out)
{
#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
	unsigned long flags;
	int ret = WIRE_STATE;

	if (!out)
		return WIRE_NULL;
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	if (core.runtime_tasks && index < core.runtime_task_cap) {
		*out = core.runtime_tasks[index];
		ret = 0;
	}
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return ret;
#else
	(void)index; (void)out;
	return WIRE_STATE;
#endif
}

int spp_diag_trace_core_test_get_op_record(size_t index, struct spp_diag_trace_operation_record *out)
{
#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
	unsigned long flags;
	int ret = WIRE_STATE;

	if (!out)
		return WIRE_NULL;
	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	if (core.runtime_ops && index < core.runtime_op_cap) {
		*out = core.runtime_ops[index];
		ret = 0;
	}
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
	return ret;
#else
	(void)index; (void)out;
	return WIRE_STATE;
#endif
}

void spp_diag_trace_core_set_read_copy_hook(void (*hook)(bool lock_held))
{
	unsigned long flags;

	spin_lock_irqsave(&spp_diag_trace_core_lock, flags);
	core.read_copy_hook = hook;
	spin_unlock_irqrestore(&spp_diag_trace_core_lock, flags);
}
#endif
