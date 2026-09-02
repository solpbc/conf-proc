/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef SPP_DIAG_TRACE_CORE_H
#define SPP_DIAG_TRACE_CORE_H

#include <linux/kconfig.h>
#include <linux/types.h>

#include "protocol_constants.h"

#if IS_ENABLED(CONFIG_KUNIT)
#define SPP_DIAG_TRACE_CORE_OP_MAX_FRAMES 8u
#define SPP_DIAG_TRACE_CORE_OP_MAX_STREAM_BYTES 1024ull
#else
#define SPP_DIAG_TRACE_CORE_OP_MAX_FRAMES SPP_DIAG_TRACE_MAX_FRAMES
#define SPP_DIAG_TRACE_CORE_OP_MAX_STREAM_BYTES SPP_DIAG_TRACE_MAX_STREAM_BYTES
#endif

struct spp_diag_trace_core_snapshot {
	int initialized;
	int failed;
	int reason;
	u8 header[SPP_DIAG_TRACE_HEADER_SIZE];
	u8 core_init_frame[SPP_DIAG_TRACE_FRAME_HEADER_SIZE];
	u8 header_chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u8 chain[SPP_DIAG_TRACE_CHAIN_LEN];
	u64 frame_count;
	u64 stream_byte_count;
	u64 sequence;
	u32 max_frames_op;
	u64 max_stream_bytes_op;
	u8 last_frame[SPP_DIAG_TRACE_MAX_FRAME_BYTES];
	u32 last_frame_len;
	u64 stream_len;
};

int spp_diag_trace_core_init(const u8 challenge[32],
			     const u8 run_identity[32],
			     const u8 control_plan_address[32],
			     const u8 command_line_sha256[32]);
int spp_diag_trace_core_is_green(void);
int spp_diag_trace_core_append(u16 event_type, u16 flags,
			       u64 task_ordinal, u64 parent_task_ordinal,
			       u64 operation_ordinal, u16 phase,
			       const void *payload, size_t payload_length);
int spp_diag_trace_core_mark_failure(int reason);

#if IS_ENABLED(CONFIG_KUNIT)
enum spp_diag_trace_core_init_fault {
	SPP_DIAG_TRACE_CORE_INIT_FAULT_NONE = 0,
	SPP_DIAG_TRACE_CORE_INIT_FAULT_ALLOCATION,
	SPP_DIAG_TRACE_CORE_INIT_FAULT_HEADER_ENCODING,
	SPP_DIAG_TRACE_CORE_INIT_FAULT_HEADER_INVARIANT,
	SPP_DIAG_TRACE_CORE_INIT_FAULT_CORE_INIT_ENCODING,
	SPP_DIAG_TRACE_CORE_INIT_FAULT_CORE_INIT_INVARIANT,
	SPP_DIAG_TRACE_CORE_INIT_FAULT_INITIAL_ARITHMETIC,
	SPP_DIAG_TRACE_CORE_INIT_FAULT_PRE_PUBLICATION,
};

int spp_diag_trace_core_snapshot(void *out, size_t out_cap,
				 size_t *required_cap);
void spp_diag_trace_core_reset(void);
void spp_diag_trace_core_inject_fault(int reason);
void spp_diag_trace_core_inject_init_fault(int stage);
void spp_diag_trace_core_set_pre_lock_barrier(void (*fn)(void *), void *arg);
void spp_diag_trace_core_set_op_caps(u32 max_frames, u64 max_stream_bytes);
int spp_diag_trace_core_test_checked_add_u64(u64 a, u64 b, u64 *out);
#endif

#endif
