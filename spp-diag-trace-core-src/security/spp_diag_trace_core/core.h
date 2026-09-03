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

#if IS_ENABLED(CONFIG_KUNIT)
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
	u64 bootstrap_denial_count;
	u32 bootstrap_stage;
	int bootstrap_released;
};
#endif

enum spp_diag_trace_bootstrap_stage {
	SPP_DIAG_TRACE_BOOTSTRAP_NONE = 0,
	SPP_DIAG_TRACE_BOOTSTRAP_CORE_READY,
	SPP_DIAG_TRACE_BOOTSTRAP_IMA_AVAILABLE,
	SPP_DIAG_TRACE_BOOTSTRAP_DENIED,
	SPP_DIAG_TRACE_BOOTSTRAP_READY_APPENDED,
	SPP_DIAG_TRACE_BOOTSTRAP_READY_MEASURED,
	SPP_DIAG_TRACE_BOOTSTRAP_RELEASE_APPENDED,
	SPP_DIAG_TRACE_BOOTSTRAP_RELEASE_MEASURED,
	SPP_DIAG_TRACE_BOOTSTRAP_RELEASED,
};

#define SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH \
	"/usr/local/libexec/solstone/pre-release-denied"

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

#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP)
int spp_diag_trace_core_bootstrap_ima_available(void);
int spp_diag_trace_core_bootstrap_gate(const char *path, size_t path_length,
				       u32 pid, u32 tgid);
int spp_diag_trace_core_bootstrap_prepare_ready(u8 record[256]);
int spp_diag_trace_core_bootstrap_ready_measured(void);
int spp_diag_trace_core_bootstrap_prepare_release(u32 pid, u32 tgid,
					  u8 record[256]);
int spp_diag_trace_core_bootstrap_release_measured(void);
int spp_diag_trace_core_bootstrap_publish(void);
#endif

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
