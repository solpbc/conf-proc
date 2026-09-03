/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_RUNTIME_TYPES_H
#define SPP_DIAG_TRACE_CORE_RUNTIME_TYPES_H

#include <linux/kconfig.h>
#include <linux/types.h>

enum spp_diag_trace_runtime_op_kind {
	SPP_DIAG_TRACE_RUNTIME_OP_NONE = 0,
	SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN = 1,
	SPP_DIAG_TRACE_RUNTIME_OP_MMAP = 2,
	SPP_DIAG_TRACE_RUNTIME_OP_MPROTECT = 3,
	SPP_DIAG_TRACE_RUNTIME_OP_CONNECT = 4,
	SPP_DIAG_TRACE_RUNTIME_OP_SENDMSG = 5,
	SPP_DIAG_TRACE_RUNTIME_OP_EXEC = 6,
	SPP_DIAG_TRACE_RUNTIME_OP_TASK_ALLOC = 7,
};
#define SPP_DIAG_TRACE_RUNTIME_OP_KINDS 7u

enum spp_diag_trace_runtime_op_state {
	SPP_DIAG_TRACE_RUNTIME_OP_STATE_FREE = 0,
	SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN = 1,
	SPP_DIAG_TRACE_RUNTIME_OP_STATE_COMMITTED = 2,
	SPP_DIAG_TRACE_RUNTIME_OP_STATE_CLOSED = 3,
};

#ifndef ESHUTDOWN
#define ESHUTDOWN 108
#endif

#define SPP_DIAG_TRACE_ERR_INACTIVE (-ESHUTDOWN)

#define SPP_DIAG_TRACE_TASK_FLAG_LIVE     0x0001u
#define SPP_DIAG_TRACE_TASK_FLAG_DOOMED   0x0002u
#define SPP_DIAG_TRACE_TASK_FLAG_EXITED   0x0004u

#define SPP_DIAG_TRACE_OP_FLAG_DENIED     0x0001u

#define SPP_DIAG_TRACE_RUNTIME_MAX_TASKS 4096u
#define SPP_DIAG_TRACE_RUNTIME_MAX_OPERATIONS 32768u

#ifndef SPP_DIAG_TRACE_RUNTIME_OP_MAX_TASKS
#if IS_ENABLED(CONFIG_KUNIT)
#define SPP_DIAG_TRACE_RUNTIME_OP_MAX_TASKS 8u
#else
#define SPP_DIAG_TRACE_RUNTIME_OP_MAX_TASKS SPP_DIAG_TRACE_RUNTIME_MAX_TASKS
#endif
#endif

#ifndef SPP_DIAG_TRACE_RUNTIME_OP_MAX_OPERATIONS
#if IS_ENABLED(CONFIG_KUNIT)
#define SPP_DIAG_TRACE_RUNTIME_OP_MAX_OPERATIONS 32u
#else
#define SPP_DIAG_TRACE_RUNTIME_OP_MAX_OPERATIONS SPP_DIAG_TRACE_RUNTIME_MAX_OPERATIONS
#endif
#endif

struct spp_diag_trace_task_record {
	const void *task_token;
	u64 task_ordinal;
	u64 parent_task_ordinal;
	u64 creation_sequence;
	u64 exit_sequence;
	u32 pid;
	u32 tgid;
	u32 exit_code;
	u16 mint_phase;
	u16 flags;
	u16 open_op_count;
	u16 reserved;
};

struct spp_diag_trace_operation_record {
	u64 operation_ordinal;
	u64 task_ordinal;
	u64 child_task_ordinal;
	u64 first_sequence;
	u64 last_sequence;
	u32 pass_count;
	u32 policy_count;
	u16 file_access;
	u16 file_modifiers;
	u16 kind;
	u16 phase;
	u16 state;
	u16 flags;
	u32 reserved;
};

#endif
