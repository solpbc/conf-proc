/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/binfmts.h>
#include <linux/ima.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/panic.h>
#include <linux/sched.h>
#include <linux/spp_diag_trace_bootstrap.h>
#include <linux/spp_diag_trace_runtime.h>
#include "protocol_constants.h"
#include "runtime_types.h"
#include "core.h"

#define ASSERT(cond, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL: %s (%s:%d): %s\n", __func__, __FILE__, __LINE__, msg); \
			exit(1); \
		} \
	} while (0)

static const char valid_command_line[] =
	"ima_policy=critical_data "
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static inline u16 load_u16be(const u8 *p)
{
	return ((u16)p[0] << 8) | (u16)p[1];
}

static inline u32 load_u32be(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static inline u64 load_u64be(const u8 *p)
{
	return ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) | ((u64)p[3] << 32) |
	       ((u64)p[4] << 24) | ((u64)p[5] << 16) | ((u64)p[6] << 8) | (u64)p[7];
}

struct frame_view {
	u32 total_len;
	u16 event_type;
	u16 flags;
	u32 payload_len;
	u64 seq;
	u64 task_ord;
	u64 parent_task_ord;
	u64 op_ord;
	u16 phase;
	u16 reserved;
	const u8 *payload;
};

static struct frame_view get_frame(const u8 *stream, size_t stream_len, size_t target_idx)
{
	size_t off = 0;
	size_t idx = 0;
	struct frame_view f;

	memset(&f, 0, sizeof(f));
	while (off + 4 <= stream_len) {
		u32 flen = load_u32be(stream + off);
		if (flen < 44 || off + 4 + flen > stream_len)
			break;
		if (idx == target_idx) {
			f.total_len = flen;
			f.event_type = load_u16be(stream + off + 4);
			f.flags = load_u16be(stream + off + 6);
			f.payload_len = load_u32be(stream + off + 8);
			f.seq = load_u64be(stream + off + 12);
			f.task_ord = load_u64be(stream + off + 20);
			f.parent_task_ord = load_u64be(stream + off + 28);
			f.op_ord = load_u64be(stream + off + 36);
			f.phase = load_u16be(stream + off + 44);
			f.reserved = load_u16be(stream + off + 46);
			f.payload = stream + off + 48;
			return f;
		}
		off += 4 + flen;
		idx++;
	}
	return f;
}

static void setup_published_runtime(struct task_struct **out_root)
{
	spp_diag_trace_core_reset();
	host_kmod_reset();
	host_ima_reset();
	host_current_task.pid = 1;
	host_current_task.tgid = 1;
	host_current_task.flags = 0;
	host_saved_command_line_set(valid_command_line);

	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();
	ASSERT(spp_diag_trace_runtime_init() == 0, "runtime init");
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_release();
	ASSERT(spp_diag_trace_runtime_ready() == 1, "runtime ready");
	ASSERT(spp_diag_trace_core_is_green() == 1, "green after release");
	if (out_root)
		*out_root = &host_current_task;
}

static void test_root_binding_direct_record(void)
{
	struct task_struct *root_ts = NULL;
	struct spp_diag_trace_task_record tr;

	setup_published_runtime(&root_ts);

	ASSERT(spp_diag_trace_core_test_get_task_record(0, &tr) == 0, "get task record 0");
	ASSERT(tr.task_token == root_ts, "root task token matches");
	ASSERT(tr.task_ordinal == 1, "root task ordinal is 1");
	ASSERT(tr.parent_task_ordinal == 0, "root parent ordinal is 0");
	ASSERT(tr.pid == 1, "root pid is 1");
	ASSERT(tr.tgid == 1, "root tgid is 1");
	ASSERT(tr.mint_phase == SPP_DIAG_TRACE_PHASE_INIT, "root mint phase is INIT");
	ASSERT(tr.flags == SPP_DIAG_TRACE_TASK_FLAG_LIVE, "root task is LIVE");
	ASSERT(tr.open_op_count == 0, "root open_op_count is 0");
	printf("PASS: test_root_binding_direct_record\n");
}

static void test_tracked_child_lifecycle(void)
{
	struct task_struct *root_ts = NULL;
	struct task_struct child_ts = { .flags = 0 };
	struct spp_diag_trace_task_record tr;
	struct spp_diag_trace_operation_record op;
	struct spp_diag_trace_fact_task_alloc alloc_fact = { .clone_flags = 0x1122334455667788ULL };
	struct spp_diag_trace_fact_task_created created_fact = {
		.pid = 4200,
		.tgid = 4200,
		.clone_flags = 0x1122334455667788ULL,
	};

	setup_published_runtime(&root_ts);

	/* 1. Task alloc attempt */
	ASSERT(spp_diag_trace_runtime_task_alloc_attempt(root_ts, &alloc_fact) == 0, "task alloc attempt");
	ASSERT(spp_diag_trace_core_test_get_task_record(0, &tr) == 0, "get root record");
	ASSERT(tr.open_op_count == 1, "root open_op_count is 1");

	ASSERT(spp_diag_trace_core_test_get_task_record(1, &tr) == 0, "get child record");
	ASSERT(tr.task_ordinal == 2, "child task ordinal is 2");
	ASSERT(tr.parent_task_ordinal == 1, "child parent ordinal is 1");
	ASSERT(tr.flags == 0, "child flags is pending (0)");

	ASSERT(spp_diag_trace_core_test_get_op_record(0, &op) == 0, "get op record 0");
	ASSERT(op.operation_ordinal == 2, "op ordinal is 2");
	ASSERT(op.task_ordinal == 1, "op task ordinal is 1");
	ASSERT(op.child_task_ordinal == 2, "op child task ordinal is 2");
	ASSERT(op.kind == SPP_DIAG_TRACE_RUNTIME_OP_TASK_ALLOC, "op kind is TASK_ALLOC");
	ASSERT(op.state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN, "op state is OPEN");

	/* 2. Task created */
	ASSERT(spp_diag_trace_runtime_task_created(root_ts, &child_ts, &created_fact) == 0, "task created");
	ASSERT(spp_diag_trace_core_test_get_task_record(1, &tr) == 0, "get child record");
	ASSERT(tr.task_token == &child_ts, "child task token matches");
	ASSERT(tr.pid == 4200, "child pid matches");
	ASSERT(tr.tgid == 4200, "child tgid matches");
	ASSERT(tr.flags == SPP_DIAG_TRACE_TASK_FLAG_LIVE, "child is LIVE");

	ASSERT(spp_diag_trace_core_test_get_task_record(0, &tr) == 0, "get root record");
	ASSERT(tr.open_op_count == 0, "root open_op_count restored to 0");

	ASSERT(spp_diag_trace_core_test_get_op_record(0, &op) == 0, "get op record 0");
	ASSERT(op.state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_CLOSED, "op state is CLOSED");

	/* 3. Task exit */
	ASSERT(spp_diag_trace_runtime_task_exit(&child_ts, 42) == 0, "child task exit");
	ASSERT(spp_diag_trace_core_test_get_task_record(1, &tr) == 0, "get child record after exit");
	ASSERT(tr.flags == SPP_DIAG_TRACE_TASK_FLAG_EXITED, "child is EXITED");
	ASSERT(tr.exit_code == 42, "child exit code is 42");
	ASSERT(spp_diag_trace_core_is_green() == 1, "still green");

	printf("PASS: test_tracked_child_lifecycle\n");
}

static u8 snap_buf[2 * 1024 * 1024];
static struct spp_diag_trace_core_snapshot meta;

static void test_exec_multipass_commit_return_and_poison(void)
{
	struct task_struct *root_ts = NULL;
	char original_path[64] = "/usr/bin/special-app";
	struct spp_diag_trace_fact_exec_attempt attempt1 = {
		.path = original_path,
		.path_len = strlen(original_path),
		.pid = 1,
		.tgid = 1,
	};
	struct spp_diag_trace_fact_exec_attempt attempt2 = {
		.path = "/usr/bin/special-app-interpreter",
		.path_len = strlen("/usr/bin/special-app-interpreter"),
		.pid = 1,
		.tgid = 1,
	};
	struct spp_diag_trace_fact_exec_commit commit = {
		.pid = 1,
		.tgid = 1,
	};
	size_t req_cap = 0;
	const u8 *stream;
	struct frame_view f;

	setup_published_runtime(&root_ts);

	/* 1. Attempt 1 */
	ASSERT(spp_diag_trace_runtime_exec_attempt(root_ts, &attempt1) == 0, "exec attempt 1");

	/* Poison original buffer */
	memset(original_path, 0xAA, sizeof(original_path));

	/* Verify appended frame has unpoisoned path */
	ASSERT(spp_diag_trace_core_snapshot(snap_buf, sizeof(snap_buf), &req_cap) == 0, "snapshot 1");
	memcpy(&meta, snap_buf, sizeof(meta));
	stream = snap_buf + sizeof(meta);
	ASSERT(meta.frame_count == 5, "5 frames total (1 init + 3 bootstrap + exec_attempt1)");

	/* Stream entry 5 (seq 4) is exec_attempt1 */
	f = get_frame(stream, (size_t)meta.stream_len, 5);
	ASSERT(f.event_type == SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT, "entry 5 event_type");
	ASSERT(f.seq == 4, "entry 5 seq");
	ASSERT(f.task_ord == 1, "entry 5 task_ord");
	ASSERT(f.op_ord == 2, "entry 5 op_ord");
	ASSERT(f.phase == SPP_DIAG_TRACE_PHASE_INIT, "entry 5 phase");
	ASSERT(f.payload_len == 16 + 20, "entry 5 payload_len");
	ASSERT(load_u32be(f.payload) == 1, "entry 5 pass_index == 1");
	ASSERT(load_u16be(f.payload + 4) == 20, "entry 5 path_len == 20");
	ASSERT(load_u16be(f.payload + 6) == 0, "entry 5 reserved == 0");
	ASSERT(load_u32be(f.payload + 8) == 1, "entry 5 pid == 1");
	ASSERT(load_u32be(f.payload + 12) == 1, "entry 5 tgid == 1");
	ASSERT(memcmp(f.payload + 16, "/usr/bin/special-app", 20) == 0, "entry 5 path payload unpoisoned");

	/* 2. Attempt 2 (multi-pass) */
	ASSERT(spp_diag_trace_runtime_exec_attempt(root_ts, &attempt2) == 0, "exec attempt 2");

	/* 3. Commit */
	ASSERT(spp_diag_trace_runtime_exec_commit(root_ts, &commit) == 0, "exec commit");

	/* 4. Operation Return */
	ASSERT(spp_diag_trace_runtime_operation_return(root_ts, 2, 0) == 0, "exec return");
	ASSERT(spp_diag_trace_core_is_green() == 1, "is green after full exec lifecycle");

	/* Inspect trace stream frames */
	ASSERT(spp_diag_trace_core_snapshot(snap_buf, sizeof(snap_buf), &req_cap) == 0, "snapshot 2");
	memcpy(&meta, snap_buf, sizeof(meta));
	stream = snap_buf + sizeof(meta);
	ASSERT(meta.frame_count == 8, "8 frames total");

	/* Stream entry 6 (seq 5) is exec attempt 2 */
	f = get_frame(stream, (size_t)meta.stream_len, 6);
	ASSERT(f.event_type == SPP_DIAG_TRACE_EVENT_EXEC_ATTEMPT, "entry 6 event_type");
	ASSERT(f.seq == 5, "entry 6 seq");
	ASSERT(f.task_ord == 1, "entry 6 task_ord");
	ASSERT(f.op_ord == 2, "entry 6 op_ord");
	ASSERT(f.payload_len == 16 + 32, "entry 6 payload_len");
	ASSERT(load_u32be(f.payload) == 2, "entry 6 pass_index == 2");
	ASSERT(load_u16be(f.payload + 4) == 32, "entry 6 path_len == 32");
	ASSERT(memcmp(f.payload + 16, "/usr/bin/special-app-interpreter", 32) == 0, "entry 6 path");

	/* Stream entry 7 (seq 6) is exec commit */
	f = get_frame(stream, (size_t)meta.stream_len, 7);
	ASSERT(f.event_type == SPP_DIAG_TRACE_EVENT_EXEC_COMMIT, "entry 7 event_type");
	ASSERT(f.seq == 6, "entry 7 seq");
	ASSERT(f.task_ord == 1, "entry 7 task_ord");
	ASSERT(f.op_ord == 2, "entry 7 op_ord");
	ASSERT(f.payload_len == 16, "entry 7 payload_len");
	ASSERT(load_u32be(f.payload) == 2, "entry 7 pass_count == 2");
	ASSERT(load_u32be(f.payload + 4) == 1, "entry 7 pid == 1");
	ASSERT(load_u32be(f.payload + 8) == 1, "entry 7 tgid == 1");
	ASSERT(load_u32be(f.payload + 12) == 0, "entry 7 reserved == 0");

	/* Stream entry 8 (seq 7) is operation return */
	f = get_frame(stream, (size_t)meta.stream_len, 8);
	ASSERT(f.event_type == SPP_DIAG_TRACE_PROVENANCE_EVENT_OPERATION_RETURN, "entry 8 event_type");
	ASSERT(f.seq == 7, "entry 8 seq");
	ASSERT(f.task_ord == 1, "entry 8 task_ord");
	ASSERT(f.op_ord == 2, "entry 8 op_ord");
	ASSERT(f.payload_len == 16, "entry 8 payload_len");
	ASSERT(load_u16be(f.payload) == SPP_DIAG_TRACE_RUNTIME_OP_EXEC, "entry 8 kind == 6");
	ASSERT(load_u16be(f.payload + 2) == 0, "entry 8 res16 == 0");
	ASSERT(load_u32be(f.payload + 4) == 0, "entry 8 res32 == 0");
	ASSERT(load_u64be(f.payload + 8) == 0, "entry 8 raw_result == 0");

	printf("PASS: test_exec_multipass_commit_return_and_poison\n");
}

static void test_generic_operation_primitives(void)
{
	struct task_struct *root_ts = NULL;
	u64 op_ord1 = 0;
	u64 op_ord2 = 0;

	setup_published_runtime(&root_ts);

	/* 1. Open op on root task (ordinal 1) */
	ASSERT(spp_diag_trace_core_runtime_open_operation(1, SPP_DIAG_TRACE_RUNTIME_OP_CONNECT, &op_ord1) == 0, "open op 1");
	ASSERT(op_ord1 == 2, "first minted op ordinal is 2");

	/* 2. Reject same-kind overlap */
	ASSERT(spp_diag_trace_core_runtime_open_operation(1, SPP_DIAG_TRACE_RUNTIME_OP_CONNECT, &op_ord2) != 0, "overlap rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after overlap");

	/* Reset and verify close operation */
	setup_published_runtime(&root_ts);
	ASSERT(spp_diag_trace_core_runtime_open_operation(1, SPP_DIAG_TRACE_RUNTIME_OP_CONNECT, &op_ord1) == 0, "open op");
	ASSERT(spp_diag_trace_core_runtime_close_operation(1, op_ord1, SPP_DIAG_TRACE_RUNTIME_OP_CONNECT) == 0, "close op");

	/* Reject double close */
	ASSERT(spp_diag_trace_core_runtime_close_operation(1, op_ord1, SPP_DIAG_TRACE_RUNTIME_OP_CONNECT) != 0, "double close rejected");

	/* Reject untracked task ordinal */
	setup_published_runtime(&root_ts);
	ASSERT(spp_diag_trace_core_runtime_open_operation(999, SPP_DIAG_TRACE_RUNTIME_OP_CONNECT, &op_ord1) != 0, "untracked task rejected");

	printf("PASS: test_generic_operation_primitives\n");
}

static void test_same_kind_overlap_rejection(void)
{
	struct task_struct *root_ts = NULL;
	struct spp_diag_trace_fact_task_alloc alloc1 = { .clone_flags = 0x1 };
	struct spp_diag_trace_fact_task_alloc alloc2 = { .clone_flags = 0x2 };

	setup_published_runtime(&root_ts);

	ASSERT(spp_diag_trace_runtime_task_alloc_attempt(root_ts, &alloc1) == 0, "alloc 1 succeeds");
	/* Overlapping TASK_ALLOC without closing previous */
	ASSERT(spp_diag_trace_runtime_task_alloc_attempt(root_ts, &alloc2) != 0, "alloc 2 overlap rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "core is sticky red after overlap");

	printf("PASS: test_same_kind_overlap_rejection\n");
}

static void test_untracked_exec_rejection(void)
{
	struct task_struct *root_ts = NULL;
	struct task_struct untracked = { .flags = 0 };
	struct spp_diag_trace_fact_exec_attempt attempt = {
		.path = "/bin/sh",
		.path_len = strlen("/bin/sh"),
		.pid = 999,
		.tgid = 999,
	};

	setup_published_runtime(&root_ts);

	ASSERT(spp_diag_trace_runtime_exec_attempt(&untracked, &attempt) != 0, "untracked exec rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "core is sticky red after untracked exec");

	printf("PASS: test_untracked_exec_rejection\n");
}

static void test_pf_kthread_ignore_twins(void)
{
	struct task_struct *root_ts = NULL;
	struct task_struct kparent = { .flags = PF_KTHREAD };
	struct task_struct kchild = { .flags = PF_KTHREAD };
	struct spp_diag_trace_fact_task_created created = {
		.pid = 0,
		.tgid = 0,
		.clone_flags = 0,
	};

	setup_published_runtime(&root_ts);

	/* Case 1: both parent and child are PF_KTHREAD on untracked create */
	ASSERT(spp_diag_trace_runtime_task_created(&kparent, &kchild, &created) == 0, "kthread create ignored");
	ASSERT(spp_diag_trace_core_is_green() == 1, "still green after kthread create");

	/* Case 2: untracked task with PF_KTHREAD on exit */
	ASSERT(spp_diag_trace_runtime_task_exit(&kchild, 0) == 0, "kthread exit ignored");
	ASSERT(spp_diag_trace_core_is_green() == 1, "still green after kthread exit");

	printf("PASS: test_pf_kthread_ignore_twins\n");
}

static void test_pf_kthread_red_twins(void)
{
	/* Case A: parent-only PF_KTHREAD */
	{
		struct task_struct *root_ts = NULL;
		struct task_struct kparent = { .flags = PF_KTHREAD };
		struct task_struct uchild = { .flags = 0 };
		struct spp_diag_trace_fact_task_created created = { .pid = 10, .tgid = 10, .clone_flags = 0 };

		setup_published_runtime(&root_ts);
		ASSERT(spp_diag_trace_runtime_task_created(&kparent, &uchild, &created) != 0, "parent-only kthread rejected");
		ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after parent-only kthread create");
	}

	/* Case B: child-only PF_KTHREAD from tracked parent */
	{
		struct task_struct *root_ts = NULL;
		struct task_struct kchild = { .flags = PF_KTHREAD };
		struct spp_diag_trace_fact_task_alloc alloc = { .clone_flags = 0 };
		struct spp_diag_trace_fact_task_created created = { .pid = 10, .tgid = 10, .clone_flags = 0 };

		setup_published_runtime(&root_ts);
		ASSERT(spp_diag_trace_runtime_task_alloc_attempt(root_ts, &alloc) == 0, "alloc attempt succeeds");
		ASSERT(spp_diag_trace_runtime_task_created(root_ts, &kchild, &created) != 0, "child-only kthread rejected");
		ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after child-only kthread create");
	}

	/* Case C: exit with PF_KTHREAD cleared before report */
	{
		struct task_struct *root_ts = NULL;
		struct task_struct ex_kthread = { .flags = 0 }; /* flag cleared */

		setup_published_runtime(&root_ts);
		ASSERT(spp_diag_trace_runtime_task_exit(&ex_kthread, 0) != 0, "exit with cleared kthread flag rejected");
		ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after untracked non-kthread exit");
	}

	printf("PASS: test_pf_kthread_red_twins\n");
}

static void test_file_open_lifecycle(void)
{
	struct task_struct *root_ts = NULL;
	char path_buf[64] = "/etc/systemd/system.conf";
	struct spp_diag_trace_fact_file_open_attempt attempt = {
		.path = path_buf,
		.path_len = strlen(path_buf),
		.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
		.modifiers = SPP_DIAG_TRACE_FILE_MOD_NOFOLLOW,
		.dirfd = 0xFFFFFF9C, /* AT_FDCWD */
	};
	struct spp_diag_trace_fact_file_policy policy = {
		.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
		.modifiers = SPP_DIAG_TRACE_FILE_MOD_NOFOLLOW,
		.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
		.object_kind = SPP_DIAG_TRACE_FILE_OBJECT_REGULAR,
		.result = 0,
		.fs_magic = 0xEF53,
		.dev_major = 8,
		.dev_minor = 1,
		.inode = 12345,
		.mount_identity = 67890,
		.observed_size = 4096,
	};
	u64 op_ord = 0;
	size_t req_cap = 0;
	const u8 *stream;
	struct frame_view f;

	setup_published_runtime(&root_ts);

	/* 1. File open attempt */
	ASSERT(spp_diag_trace_runtime_file_open_attempt(root_ts, &attempt, &op_ord) == 0, "file open attempt");
	ASSERT(op_ord == 2, "first op ordinal is 2");

	/* Pointer poison check: overwrite source buffer */
	memset(path_buf, 'Z', sizeof(path_buf));

	/* 2. File policy decision */
	ASSERT(spp_diag_trace_runtime_file_policy_decision(root_ts, op_ord, &policy) == 0, "file policy decision");

	/* 3. Operation return */
	ASSERT(spp_diag_trace_runtime_operation_return(root_ts, op_ord, 0) == 0, "file open return");
	ASSERT(spp_diag_trace_core_is_green() == 1, "is green after file open lifecycle");

	/* Check stream */
	ASSERT(spp_diag_trace_core_snapshot(snap_buf, sizeof(snap_buf), &req_cap) == 0, "snapshot file open");
	memcpy(&meta, snap_buf, sizeof(meta));
	stream = snap_buf + sizeof(meta);
	ASSERT(meta.frame_count == 7, "7 frames total (1 init + 3 bootstrap + 3 file_open)");

	/* Stream entry 5 (seq 4): file_open_attempt */
	f = get_frame(stream, (size_t)meta.stream_len, 5);
	ASSERT(f.event_type == SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_OPEN_ATTEMPT, "entry 5 event_type");
	ASSERT(f.seq == 4, "entry 5 seq == 4");
	ASSERT(f.task_ord == 1, "entry 5 task == 1");
	ASSERT(f.op_ord == 2, "entry 5 op == 2");
	ASSERT(load_u16be(f.payload) == 1, "entry 5 action == 1");
	ASSERT(load_u16be(f.payload + 2) == 24, "entry 5 path_len == 24");
	ASSERT(load_u16be(f.payload + 4) == SPP_DIAG_TRACE_FILE_ACCESS_READ, "entry 5 access == READ");
	ASSERT(load_u16be(f.payload + 6) == SPP_DIAG_TRACE_FILE_MOD_NOFOLLOW, "entry 5 mod == NOFOLLOW");
	ASSERT(load_u32be(f.payload + 8) == 0xFFFFFF9C, "entry 5 dirfd");
	ASSERT(load_u32be(f.payload + 12) == 0, "entry 5 reserved == 0");
	ASSERT(memcmp(f.payload + 16, "/etc/systemd/system.conf", 24) == 0, "entry 5 path unpoisoned");

	/* Stream entry 6 (seq 5): file_policy_decision */
	f = get_frame(stream, (size_t)meta.stream_len, 6);
	ASSERT(f.event_type == SPP_DIAG_TRACE_PROVENANCE_EVENT_FILE_POLICY_DECISION, "entry 6 event_type");
	ASSERT(f.seq == 5, "entry 6 seq == 5");
	ASSERT(f.task_ord == 1, "entry 6 task == 1");
	ASSERT(f.op_ord == 2, "entry 6 op == 2");
	ASSERT(f.payload_len == 48, "entry 6 payload_len == 48");
	ASSERT(load_u16be(f.payload) == SPP_DIAG_TRACE_FILE_ACCESS_READ, "entry 6 access");
	ASSERT(load_u16be(f.payload + 2) == SPP_DIAG_TRACE_FILE_MOD_NOFOLLOW, "entry 6 modifiers");
	ASSERT(load_u16be(f.payload + 4) == SPP_DIAG_TRACE_POLICY_ALLOW, "entry 6 decision");
	ASSERT(load_u16be(f.payload + 6) == SPP_DIAG_TRACE_FILE_OBJECT_REGULAR, "entry 6 object_kind");
	ASSERT(load_u32be(f.payload + 8) == 0, "entry 6 result");
	ASSERT(load_u32be(f.payload + 12) == 0xEF53, "entry 6 fs_magic");
	ASSERT(load_u32be(f.payload + 16) == 8, "entry 6 dev_major");
	ASSERT(load_u32be(f.payload + 20) == 1, "entry 6 dev_minor");
	ASSERT(load_u64be(f.payload + 24) == 12345, "entry 6 inode");
	ASSERT(load_u64be(f.payload + 32) == 67890, "entry 6 mount");
	ASSERT(load_u64be(f.payload + 40) == 4096, "entry 6 size");

	/* Stream entry 7 (seq 6): operation_return */
	f = get_frame(stream, (size_t)meta.stream_len, 7);
	ASSERT(f.event_type == SPP_DIAG_TRACE_PROVENANCE_EVENT_OPERATION_RETURN, "entry 7 event_type");
	ASSERT(f.seq == 6, "entry 7 seq == 6");
	ASSERT(f.task_ord == 1, "entry 7 task == 1");
	ASSERT(f.op_ord == 2, "entry 7 op == 2");
	ASSERT(load_u16be(f.payload) == SPP_DIAG_TRACE_RUNTIME_OP_FILE_OPEN, "entry 7 kind == 1");
	ASSERT(load_u64be(f.payload + 8) == 0, "entry 7 result == 0");

	printf("PASS: test_file_open_lifecycle\n");
}

static void test_file_open_policy_rejection_cases(void)
{
	/* Case 1: second FILE_POLICY_DECISION on same operation */
	{
		struct task_struct *root_ts = NULL;
		struct spp_diag_trace_fact_file_open_attempt attempt = {
			.path = "/etc/passwd",
			.path_len = strlen("/etc/passwd"),
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0,
			.dirfd = 0,
		};
		struct spp_diag_trace_fact_file_policy policy = {
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0,
			.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
			.object_kind = SPP_DIAG_TRACE_FILE_OBJECT_REGULAR,
			.result = 0,
			.fs_magic = 0xEF53,
			.dev_major = 8,
			.dev_minor = 1,
			.inode = 100,
			.mount_identity = 200,
			.observed_size = 500,
		};
		u64 op_ord = 0;

		setup_published_runtime(&root_ts);
		ASSERT(spp_diag_trace_runtime_file_open_attempt(root_ts, &attempt, &op_ord) == 0, "open attempt");
		ASSERT(spp_diag_trace_runtime_file_policy_decision(root_ts, op_ord, &policy) == 0, "first policy decision");
		ASSERT(spp_diag_trace_runtime_file_policy_decision(root_ts, op_ord, &policy) != 0, "second policy decision rejected");
		ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after second policy row");
	}

	/* Case 2: access / modifiers mismatch between attempt and policy */
	{
		struct task_struct *root_ts = NULL;
		struct spp_diag_trace_fact_file_open_attempt attempt = {
			.path = "/etc/shadow",
			.path_len = strlen("/etc/shadow"),
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0,
			.dirfd = 0,
		};
		struct spp_diag_trace_fact_file_policy mismatched_policy = {
			.access = SPP_DIAG_TRACE_FILE_ACCESS_WRITE, /* mismatch! */
			.modifiers = 0,
			.decision = SPP_DIAG_TRACE_POLICY_DENY,
			.object_kind = SPP_DIAG_TRACE_FILE_OBJECT_REGULAR,
			.result = 0x8000000D,
			.fs_magic = 0xEF53,
			.dev_major = 8,
			.dev_minor = 1,
			.inode = 101,
			.mount_identity = 200,
			.observed_size = 500,
		};
		u64 op_ord = 0;

		setup_published_runtime(&root_ts);
		ASSERT(spp_diag_trace_runtime_file_open_attempt(root_ts, &attempt, &op_ord) == 0, "open attempt");
		ASSERT(spp_diag_trace_runtime_file_policy_decision(root_ts, op_ord, &mismatched_policy) != 0, "mismatched access rejected");
		ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after mismatched access");
	}

	printf("PASS: test_file_open_policy_rejection_cases\n");
}

static void test_mmap_lifecycle_and_overlap(void)
{
	struct task_struct *root_ts = NULL;
	struct spp_diag_trace_fact_mapping_policy mmap_fact = {
		.operation = SPP_DIAG_TRACE_MAPPING_OPERATION_MMAP,
		.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
		.backing = SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR,
		.mode = SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE,
		.requested = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_EXEC,
		.effective = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_EXEC,
		.prior = 0,
		.result = 0,
		.fs_magic = 0xEF53,
		.dev_major = 8,
		.dev_minor = 1,
		.seals = 0,
		.inode = 2000,
		.mount_identity = 3000,
		.observed_size = 8192,
	};
	u64 op_ord = 0;

	setup_published_runtime(&root_ts);

	/* 1. First MMAP succeeds */
	ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root_ts, &mmap_fact, &op_ord) == 0, "mmap 1 succeeds");
	ASSERT(op_ord == 2, "mmap op ordinal == 2");
	ASSERT(spp_diag_trace_core_is_green() == 1, "is green");

	/* 2. Attempting a second MMAP while the first is unreturned must fail (same kind overlap) */
	ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root_ts, &mmap_fact, NULL) != 0, "mmap overlap rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after overlap");

	/* Clean run for close */
	{
		setup_published_runtime(&root_ts);
		ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root_ts, &mmap_fact, &op_ord) == 0, "mmap succeeds");
		ASSERT(spp_diag_trace_runtime_operation_return(root_ts, op_ord, 0) == 0, "mmap return");
		ASSERT(spp_diag_trace_core_is_green() == 1, "is green after mmap close");
	}

	printf("PASS: test_mmap_lifecycle_and_overlap\n");
}

static void test_mprotect_lifecycle_and_deny_cutoff(void)
{
	struct task_struct *root_ts = NULL;
	struct spp_diag_trace_fact_mapping_policy row1 = {
		.operation = SPP_DIAG_TRACE_MAPPING_OPERATION_MPROTECT,
		.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
		.backing = SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR,
		.mode = SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE,
		.requested = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_WRITE | SPP_DIAG_TRACE_MAPPING_PROT_EXEC,
		.effective = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_WRITE | SPP_DIAG_TRACE_MAPPING_PROT_EXEC,
		.prior = SPP_DIAG_TRACE_MAPPING_PROT_READ,
		.result = 0,
		.fs_magic = 0xEF53,
		.dev_major = 8,
		.dev_minor = 1,
		.seals = 0,
		.inode = 2000,
		.mount_identity = 3000,
		.observed_size = 8192,
	};
	struct spp_diag_trace_fact_mapping_policy row2 = {
		.operation = SPP_DIAG_TRACE_MAPPING_OPERATION_MPROTECT,
		.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
		.backing = SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR,
		.mode = SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE,
		.requested = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_EXEC,
		.effective = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_EXEC,
		.prior = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_WRITE,
		.result = 0,
		.fs_magic = 0xEF53,
		.dev_major = 8,
		.dev_minor = 1,
		.seals = 0,
		.inode = 2000,
		.mount_identity = 3000,
		.observed_size = 8192,
	};
	struct spp_diag_trace_fact_mapping_policy row3_deny = {
		.operation = SPP_DIAG_TRACE_MAPPING_OPERATION_MPROTECT,
		.decision = SPP_DIAG_TRACE_POLICY_DENY,
		.backing = SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR,
		.mode = SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE,
		.requested = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_WRITE | SPP_DIAG_TRACE_MAPPING_PROT_EXEC,
		.effective = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_WRITE | SPP_DIAG_TRACE_MAPPING_PROT_EXEC,
		.prior = SPP_DIAG_TRACE_MAPPING_PROT_READ,
		.result = 0x80000001,
		.fs_magic = 0xEF53,
		.dev_major = 8,
		.dev_minor = 1,
		.seals = 0,
		.inode = 2000,
		.mount_identity = 3000,
		.observed_size = 8192,
	};
	struct spp_diag_trace_fact_mapping_policy row4_after_deny = {
		.operation = SPP_DIAG_TRACE_MAPPING_OPERATION_MPROTECT,
		.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
		.backing = SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR,
		.mode = SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE,
		.requested = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_EXEC,
		.effective = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_EXEC,
		.prior = SPP_DIAG_TRACE_MAPPING_PROT_READ,
		.result = 0,
		.fs_magic = 0xEF53,
		.dev_major = 8,
		.dev_minor = 1,
		.seals = 0,
		.inode = 2000,
		.mount_identity = 3000,
		.observed_size = 8192,
	};
	u64 op_ord1 = 0, op_ord2 = 0, op_ord3 = 0;

	setup_published_runtime(&root_ts);

	/* Multi-row mprotect reuse */
	ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root_ts, &row1, &op_ord1) == 0, "mprotect row 1");
	ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root_ts, &row2, &op_ord2) == 0, "mprotect row 2");
	ASSERT(op_ord1 == op_ord2, "row 1 and row 2 reuse same op");
	ASSERT(spp_diag_trace_core_is_green() == 1, "is green after 2 rows");

	/* Deny row on the same op */
	ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root_ts, &row3_deny, &op_ord3) == 0, "mprotect row 3 deny");
	ASSERT(op_ord1 == op_ord3, "deny row on same op");
	ASSERT(spp_diag_trace_core_is_green() == 1, "is green (deny decision is valid event)");

	/* Appending another row after DENY must fail */
	ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root_ts, &row4_after_deny, NULL) != 0, "row after deny rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after row appended post-deny");

	/* Clean run for multi-row + return */
	{
		setup_published_runtime(&root_ts);
		ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root_ts, &row1, &op_ord1) == 0, "clean mprotect row 1");
		ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root_ts, &row2, &op_ord2) == 0, "clean mprotect row 2");
		ASSERT(spp_diag_trace_runtime_operation_return(root_ts, op_ord1, 0) == 0, "mprotect return");
		ASSERT(spp_diag_trace_core_is_green() == 1, "is green after multi-row mprotect return");
	}

	printf("PASS: test_mprotect_lifecycle_and_deny_cutoff\n");
}

static void test_mapping_missing_prot_exec_rejection(void)
{
	struct task_struct *root_ts = NULL;
	struct spp_diag_trace_fact_mapping_policy no_exec = {
		.operation = SPP_DIAG_TRACE_MAPPING_OPERATION_MMAP,
		.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
		.backing = SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR,
		.mode = SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE,
		.requested = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_WRITE,
		.effective = SPP_DIAG_TRACE_MAPPING_PROT_READ | SPP_DIAG_TRACE_MAPPING_PROT_WRITE, /* missing PROT_EXEC */
		.prior = 0,
		.result = 0,
		.fs_magic = 0xEF53,
		.dev_major = 8,
		.dev_minor = 1,
		.seals = 0,
		.inode = 2000,
		.mount_identity = 3000,
		.observed_size = 8192,
	};

	setup_published_runtime(&root_ts);
	ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root_ts, &no_exec, NULL) != 0, "mapping without PROT_EXEC rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after non-exec mapping");

	printf("PASS: test_mapping_missing_prot_exec_rejection\n");
}

static void test_network_lifecycle_and_overlap(void)
{
	/* Case 1: duplicate CONNECT overlap */
	{
		struct task_struct *root_ts = NULL;
		struct spp_diag_trace_fact_network_policy connect1 = {
			.operation = SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT,
			.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
			.kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4,
			.source = SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT,
			.socket_kind = SPP_DIAG_TRACE_NETWORK_SOCKET_STREAM,
			.protocol = 6,
			.family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET,
			.addrlen = 16,
			.result = 0,
			.flags = 0,
			.size = 0,
			.cookie = 0x1122334455667788ull,
			.port = 443,
			.reserved = 0,
			.scope = 0,
			.flow = 0,
			.address = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1 },
		};
		u64 op_ord1 = 0;

		setup_published_runtime(&root_ts);
		ASSERT(spp_diag_trace_runtime_network_policy_decision(root_ts, &connect1, &op_ord1) == 0, "first connect succeeds");
		ASSERT(spp_diag_trace_core_is_green() == 1, "is green after first connect");
		ASSERT(spp_diag_trace_runtime_network_policy_decision(root_ts, &connect1, NULL) != 0, "second live connect rejected");
		ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after connect overlap");
	}

	/* Case 2: duplicate SENDMSG overlap */
	{
		struct task_struct *root_ts = NULL;
		struct spp_diag_trace_fact_network_policy send1 = {
			.operation = SPP_DIAG_TRACE_NETWORK_OPERATION_SENDMSG,
			.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
			.kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4,
			.source = SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT,
			.socket_kind = SPP_DIAG_TRACE_NETWORK_SOCKET_DGRAM,
			.protocol = 17,
			.family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET,
			.addrlen = 16,
			.result = 0,
			.flags = 0,
			.size = 64,
			.cookie = 0x2233445566778899ull,
			.port = 53,
			.reserved = 0,
			.scope = 0,
			.flow = 0,
			.address = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2 },
		};
		u64 op_ord1 = 0;

		setup_published_runtime(&root_ts);
		ASSERT(spp_diag_trace_runtime_network_policy_decision(root_ts, &send1, &op_ord1) == 0, "first sendmsg succeeds");
		ASSERT(spp_diag_trace_core_is_green() == 1, "is green after first sendmsg");
		ASSERT(spp_diag_trace_runtime_network_policy_decision(root_ts, &send1, NULL) != 0, "second live sendmsg rejected");
		ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after sendmsg overlap");
	}

	printf("PASS: test_network_lifecycle_and_overlap\n");
}

static void test_network_simultaneous_connect_and_sendmsg(void)
{
	struct task_struct *root_ts = NULL;
	struct spp_diag_trace_fact_network_policy connect_fact = {
		.operation = SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT,
		.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
		.kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4,
		.source = SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT,
		.socket_kind = SPP_DIAG_TRACE_NETWORK_SOCKET_STREAM,
		.protocol = 6,
		.family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET,
		.addrlen = 16,
		.result = 0,
		.flags = 0,
		.size = 0,
		.cookie = 0x1000ull,
		.port = 80,
		.reserved = 0,
		.scope = 0,
		.flow = 0,
		.address = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1 },
	};
	struct spp_diag_trace_fact_network_policy sendmsg_fact = {
		.operation = SPP_DIAG_TRACE_NETWORK_OPERATION_SENDMSG,
		.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
		.kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV6,
		.source = SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_CONNECTED,
		.socket_kind = SPP_DIAG_TRACE_NETWORK_SOCKET_DGRAM,
		.protocol = 17,
		.family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET6,
		.addrlen = 0,
		.result = 0,
		.flags = 0,
		.size = 256,
		.cookie = 0x2000ull,
		.port = 5353,
		.reserved = 0,
		.scope = 0,
		.flow = 0,
		.address = { 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb },
	};
	u64 op_connect = 0, op_sendmsg = 0;

	setup_published_runtime(&root_ts);
	ASSERT(spp_diag_trace_runtime_network_policy_decision(root_ts, &connect_fact, &op_connect) == 0, "connect opens");
	ASSERT(spp_diag_trace_runtime_network_policy_decision(root_ts, &sendmsg_fact, &op_sendmsg) == 0, "sendmsg opens simultaneously");
	ASSERT(op_connect != op_sendmsg, "connect and sendmsg have distinct operation ordinals");
	ASSERT(spp_diag_trace_core_is_green() == 1, "is green with both live");

	ASSERT(spp_diag_trace_runtime_operation_return(root_ts, op_connect, 0) == 0, "connect returns");
	ASSERT(spp_diag_trace_runtime_operation_return(root_ts, op_sendmsg, 0) == 0, "sendmsg returns");
	ASSERT(spp_diag_trace_core_is_green() == 1, "is green after both return");

	printf("PASS: test_network_simultaneous_connect_and_sendmsg\n");
}

static void test_network_untracked_task_rejection(void)
{
	struct task_struct *root_ts = NULL;
	struct task_struct untracked = { .pid = 999, .tgid = 999, .flags = 0 };
	struct spp_diag_trace_fact_network_policy connect_fact = {
		.operation = SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT,
		.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
		.kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4,
		.source = SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT,
		.socket_kind = SPP_DIAG_TRACE_NETWORK_SOCKET_STREAM,
		.protocol = 6,
		.family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET,
		.addrlen = 16,
		.result = 0,
		.flags = 0,
		.size = 0,
		.cookie = 0x1000ull,
		.port = 80,
		.reserved = 0,
		.scope = 0,
		.flow = 0,
		.address = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1 },
	};

	setup_published_runtime(&root_ts);
	ASSERT(spp_diag_trace_runtime_network_policy_decision(&untracked, &connect_fact, NULL) != 0, "untracked task rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after untracked network op");

	printf("PASS: test_network_untracked_task_rejection\n");
}

static void test_network_malformed_relational_rejection(void)
{
	struct task_struct *root_ts = NULL;
	/* kind==IPV4 with family==AF_INET6 mismatch */
	struct spp_diag_trace_fact_network_policy mismatched = {
		.operation = SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT,
		.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
		.kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4,
		.source = SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT,
		.socket_kind = SPP_DIAG_TRACE_NETWORK_SOCKET_STREAM,
		.protocol = 6,
		.family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET6, /* mismatch! */
		.addrlen = 16,
		.result = 0,
		.flags = 0,
		.size = 0,
		.cookie = 0x1000ull,
		.port = 80,
		.reserved = 0,
		.scope = 0,
		.flow = 0,
		.address = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1 },
	};

	setup_published_runtime(&root_ts);
	ASSERT(spp_diag_trace_runtime_network_policy_decision(root_ts, &mismatched, NULL) != 0, "relational mismatch rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after relational mismatch");

	printf("PASS: test_network_malformed_relational_rejection\n");
}

static void test_uncommitted_exec_denial_return_semantics(void)
{
	struct task_struct *root_ts = NULL;
	struct spp_diag_trace_fact_exec_attempt attempt = {
		.path = "/bin/denied-canary",
		.path_len = strlen("/bin/denied-canary"),
		.pid = 1,
		.tgid = 1,
	};

	/* 1. Uncommitted exec returning positive result is rejected with sticky red */
	setup_published_runtime(&root_ts);
	ASSERT(spp_diag_trace_runtime_exec_attempt(root_ts, &attempt) == 0, "attempt");
	ASSERT(spp_diag_trace_runtime_operation_return(root_ts, 2, 1) != 0, "positive return rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after positive uncommitted return");

	/* 2. Uncommitted exec returning zero (success) result is rejected with sticky red */
	setup_published_runtime(&root_ts);
	ASSERT(spp_diag_trace_runtime_exec_attempt(root_ts, &attempt) == 0, "attempt");
	ASSERT(spp_diag_trace_runtime_operation_return(root_ts, 2, 0) != 0, "zero return rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "sticky red after zero uncommitted return");

	/* 3. Uncommitted exec returning strictly negative result succeeds and core remains green */
	setup_published_runtime(&root_ts);
	ASSERT(spp_diag_trace_runtime_exec_attempt(root_ts, &attempt) == 0, "attempt");
	ASSERT(spp_diag_trace_runtime_operation_return(root_ts, 2, -13) == 0, "negative return succeeds");
	ASSERT(spp_diag_trace_core_is_green() == 1, "green after negative uncommitted return");

	printf("PASS: test_uncommitted_exec_denial_return_semantics\n");
}

int main(void)
{
	test_root_binding_direct_record();
	test_tracked_child_lifecycle();
	test_exec_multipass_commit_return_and_poison();
	test_generic_operation_primitives();
	test_same_kind_overlap_rejection();
	test_untracked_exec_rejection();
	test_pf_kthread_ignore_twins();
	test_pf_kthread_red_twins();
	test_file_open_lifecycle();
	test_file_open_policy_rejection_cases();
	test_mmap_lifecycle_and_overlap();
	test_mprotect_lifecycle_and_deny_cutoff();
	test_mapping_missing_prot_exec_rejection();
	test_network_lifecycle_and_overlap();
	test_network_simultaneous_connect_and_sendmsg();
	test_network_untracked_task_rejection();
	test_network_malformed_relational_rejection();
	test_uncommitted_exec_denial_return_semantics();
	printf("All runtime lifecycle tests passed successfully.\n");
	return 0;
}
