/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kmod.h>
#include <linux/ima.h>
#include <linux/security.h>
#include <linux/spp_diag_trace_bootstrap.h>
#include <linux/spp_diag_trace_runtime.h>

#include "protocol_constants.h"
#include "runtime_types.h"
#include "core.h"

/* Header Init Values matching STREAM_HEX */
static const u8 challenge_bytes[32] = {
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};
static const u8 run_identity_bytes[32] = {
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f
};
static const u8 control_plan_bytes[32] = {
	0xae, 0x00, 0x78, 0xc8, 0x8d, 0xe3, 0x52, 0x02, 0x2f, 0x76, 0x88, 0xb1, 0x78, 0x13, 0x47, 0x3d,
	0xd3, 0x92, 0xd0, 0x66, 0x17, 0x8f, 0xd3, 0x20, 0x01, 0xb5, 0x7e, 0x1d, 0x7e, 0xf0, 0x35, 0xaf
};
static const u8 command_line_sha256[32] = {
	0x62, 0x62, 0x29, 0xf9, 0x77, 0xac, 0x86, 0x0c, 0x4d, 0x0e, 0xb1, 0xee, 0x0c, 0x52, 0xf6, 0x88,
	0x6e, 0xab, 0x94, 0x47, 0xf1, 0x93, 0x76, 0xe1, 0x9d, 0x39, 0xdd, 0xa7, 0x0a, 0x38, 0x4f, 0x9b
};

static struct spp_diag_trace_task_record task_records[4096];
static struct spp_diag_trace_operation_record op_records[32768];

static u64 get_task_open_op(u64 task_ordinal)
{
	for (size_t j = 0; j < 32768; j++) {
		if (op_records[j].task_ordinal == task_ordinal &&
		    (op_records[j].state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_OPEN ||
		     op_records[j].state == SPP_DIAG_TRACE_RUNTIME_OP_STATE_COMMITTED))
			return op_records[j].operation_ordinal;
	}
	return 0;
}

static void make_cmd(u8 *buf, u16 kind, u16 phase)
{
	static const u8 magic[8] = { SPP_DIAG_TRACE_MAGIC_COMMAND_BYTES };
	memset(buf, 0, SPP_DIAG_TRACE_COMMAND_SIZE);
	memcpy(buf, magic, 8);
	buf[8] = 0; buf[9] = 1;
	buf[10] = (u8)(kind >> 8); buf[11] = (u8)(kind & 0xff);
	buf[12] = 0; buf[13] = 0; buf[14] = 0; buf[15] = 128;
	memcpy(buf + 16, challenge_bytes, 32);
	memcpy(buf + 48, run_identity_bytes, 32);
	memcpy(buf + 80, control_plan_bytes, 32);
	buf[112] = (u8)(phase >> 8); buf[113] = (u8)(phase & 0xff);
}

static int advance_to(u16 next_phase)
{
	u8 cmd[128];
	make_cmd(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, next_phase);
	return spp_diag_trace_core_runtime_handle_command(cmd, sizeof(cmd));
}

static int seal_runtime(void)
{
	u8 cmd[128];
	make_cmd(cmd, SPP_DIAG_TRACE_CMD_SEAL, SPP_DIAG_TRACE_PHASE_SEALED);
	return spp_diag_trace_core_runtime_handle_command(cmd, sizeof(cmd));
}

int main(int argc, char **argv)
{
	u32 root_pid = 1;
	u32 root_tgid = 1;
	int mutate_task_correlation = 0;
	int mutate_op_close = 0;
	int mutate_phase_order = 0;
	int mutate_terminal = 0;
	int flag_wrong_poison_path = 0;
	int flag_wrong_endpoint = 0;
	int flag_successful_denial_canary = 0;
	int flag_absent_canary = 0;
	struct task_struct root_task;
	struct task_struct child2, child3, child4;
	u8 ready_buf[SPP_DIAG_TRACE_IMA_SIZE];
	u8 release_buf[SPP_DIAG_TRACE_IMA_SIZE];
	u8 snapshot_buf[65536];
	struct spp_diag_trace_core_snapshot *snap = (struct spp_diag_trace_core_snapshot *)snapshot_buf;
	size_t required = 0;
	u64 op_ord = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--mutate-task-correlation") == 0)
			mutate_task_correlation = 1;
		else if (strcmp(argv[i], "--mutate-op-close") == 0)
			mutate_op_close = 1;
		else if (strcmp(argv[i], "--mutate-phase-order") == 0)
			mutate_phase_order = 1;
		else if (strcmp(argv[i], "--mutate-terminal") == 0)
			mutate_terminal = 1;
		else if (strcmp(argv[i], "--wrong-poison-path") == 0)
			flag_wrong_poison_path = 1;
		else if (strcmp(argv[i], "--wrong-endpoint") == 0)
			flag_wrong_endpoint = 1;
		else if (strcmp(argv[i], "--successful-denial-canary") == 0)
			flag_successful_denial_canary = 1;
		else if (strcmp(argv[i], "--absent-canary") == 0)
			flag_absent_canary = 1;
	}

	memset(&root_task, 0, sizeof(root_task));
	root_task.pid = root_pid;
	root_task.tgid = root_tgid;

	memset(&child2, 0, sizeof(child2));
	child2.pid = 2002;
	child2.tgid = 2002;

	memset(&child3, 0, sizeof(child3));
	child3.pid = 3003;
	child3.tgid = 3003;

	memset(&child4, 0, sizeof(child4));
	child4.pid = 4004;
	child4.tgid = 4004;

	host_kmod_reset();
	host_ima_reset();
	host_securityfs_reset();
	host_current_task.pid = root_pid;
	host_current_task.tgid = root_tgid;
	host_current_task.flags = 0;
	host_current_task_ptr = &root_task;

	spp_diag_trace_core_reset();
	spp_diag_trace_core_set_op_caps(SPP_DIAG_TRACE_MAX_FRAMES, SPP_DIAG_TRACE_MAX_STREAM_BYTES);

	if (spp_diag_trace_core_init(challenge_bytes, run_identity_bytes,
				     control_plan_bytes, command_line_sha256)) {
		fprintf(stderr, "core init failed\n");
		return 1;
	}

	if (spp_diag_trace_core_runtime_install_arrays(task_records, 4096,
						       op_records, 32768)) {
		fprintf(stderr, "install arrays failed\n");
		return 1;
	}

	if (spp_diag_trace_runtime_fs_init()) {
		fprintf(stderr, "fs init failed\n");
		return 1;
	}

	/* seq 01: PRE_RELEASE_EXEC_DENIED */
	if (spp_diag_trace_core_bootstrap_ima_available() ||
	    spp_diag_trace_core_bootstrap_gate(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH,
					       strlen(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH),
					       root_pid, root_tgid) != -EACCES) {
		fprintf(stderr, "bootstrap denial record failed\n");
		return 1;
	}

	/* seq 02: IMA_READY */
	if (spp_diag_trace_core_bootstrap_prepare_ready(ready_buf) ||
	    spp_diag_trace_core_bootstrap_ready_measured()) {
		fprintf(stderr, "bootstrap ready failed\n");
		return 1;
	}

	/* seq 03: USERSPACE_RELEASE */
	if (spp_diag_trace_core_bootstrap_prepare_release(root_pid, root_tgid, release_buf) ||
	    spp_diag_trace_core_bootstrap_release_measured()) {
		fprintf(stderr, "bootstrap release failed\n");
		return 1;
	}

	/* Bind root task */
	host_current_task_ptr = &root_task;
	if (spp_diag_trace_core_bootstrap_publish() ||
	    spp_diag_trace_runtime_bind_root(&root_task)) {
		fprintf(stderr, "bootstrap publish / bind_root failed\n");
		return 1;
	}

	/* Phase 2: cold_start (seq 04: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_COLD_START)) {
		fprintf(stderr, "advance to phase 2 failed\n");
		return 1;
	}

	/* seq 05: TASK_ALLOC_ATTEMPT (child 2, op 2) */
	{
		struct spp_diag_trace_fact_task_alloc fact = { .clone_flags = 0x11 };
		if (spp_diag_trace_runtime_task_alloc_attempt(&root_task, &fact)) {
			fprintf(stderr, "task_alloc child2 failed\n");
			return 1;
		}
	}

	/* seq 06: TASK_CREATED (child 2) */
	{
		struct spp_diag_trace_fact_task_created fact = {
			.pid = 2002,
			.tgid = 2002,
			.clone_flags = 0x11,
		};
		const void *parent_ptr = &root_task;
		if (mutate_task_correlation) {
			/* Mutation (a): pass child3 as parent (which did not open op 2) */
			parent_ptr = &child3;
		}
		if (spp_diag_trace_runtime_task_created(parent_ptr, &child2, &fact)) {
			if (mutate_task_correlation) {
				/* Expected rejection: core went sticky red */
				if (!spp_diag_trace_core_is_green()) {
					fprintf(stderr, "MUTATION_TASK_CORRELATION_REJECTED\n");
					return 42;
				}
			}
			fprintf(stderr, "task_created child2 failed\n");
			return 1;
		}
		if (mutate_task_correlation) {
			fprintf(stderr, "mutation task correlation unexpectedly succeeded\n");
			return 1;
		}
	}

	/* seq 07: EXEC_ATTEMPT pass 1 (child 2, op 3) */
	/* seq 08: EXEC_ATTEMPT pass 2 (child 2, op 3) */
	{
		const char *path = "/opt/solstone/bin/synthetic-runtime";
		struct spp_diag_trace_fact_exec_attempt fact = {
			.path = path,
			.path_len = strlen(path),
			.pid = 2002,
			.tgid = 2002,
		};
		if (spp_diag_trace_runtime_exec_attempt(&child2, &fact) ||
		    spp_diag_trace_runtime_exec_attempt(&child2, &fact)) {
			fprintf(stderr, "exec attempt child2 failed\n");
			return 1;
		}
	}

	/* seq 09: EXEC_COMMIT (child 2, op 3) */
	{
		struct spp_diag_trace_fact_exec_commit fact = {
			.pid = 2002,
			.tgid = 2002,
		};
		if (spp_diag_trace_runtime_exec_commit(&child2, &fact)) {
			fprintf(stderr, "exec commit child2 failed\n");
			return 1;
		}
	}

	/* seq 10: OPERATION_RETURN (child 2, op 3) */
	if (!mutate_op_close) {
		if (spp_diag_trace_runtime_operation_return(&child2, 3, 0)) {
			fprintf(stderr, "op return child2 op 3 failed\n");
			return 1;
		}
	}

	/* seq 11: TASK_EXIT (child 2) */
	if (spp_diag_trace_runtime_task_exit(&child2, 0)) {
		if (mutate_op_close) {
			fprintf(stderr, "MUTATION_OP_CLOSE_REJECTED\n");
			return 43;
		}
		fprintf(stderr, "task exit child2 failed\n");
		return 1;
	}

	/* Phase 3: synthetic_inference (seq 12: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_SYNTHETIC_INFERENCE)) {
		if (mutate_op_close) {
			/* Mutation (b): rejected phase advance because op 3 is still open */
			fprintf(stderr, "MUTATION_OP_CLOSE_REJECTED\n");
			return 43;
		}
		fprintf(stderr, "advance to phase 3 failed\n");
		return 1;
	}
	if (mutate_op_close) {
		fprintf(stderr, "mutation op close unexpectedly succeeded\n");
		return 1;
	}

	/* seq 13: TASK_ALLOC_ATTEMPT (child 3, op 4) */
	{
		struct spp_diag_trace_fact_task_alloc fact = { .clone_flags = 0x11 };
		if (spp_diag_trace_runtime_task_alloc_attempt(&root_task, &fact)) {
			fprintf(stderr, "task_alloc child3 failed\n");
			return 1;
		}
	}

	/* seq 14: TASK_CREATED (child 3) */
	{
		struct spp_diag_trace_fact_task_created fact = {
			.pid = 3003,
			.tgid = 3003,
			.clone_flags = 0x11,
		};
		if (spp_diag_trace_runtime_task_created(&root_task, &child3, &fact)) {
			fprintf(stderr, "task_created child3 failed\n");
			return 1;
		}
	}

	/* seq 15: FILE_OPEN_ATTEMPT (child 3, op 5) */
	{
		const char *path = "/opt/solstone/models/synthetic-fixture-v1.bin";
		struct spp_diag_trace_fact_file_open_attempt fact = {
			.path = path,
			.path_len = strlen(path),
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0x10,
			.dirfd = (u32)-100,
		};
		if (spp_diag_trace_runtime_file_open_attempt(&child3, &fact, &op_ord) || op_ord != 5) {
			fprintf(stderr, "file_open_attempt child3 op 5 failed\n");
			return 1;
		}
	}

	/* seq 16: FILE_POLICY_DECISION (child 3, op 5) */
	{
		struct spp_diag_trace_fact_file_policy fact = {
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0x10,
			.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
			.object_kind = SPP_DIAG_TRACE_FILE_OBJECT_REGULAR,
			.result = 0,
			.fs_magic = 0xef53,
			.dev_major = 0x103,
			.dev_minor = 7,
			.inode = 0x1001,
			.mount_identity = 0xa1,
			.observed_size = 0x100000,
		};
		if (spp_diag_trace_runtime_file_policy_decision(&child3, 5, &fact)) {
			fprintf(stderr, "file_policy child3 op 5 failed\n");
			return 1;
		}
	}

	/* seq 17: OPERATION_RETURN (child 3, op 5) */
	if (spp_diag_trace_runtime_operation_return(&child3, 5, 5)) {
		fprintf(stderr, "op return child3 op 5 failed\n");
		return 1;
	}

	/* seq 18: MMAP POLICY (child 3, op 6) */
	{
		struct spp_diag_trace_fact_mapping_policy fact = {
			.operation = SPP_DIAG_TRACE_MAPPING_OPERATION_MMAP,
			.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
			.backing = SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR,
			.mode = SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE,
			.requested = 5,
			.effective = 5,
			.prior = 0,
			.result = 0,
			.fs_magic = 0xef53,
			.dev_major = 0x103,
			.dev_minor = 7,
			.seals = 0,
			.inode = 0x1001,
			.mount_identity = 0xa1,
			.observed_size = 0x100000,
		};
		if (spp_diag_trace_runtime_mapping_policy_decision(&child3, &fact, &op_ord) || op_ord != 6) {
			fprintf(stderr, "mmap_policy child3 op 6 failed\n");
			return 1;
		}
	}

	/* seq 19: OPERATION_RETURN (child 3, op 6) */
	if (spp_diag_trace_runtime_operation_return(&child3, 6, 0x71000000)) {
		fprintf(stderr, "op return child3 op 6 failed\n");
		return 1;
	}

	/* seq 20: FILE_OPEN_ATTEMPT (child 3, op 7) */
	{
		const char *path = "/etc/ssl/certs/ca-certificates.crt";
		struct spp_diag_trace_fact_file_open_attempt fact = {
			.path = path,
			.path_len = strlen(path),
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0x10,
			.dirfd = (u32)-100,
		};
		if (spp_diag_trace_runtime_file_open_attempt(&child3, &fact, &op_ord) || op_ord != 7) {
			fprintf(stderr, "file_open_attempt child3 op 7 failed\n");
			return 1;
		}
	}

	/* seq 21: FILE_POLICY_DECISION (child 3, op 7) */
	{
		struct spp_diag_trace_fact_file_policy fact = {
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0x10,
			.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
			.object_kind = SPP_DIAG_TRACE_FILE_OBJECT_REGULAR,
			.result = 0,
			.fs_magic = 0xef53,
			.dev_major = 0x103,
			.dev_minor = 7,
			.inode = 0x2002,
			.mount_identity = 0xa1,
			.observed_size = 0x34000,
		};
		if (spp_diag_trace_runtime_file_policy_decision(&child3, 7, &fact)) {
			fprintf(stderr, "file_policy child3 op 7 failed\n");
			return 1;
		}
	}

	/* seq 22: OPERATION_RETURN (child 3, op 7) */
	if (spp_diag_trace_runtime_operation_return(&child3, 7, -5)) {
		fprintf(stderr, "op return child3 op 7 failed\n");
		return 1;
	}

	/* seq 23: TASK_EXIT (child 3) */
	if (spp_diag_trace_runtime_task_exit(&child3, 0)) {
		fprintf(stderr, "task exit child3 failed\n");
		return 1;
	}

	/* seq 24: TASK_ALLOC_ATTEMPT (child 4, op 8) */
	{
		struct spp_diag_trace_fact_task_alloc fact = { .clone_flags = 0x11 };
		if (spp_diag_trace_runtime_task_alloc_attempt(&root_task, &fact)) {
			fprintf(stderr, "task_alloc child4 failed\n");
			return 1;
		}
	}

	/* seq 25: TASK_CREATED (child 4) */
	{
		struct spp_diag_trace_fact_task_created fact = {
			.pid = 4004,
			.tgid = 4004,
			.clone_flags = 0x11,
		};
		if (spp_diag_trace_runtime_task_created(&root_task, &child4, &fact)) {
			fprintf(stderr, "task_created child4 failed\n");
			return 1;
		}
	}

	/* seq 26: EXEC_ATTEMPT pass 1 (child 4, op 9) */
	{
		const char *path = "/opt/solstone/bin/postcommit-invalid-image";
		struct spp_diag_trace_fact_exec_attempt fact = {
			.path = path,
			.path_len = strlen(path),
			.pid = 4004,
			.tgid = 4004,
		};
		if (spp_diag_trace_runtime_exec_attempt(&child4, &fact)) {
			fprintf(stderr, "exec attempt child4 failed\n");
			return 1;
		}
	}

	/* seq 27: EXEC_COMMIT (child 4, op 9) */
	{
		struct spp_diag_trace_fact_exec_commit fact = {
			.pid = 4004,
			.tgid = 4004,
		};
		if (spp_diag_trace_runtime_exec_commit(&child4, &fact)) {
			fprintf(stderr, "exec commit child4 failed\n");
			return 1;
		}
	}

	/* seq 28: OPERATION_RETURN (child 4, op 9) */
	if (spp_diag_trace_runtime_operation_return(&child4, 9, -8)) {
		fprintf(stderr, "op return child4 op 9 failed\n");
		return 1;
	}

	/* seq 29: TASK_EXIT (child 4) */
	if (spp_diag_trace_runtime_task_exit(&child4, 11)) {
		fprintf(stderr, "task exit child4 failed\n");
		return 1;
	}

	/* Phase 4: poison_import (seq 30: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_POISON_IMPORT)) {
		fprintf(stderr, "advance to phase 4 failed\n");
		return 1;
	}

	if (!flag_absent_canary) {
		/* seq 31: FILE_OPEN_ATTEMPT (root, op 10) */
		{
			const char *path = flag_wrong_poison_path ?
				"/var/lib/solstone/poison/other.py" :
				"/var/lib/solstone/poison/import.py";
			struct spp_diag_trace_fact_file_open_attempt fact = {
				.path = path,
				.path_len = strlen(path),
				.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
				.modifiers = 0x18,
				.dirfd = (u32)-100,
			};
			if (spp_diag_trace_runtime_file_open_attempt(&root_task, &fact, &op_ord)) {
				fprintf(stderr, "file_open_attempt root op 10 failed\n");
				return 1;
			}
		}

		/* seq 32: OPERATION_RETURN (root, op 10) */
		if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), -2)) {
			fprintf(stderr, "op return root op 10 failed\n");
			return 1;
		}
	}

	/* Phase 5: poison_module (seq 33: PHASE_MARKER) */
	if (mutate_phase_order) {
		/* Mutation (c): skip phase 5 and advance straight to phase 6 */
		if (advance_to(SPP_DIAG_TRACE_PHASE_POISON_LIBRARY)) {
			fprintf(stderr, "MUTATION_PHASE_ORDER_REJECTED\n");
			return 44;
		}
		fprintf(stderr, "mutation phase order unexpectedly succeeded\n");
		return 1;
	}

	if (advance_to(SPP_DIAG_TRACE_PHASE_POISON_MODULE)) {
		fprintf(stderr, "advance to phase 5 failed\n");
		return 1;
	}

	/* seq 34: FILE_OPEN_ATTEMPT (root, op 11) */
	{
		const char *path = "/var/lib/solstone/poison/module.so";
		struct spp_diag_trace_fact_file_open_attempt fact = {
			.path = path,
			.path_len = strlen(path),
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0x18,
			.dirfd = (u32)-100,
		};
		if (spp_diag_trace_runtime_file_open_attempt(&root_task, &fact, &op_ord)) {
			fprintf(stderr, "file_open_attempt root op 11 failed\n");
			return 1;
		}
	}

	/* seq 35: OPERATION_RETURN (root, op 11) */
	if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), -2)) {
		fprintf(stderr, "op return root op 11 failed\n");
		return 1;
	}

	/* Phase 6: poison_library (seq 36: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_POISON_LIBRARY)) {
		fprintf(stderr, "advance to phase 6 failed\n");
		return 1;
	}

	/* seq 37: FILE_OPEN_ATTEMPT (root, op 12) */
	{
		const char *path = "/var/lib/solstone/poison/libinject.so";
		struct spp_diag_trace_fact_file_open_attempt fact = {
			.path = path,
			.path_len = strlen(path),
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0x18,
			.dirfd = (u32)-100,
		};
		if (spp_diag_trace_runtime_file_open_attempt(&root_task, &fact, &op_ord)) {
			fprintf(stderr, "file_open_attempt root op 12 failed\n");
			return 1;
		}
	}

	/* seq 38: OPERATION_RETURN (root, op 12) */
	if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), -2)) {
		fprintf(stderr, "op return root op 12 failed\n");
		return 1;
	}

	/* Phase 7: remote_package (seq 39: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_REMOTE_PACKAGE)) {
		fprintf(stderr, "advance to phase 7 failed\n");
		return 1;
	}

	/* seq 40: NETWORK_POLICY_DECISION (root, op 13) */
	{
		struct spp_diag_trace_fact_network_policy fact = {
			.operation = SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT,
			.decision = SPP_DIAG_TRACE_POLICY_DENY,
			.kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4,
			.source = SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT,
			.socket_kind = SPP_DIAG_TRACE_NETWORK_SOCKET_STREAM,
			.protocol = 6,
			.family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET,
			.addrlen = 16,
			.result = 0xfffffff3,
			.flags = 0,
			.size = 0,
			.cookie = 0xc001,
			.port = 443,
			.reserved = 0,
			.scope = 0,
			.flow = 0,
			.address = { 0,0,0,0,0,0,0,0,0,0,0,0, 0xc6, 0x33, 0x64, (u8)(flag_wrong_endpoint ? 0x08 : 0x07) },
		};
		if (spp_diag_trace_runtime_network_policy_decision(&root_task, &fact, &op_ord)) {
			fprintf(stderr, "connect root op 13 failed\n");
			return 1;
		}
	}

	/* seq 41: OPERATION_RETURN (root, op 13) */
	if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), -13)) {
		fprintf(stderr, "op return root op 13 failed\n");
		return 1;
	}

	/* Phase 8: remote_model (seq 42: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_REMOTE_MODEL)) {
		fprintf(stderr, "advance to phase 8 failed\n");
		return 1;
	}

	/* seq 43: NETWORK_POLICY_DECISION (root, op 14) */
	{
		struct spp_diag_trace_fact_network_policy fact = {
			.operation = SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT,
			.decision = SPP_DIAG_TRACE_POLICY_DENY,
			.kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV6,
			.source = SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT,
			.socket_kind = SPP_DIAG_TRACE_NETWORK_SOCKET_STREAM,
			.protocol = 6,
			.family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET6,
			.addrlen = 28,
			.result = 0xfffffff3,
			.flags = 0,
			.size = 0,
			.cookie = 0xc002,
			.port = 443,
			.reserved = 0,
			.scope = 0,
			.flow = 0,
			.address = { 0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,0x08 },
		};
		if (spp_diag_trace_runtime_network_policy_decision(&root_task, &fact, &op_ord)) {
			fprintf(stderr, "connect root op 14 failed\n");
			return 1;
		}
	}

	/* seq 44: OPERATION_RETURN (root, op 14) */
	if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), -13)) {
		fprintf(stderr, "op return root op 14 failed\n");
		return 1;
	}

	/* Phase 9: remote_plugin (seq 45: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_REMOTE_PLUGIN)) {
		fprintf(stderr, "advance to phase 9 failed\n");
		return 1;
	}

	/* seq 46: NETWORK_POLICY_DECISION (root, op 15) */
	{
		struct spp_diag_trace_fact_network_policy fact = {
			.operation = SPP_DIAG_TRACE_NETWORK_OPERATION_SENDMSG,
			.decision = SPP_DIAG_TRACE_POLICY_DENY,
			.kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4,
			.source = SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT,
			.socket_kind = SPP_DIAG_TRACE_NETWORK_SOCKET_DGRAM,
			.protocol = 17,
			.family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET,
			.addrlen = 16,
			.result = 0xffffffff,
			.flags = 0,
			.size = 1,
			.cookie = 0xc003,
			.port = 443,
			.reserved = 0,
			.scope = 0,
			.flow = 0,
			.address = { 0,0,0,0,0,0,0,0,0,0,0,0, 0xcb, 0x00, 0x71, 0x09 },
		};
		if (spp_diag_trace_runtime_network_policy_decision(&root_task, &fact, &op_ord)) {
			fprintf(stderr, "sendmsg root op 15 failed\n");
			return 1;
		}
	}

	/* seq 47: OPERATION_RETURN (root, op 15) */
	if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), -1)) {
		fprintf(stderr, "op return root op 15 failed\n");
		return 1;
	}

	/* Phase 10: writable_exec (seq 48: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_WRITABLE_EXEC)) {
		fprintf(stderr, "advance to phase 10 failed\n");
		return 1;
	}

	/* seq 49: EXEC_ATTEMPT (root, op 16) */
	{
		const char *path = "/var/tmp/solstone-writable-exec";
		struct spp_diag_trace_fact_exec_attempt fact = {
			.path = path,
			.path_len = strlen(path),
			.pid = root_pid,
			.tgid = root_tgid,
		};
		if (spp_diag_trace_runtime_exec_attempt(&root_task, &fact)) {
			fprintf(stderr, "exec attempt root op 16 failed\n");
			return 1;
		}
	}

	if (flag_successful_denial_canary) {
		struct spp_diag_trace_fact_exec_commit fact = {
			.pid = root_pid,
			.tgid = root_tgid,
		};
		if (spp_diag_trace_runtime_exec_commit(&root_task, &fact)) {
			fprintf(stderr, "exec commit root op 16 failed\n");
			return 1;
		}
	}

	/* seq 50: OPERATION_RETURN (root, op 16) */
	{
		int res = flag_successful_denial_canary ? 0 : -13;
		if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), res)) {
			fprintf(stderr, "op return root op 16 failed\n");
			return 1;
		}
	}

	/* Phase 11: attached_disk_exec (seq 51: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_ATTACHED_DISK_EXEC)) {
		fprintf(stderr, "advance to phase 11 failed\n");
		return 1;
	}

	/* seq 52: EXEC_ATTEMPT uncommitted (root, op 17) */
	{
		const char *path = "/mnt/solstone-attached/foreign-exec";
		struct spp_diag_trace_fact_exec_attempt fact = {
			.path = path,
			.path_len = strlen(path),
			.pid = root_pid,
			.tgid = root_tgid,
		};
		if (spp_diag_trace_runtime_exec_attempt(&root_task, &fact)) {
			fprintf(stderr, "exec attempt root op 17 failed\n");
			return 1;
		}
	}

	/* seq 53: OPERATION_RETURN (root, op 17) */
	if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), -13)) {
		fprintf(stderr, "op return root op 17 failed\n");
		return 1;
	}

	/* Phase 12: remote_code (seq 54: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_REMOTE_CODE)) {
		fprintf(stderr, "advance to phase 12 failed\n");
		return 1;
	}

	/* seq 55: EXEC_ATTEMPT uncommitted (root, op 18) */
	{
		const char *path = "/run/solstone/remote-code/foreign-exec";
		struct spp_diag_trace_fact_exec_attempt fact = {
			.path = path,
			.path_len = strlen(path),
			.pid = root_pid,
			.tgid = root_tgid,
		};
		if (spp_diag_trace_runtime_exec_attempt(&root_task, &fact)) {
			fprintf(stderr, "exec attempt root op 18 failed\n");
			return 1;
		}
	}

	/* seq 56: OPERATION_RETURN (root, op 18) */
	if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), -13)) {
		fprintf(stderr, "op return root op 18 failed\n");
		return 1;
	}

	/* Phase 13: jit_cache (seq 57: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_JIT_CACHE)) {
		fprintf(stderr, "advance to phase 13 failed\n");
		return 1;
	}

	/* seq 58: FILE_OPEN_ATTEMPT (root, op 19) */
	{
		const char *path = "/var/cache/solstone/jit/synthetic-fixture-v1.so";
		struct spp_diag_trace_fact_file_open_attempt fact = {
			.path = path,
			.path_len = strlen(path),
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0x10,
			.dirfd = (u32)-100,
		};
		if (spp_diag_trace_runtime_file_open_attempt(&root_task, &fact, &op_ord)) {
			fprintf(stderr, "file open attempt root op 19 failed\n");
			return 1;
		}
	}

	/* seq 59: FILE_POLICY_DECISION (root, op 19) */
	{
		struct spp_diag_trace_fact_file_policy fact = {
			.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
			.modifiers = 0x10,
			.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
			.object_kind = SPP_DIAG_TRACE_FILE_OBJECT_REGULAR,
			.result = 0,
			.fs_magic = 0x1021994,
			.dev_major = 0,
			.dev_minor = 42,
			.inode = 0x3003,
			.mount_identity = 0xb2,
			.observed_size = 0x8000,
		};
		if (spp_diag_trace_runtime_file_policy_decision(&root_task, op_ord, &fact)) {
			fprintf(stderr, "file policy root op 19 failed\n");
			return 1;
		}
	}

	/* seq 60: OPERATION_RETURN (root, op 19) */
	if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), 7)) {
		fprintf(stderr, "op return root op 19 failed\n");
		return 1;
	}

	/* seq 61: MMAP POLICY (root, op 20) */
	{
		struct spp_diag_trace_fact_mapping_policy fact = {
			.operation = SPP_DIAG_TRACE_MAPPING_OPERATION_MMAP,
			.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
			.backing = SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR,
			.mode = SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE,
			.requested = 5,
			.effective = 5,
			.prior = 0,
			.result = 0,
			.fs_magic = 0x1021994,
			.dev_major = 0,
			.dev_minor = 42,
			.seals = 0,
			.inode = 0x3003,
			.mount_identity = 0xb2,
			.observed_size = 0x8000,
		};
		if (spp_diag_trace_runtime_mapping_policy_decision(&root_task, &fact, &op_ord)) {
			fprintf(stderr, "mmap policy root op 20 failed\n");
			return 1;
		}
	}

	/* seq 62: OPERATION_RETURN (root, op 20) */
	if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), 0x72000000)) {
		fprintf(stderr, "op return root op 20 failed\n");
		return 1;
	}

	/* seq 63: MPROTECT POLICY row 1 (root, op 21) */
	{
		struct spp_diag_trace_fact_mapping_policy fact = {
			.operation = SPP_DIAG_TRACE_MAPPING_OPERATION_MPROTECT,
			.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
			.backing = SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR,
			.mode = SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE,
			.requested = 5,
			.effective = 5,
			.prior = 3,
			.result = 0,
			.fs_magic = 0x1021994,
			.dev_major = 0,
			.dev_minor = 42,
			.seals = 0,
			.inode = 0x3003,
			.mount_identity = 0xb2,
			.observed_size = 0x8000,
		};
		if (spp_diag_trace_runtime_mapping_policy_decision(&root_task, &fact, &op_ord)) {
			fprintf(stderr, "mprotect policy root op 21 row 1 failed\n");
			return 1;
		}
	}

	/* seq 64: MPROTECT POLICY row 2 (root, op 21) */
	{
		struct spp_diag_trace_fact_mapping_policy fact = {
			.operation = SPP_DIAG_TRACE_MAPPING_OPERATION_MPROTECT,
			.decision = SPP_DIAG_TRACE_POLICY_ALLOW,
			.backing = SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR,
			.mode = SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE,
			.requested = 5,
			.effective = 5,
			.prior = 3,
			.result = 0,
			.fs_magic = 0x1021994,
			.dev_major = 0,
			.dev_minor = 42,
			.seals = 0,
			.inode = 0x3003,
			.mount_identity = 0xb2,
			.observed_size = 0x8000,
		};
		if (spp_diag_trace_runtime_mapping_policy_decision(&root_task, &fact, &op_ord)) {
			fprintf(stderr, "mprotect policy root op 21 row 2 failed\n");
			return 1;
		}
	}

	/* seq 65: OPERATION_RETURN (root, op 21) */
	if (spp_diag_trace_runtime_operation_return(&root_task, get_task_open_op(1), 0)) {
		fprintf(stderr, "op return root op 21 failed\n");
		return 1;
	}

	/* Phase 14: evidence_finalize (seq 66: PHASE_MARKER) */
	if (advance_to(SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE)) {
		fprintf(stderr, "advance to phase 14 failed\n");
		return 1;
	}

	/* Phase 15: SEAL (seq 67: TERMINAL) */
	if (seal_runtime()) {
		fprintf(stderr, "seal runtime failed\n");
		return 1;
	}

	if (mutate_terminal) {
		/* Mutation (d): attempt second seal after already sealed */
		if (seal_runtime() != 0 && spp_diag_trace_core_runtime_is_sealed()) {
			fprintf(stderr, "MUTATION_TERMINAL_REJECTED\n");
			return 45;
		}
		fprintf(stderr, "mutation terminal unexpectedly succeeded\n");
		return 1;
	}

	if (!spp_diag_trace_core_runtime_is_sealed()) {
		fprintf(stderr, "not sealed\n");
		return 1;
	}

	if (spp_diag_trace_core_snapshot(snapshot_buf, sizeof(snapshot_buf), &required)) {
		fprintf(stderr, "snapshot failed\n");
		return 1;
	}

	if (fwrite(snapshot_buf + sizeof(*snap), 1, snap->stream_len, stdout) != snap->stream_len) {
		fprintf(stderr, "fwrite failed\n");
		return 1;
	}

	return 0;
}
