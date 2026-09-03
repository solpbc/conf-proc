/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <string.h>

#include <crypto/sha2.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kmod.h>
#include <linux/ima.h>
#include <linux/spp_diag_trace_bootstrap.h>
#include <linux/spp_diag_trace_runtime.h>

#include "core.h"

static const char valid_command_line[] =
	"ima_policy=critical_data "
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static int emit_blob(const void *data, size_t length)
{
	u8 size[4] = {
		(u8)(length >> 24), (u8)(length >> 16),
		(u8)(length >> 8), (u8)length,
	};

	return fwrite(size, 1, sizeof(size), stdout) == sizeof(size) &&
	       fwrite(data, 1, length, stdout) == length ? 0 : -1;
}

int main(void)
{
	struct task_struct *root_ts;
	u8 snapshot_buffer[65536];
	struct spp_diag_trace_core_snapshot *snapshot =
		(struct spp_diag_trace_core_snapshot *)snapshot_buffer;
	size_t required;

	/* Operation fact structures */
	const char exec_path[] = "/usr/bin/python3";
	struct spp_diag_trace_fact_exec_attempt exec_attempt_fact = {
		.path = exec_path,
		.path_len = strlen(exec_path),
		.pid = 1,
		.tgid = 1,
	};
	struct spp_diag_trace_fact_exec_commit exec_commit_fact = {
		.pid = 1,
		.tgid = 1,
	};

	const char file_path[] = "/etc/ld.so.cache";
	struct spp_diag_trace_fact_file_open_attempt file_open_fact = {
		.path = file_path,
		.path_len = strlen(file_path),
		.access = SPP_DIAG_TRACE_FILE_ACCESS_READ,
		.modifiers = SPP_DIAG_TRACE_FILE_MOD_NOFOLLOW,
		.dirfd = 0xFFFFFF9C,
	};
	struct spp_diag_trace_fact_file_policy file_policy_fact = {
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

	struct spp_diag_trace_fact_mapping_policy mprotect_fact1 = {
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
	struct spp_diag_trace_fact_mapping_policy mprotect_fact2 = {
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
		.cookie = 0x1122334455667788ull,
		.port = 443,
		.reserved = 0,
		.scope = 0,
		.flow = 0,
		.address = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1 },
	};

	struct spp_diag_trace_fact_network_policy sendmsg_fact = {
		.operation = SPP_DIAG_TRACE_NETWORK_OPERATION_SENDMSG,
		.decision = SPP_DIAG_TRACE_POLICY_DENY,
		.kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV6,
		.source = SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_CONNECTED,
		.socket_kind = SPP_DIAG_TRACE_NETWORK_SOCKET_DGRAM,
		.protocol = 17,
		.family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET6,
		.addrlen = 0,
		.result = 0x8000000D,
		.flags = 0,
		.size = 512,
		.cookie = 0x99aabbccddeeff00ull,
		.port = 53,
		.reserved = 0,
		.scope = 1,
		.flow = 2,
		.address = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
	};

	u64 op_file = 0, op_mmap = 0, op_mprotect1 = 0, op_mprotect2 = 0;
	u64 op_connect = 0, op_sendmsg = 0;

	spp_diag_trace_core_reset();
	spp_diag_trace_core_set_op_caps(SPP_DIAG_TRACE_MAX_FRAMES, SPP_DIAG_TRACE_MAX_STREAM_BYTES);
	host_kmod_reset();
	host_ima_reset();
	host_current_task.pid = 1;
	host_current_task.tgid = 1;
	host_current_task.flags = 0;
	host_saved_command_line_set(valid_command_line);

	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();
	if (spp_diag_trace_runtime_init())
		return 1;
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_release();
	if (!spp_diag_trace_runtime_ready() || !spp_diag_trace_core_is_green())
		return 1;

	root_ts = &host_current_task;

	/* 1. EXEC family (op 2) */
	if (spp_diag_trace_runtime_exec_attempt(root_ts, &exec_attempt_fact) ||
	    spp_diag_trace_runtime_exec_attempt(root_ts, &exec_attempt_fact) ||
	    spp_diag_trace_runtime_exec_commit(root_ts, &exec_commit_fact) ||
	    spp_diag_trace_runtime_operation_return(root_ts, 2, 0))
		return 2;

	/* 2. FILE_OPEN family (op 3) */
	if (spp_diag_trace_runtime_file_open_attempt(root_ts, &file_open_fact, &op_file) ||
	    spp_diag_trace_runtime_file_policy_decision(root_ts, op_file, &file_policy_fact) ||
	    spp_diag_trace_runtime_operation_return(root_ts, op_file, 0))
		return 3;

	/* 3. MMAP family (op 4) */
	if (spp_diag_trace_runtime_mapping_policy_decision(root_ts, &mmap_fact, &op_mmap) ||
	    spp_diag_trace_runtime_operation_return(root_ts, op_mmap, 0))
		return 4;

	/* 4. MPROTECT family (op 5, multi-row + deny) */
	if (spp_diag_trace_runtime_mapping_policy_decision(root_ts, &mprotect_fact1, &op_mprotect1) ||
	    spp_diag_trace_runtime_mapping_policy_decision(root_ts, &mprotect_fact2, &op_mprotect2) ||
	    spp_diag_trace_runtime_operation_return(root_ts, op_mprotect1, -1))
		return 5;

	/* 5. CONNECT family (op 6) */
	if (spp_diag_trace_runtime_network_policy_decision(root_ts, &connect_fact, &op_connect) ||
	    spp_diag_trace_runtime_operation_return(root_ts, op_connect, 0))
		return 6;

	/* 6. SENDMSG family (op 7) */
	if (spp_diag_trace_runtime_network_policy_decision(root_ts, &sendmsg_fact, &op_sendmsg) ||
	    spp_diag_trace_runtime_operation_return(root_ts, op_sendmsg, -13))
		return 7;

	if (spp_diag_trace_core_snapshot(snapshot_buffer, sizeof(snapshot_buffer), &required))
		return 8;

	if (emit_blob(snapshot_buffer + sizeof(*snapshot), snapshot->stream_len))
		return 9;

	return 0;
}
