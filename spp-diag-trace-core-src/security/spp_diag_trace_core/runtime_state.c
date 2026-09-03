/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include <linux/spp_diag_trace_runtime.h>

#include "core.h"
#include "runtime_types.h"

int spp_diag_trace_runtime_init(void)
{
	size_t task_cap = SPP_DIAG_TRACE_RUNTIME_OP_MAX_TASKS;
	size_t op_cap = SPP_DIAG_TRACE_RUNTIME_OP_MAX_OPERATIONS;
	struct spp_diag_trace_task_record *tasks = NULL;
	struct spp_diag_trace_operation_record *ops = NULL;
	size_t tasks_size = task_cap * sizeof(struct spp_diag_trace_task_record);
	size_t ops_size = op_cap * sizeof(struct spp_diag_trace_operation_record);
	int err;

	tasks = vmalloc(tasks_size);
	if (!tasks) {
		spp_diag_trace_core_mark_failure(WIRE_CAP);
		return WIRE_CAP;
	}
	memset(tasks, 0, tasks_size);

	ops = vmalloc(ops_size);
	if (!ops) {
		vfree(tasks);
		spp_diag_trace_core_mark_failure(WIRE_CAP);
		return WIRE_CAP;
	}
	memset(ops, 0, ops_size);

	err = spp_diag_trace_core_runtime_install_arrays(tasks, task_cap,
							 ops, op_cap);
	if (err) {
		vfree(tasks);
		vfree(ops);
		return err;
	}
	err = spp_diag_trace_runtime_fs_init();
	if (err) {
		spp_diag_trace_core_mark_failure(WIRE_STATE);
		return err;
	}
	return 0;
}

int spp_diag_trace_runtime_ready(void)
{
	return spp_diag_trace_core_runtime_is_ready() ? 1 : 0;
}

int spp_diag_trace_runtime_bind_root(const void *task_token)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	return spp_diag_trace_core_runtime_bind_root(task_token);
}

int spp_diag_trace_runtime_task_alloc_attempt(const void *parent_token,
					      const struct spp_diag_trace_fact_task_alloc *fact)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!parent_token || !fact)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_task_alloc_attempt(parent_token,
							      fact->clone_flags);
}

int spp_diag_trace_runtime_task_created(const void *parent_token,
					const void *child_token,
					const struct spp_diag_trace_fact_task_created *fact)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!parent_token || !child_token || !fact)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_task_created(parent_token,
							child_token,
							fact->pid,
							fact->tgid,
							fact->clone_flags);
}

int spp_diag_trace_runtime_task_exit(const void *task_token, int exit_code)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_task_exit(task_token, (u32)exit_code);
}

int spp_diag_trace_runtime_exec_attempt(const void *task_token,
					const struct spp_diag_trace_fact_exec_attempt *fact)
{
	char local_path[SPP_DIAG_TRACE_MAX_PATH_BYTES];

	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !fact)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);
	if (!fact->path || fact->path_len == 0 ||
	    fact->path_len > SPP_DIAG_TRACE_MAX_PATH_BYTES)
		return spp_diag_trace_core_mark_failure(WIRE_LENGTH);

	/* Copy path locally immediately before any other work (AC4 poison resistance) */
	memcpy(local_path, fact->path, fact->path_len);

	return spp_diag_trace_core_runtime_exec_attempt(task_token,
							local_path,
							fact->path_len,
							fact->pid,
							fact->tgid);
}

int spp_diag_trace_runtime_exec_reserve(const void *task_token,
					const struct spp_diag_trace_fact_exec_attempt *fact,
					u32 *out_reservation_token)
{
	char local_path[SPP_DIAG_TRACE_MAX_PATH_BYTES];

	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !fact || !out_reservation_token)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);
	if (!fact->path || fact->path_len == 0 ||
	    fact->path_len > SPP_DIAG_TRACE_MAX_PATH_BYTES)
		return spp_diag_trace_core_mark_failure(WIRE_LENGTH);

	memcpy(local_path, fact->path, fact->path_len);
	return spp_diag_trace_core_runtime_exec_reserve(task_token, local_path,
							fact->path_len, fact->pid, fact->tgid,
							out_reservation_token);
}

int spp_diag_trace_runtime_exec_pass(
	const void *task_token,
	const struct spp_diag_trace_fact_exec_attempt *fact)
{
	char local_path[SPP_DIAG_TRACE_MAX_PATH_BYTES];

	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !fact)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);
	if (!fact->path || fact->path_len == 0 ||
	    fact->path_len > SPP_DIAG_TRACE_MAX_PATH_BYTES)
		return spp_diag_trace_core_mark_failure(WIRE_LENGTH);

	memcpy(local_path, fact->path, fact->path_len);
	return spp_diag_trace_core_runtime_exec_pass(task_token, local_path,
						     fact->path_len, fact->pid, fact->tgid);
}

int spp_diag_trace_runtime_exec_active_operation(const void *task_token,
						 u64 *out_op_ordinal)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !out_op_ordinal)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_exec_active_operation(task_token,
									out_op_ordinal);
}

int spp_diag_trace_runtime_exec_return(const void *task_token,
					 u32 reservation_token, s64 result)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_exec_return(task_token,
							 reservation_token, result);
}

int spp_diag_trace_runtime_exec_unsupported(const void *task_token)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_exec_unsupported(task_token);
}

int spp_diag_trace_runtime_exec_commit(const void *task_token,
				       const struct spp_diag_trace_fact_exec_commit *fact)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !fact)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_exec_commit(task_token,
						       fact->pid,
						       fact->tgid);
}

int spp_diag_trace_runtime_file_open_attempt(
	const void *task_token,
	const struct spp_diag_trace_fact_file_open_attempt *fact,
	u64 *out_op_ordinal)
{
	char local_path[SPP_DIAG_TRACE_MAX_PATH_BYTES];

	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !fact || !out_op_ordinal)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);
	if (!fact->path || fact->path_len == 0 ||
	    fact->path_len > SPP_DIAG_TRACE_MAX_PATH_BYTES)
		return spp_diag_trace_core_mark_failure(WIRE_LENGTH);

	/* Copy path locally immediately before any other work (AC4 poison resistance) */
	memcpy(local_path, fact->path, fact->path_len);

	return spp_diag_trace_core_runtime_file_open_attempt(
		task_token, local_path, fact->path_len,
		fact->access, fact->modifiers, fact->dirfd,
		out_op_ordinal);
}

int spp_diag_trace_runtime_file_policy_decision(
	const void *task_token,
	u64 operation_ordinal,
	const struct spp_diag_trace_fact_file_policy *fact)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !fact)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_file_policy_decision(
		task_token, operation_ordinal, fact);
}

int spp_diag_trace_runtime_file_gate_observation(
	const void *task_token, const void *file_token, u64 operation_ordinal,
	const struct spp_diag_trace_fact_file_policy *fact)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !file_token || !fact)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_file_gate_observation(
		task_token, file_token, operation_ordinal, fact);
}

int spp_diag_trace_runtime_mapping_policy_decision(
	const void *task_token,
	const struct spp_diag_trace_fact_mapping_policy *fact,
	u64 *out_op_ordinal)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !fact || !out_op_ordinal)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_mapping_policy_decision(
		task_token, fact, out_op_ordinal);
}

int spp_diag_trace_runtime_network_policy_decision(
	const void *task_token,
	const struct spp_diag_trace_fact_network_policy *fact,
	u64 *out_op_ordinal)
{
	struct spp_diag_trace_fact_network_policy local_fact;

	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !fact || !out_op_ordinal)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	/* Copy fact struct locally immediately before any other work (poison resistance) */
	memcpy(&local_fact, fact, sizeof(local_fact));

	return spp_diag_trace_core_runtime_network_policy_decision(
		task_token, &local_fact, out_op_ordinal);
}

int spp_diag_trace_runtime_file_open_active_operation(const void *task_token,
						      u64 *out_op_ordinal,
						      u16 *out_access,
						      u16 *out_modifiers)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !out_op_ordinal || !out_access || !out_modifiers)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_file_open_active_operation(task_token,
									      out_op_ordinal,
									      out_access,
									      out_modifiers);
}

int spp_diag_trace_runtime_mmap_active_operation(const void *task_token,
						 u64 *out_op_ordinal)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !out_op_ordinal)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_mmap_active_operation(task_token,
									out_op_ordinal);
}

int spp_diag_trace_runtime_mprotect_active_operation(const void *task_token,
						     u64 *out_op_ordinal)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !out_op_ordinal)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_mprotect_active_operation(task_token,
									out_op_ordinal);
}

int spp_diag_trace_runtime_connect_active_operation(const void *task_token,
						    u64 *out_op_ordinal)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !out_op_ordinal)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_connect_active_operation(task_token,
								   out_op_ordinal);
}

int spp_diag_trace_runtime_sendmsg_active_operation(const void *task_token,
						    u64 *out_op_ordinal)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token || !out_op_ordinal)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_sendmsg_active_operation(task_token,
								   out_op_ordinal);
}

int spp_diag_trace_runtime_mapping_unsupported(const void *task_token)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_mapping_unsupported(task_token);
}

int spp_diag_trace_runtime_network_unsupported(const void *task_token)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_network_unsupported(task_token);
}

int spp_diag_trace_runtime_operation_unsupported(const void *task_token)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_operation_unsupported(task_token);
}

int spp_diag_trace_runtime_operation_return(const void *task_token,
					    u64 operation_ordinal, s64 result)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_operation_return(task_token,
						    operation_ordinal,
						    result);
}

int spp_diag_trace_runtime_operation_return_raw(const void *task_token,
						u64 operation_ordinal, u64 result_bits)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_operation_return_raw(
		task_token, operation_ordinal, result_bits);
}

int spp_diag_trace_runtime_file_open_return(const void *task_token,
					    const void *file_token, s64 result)
{
	if (spp_diag_trace_core_runtime_is_sealed())
		return SPP_DIAG_TRACE_ERR_INACTIVE;
	if (!task_token)
		return spp_diag_trace_core_mark_failure(WIRE_NULL);

	return spp_diag_trace_core_runtime_file_open_return(
		task_token, file_token, result);
}

/*
 * securityfs itself registers at core_initcall.  fs_initcall makes that
 * dependency ordered rather than link-order-dependent while still allocating
 * all runtime state before kernel_init_freeable() executes release.
 */
static int __init spp_diag_trace_runtime_initcall(void)
{
	return spp_diag_trace_runtime_init();
}
fs_initcall(spp_diag_trace_runtime_initcall);
