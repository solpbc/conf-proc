/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SPP_DIAG_TRACE_RUNTIME_H
#define _LINUX_SPP_DIAG_TRACE_RUNTIME_H

#include <linux/kconfig.h>
#include <linux/types.h>

#ifndef ESHUTDOWN
#define ESHUTDOWN 108
#endif
#define SPP_DIAG_TRACE_ERR_INACTIVE (-ESHUTDOWN)

struct spp_diag_trace_fact_task_alloc {
	u64 clone_flags;
};

struct spp_diag_trace_fact_task_created {
	u32 pid;
	u32 tgid;
	u64 clone_flags;
};

struct spp_diag_trace_fact_exec_attempt {
	const char *path;
	size_t path_len;
	u32 pid;
	u32 tgid;
};

struct spp_diag_trace_fact_exec_commit {
	u32 pid;
	u32 tgid;
};

struct spp_diag_trace_fact_file_open_attempt {
	const char *path;
	size_t path_len;
	u16 access;
	u16 modifiers;
	u32 dirfd;
};

struct spp_diag_trace_fact_file_policy {
	u16 access;
	u16 modifiers;
	u16 decision;
	u16 object_kind;
	u32 result;
	u32 fs_magic;
	u32 dev_major;
	u32 dev_minor;
	u64 inode;
	u64 mount_identity;
	u64 observed_size;
};

struct spp_diag_trace_fact_mapping_policy {
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
};

struct spp_diag_trace_fact_network_policy {
	u16 operation;
	u16 decision;
	u16 kind;
	u16 source;
	u16 socket_kind;
	u16 protocol;
	u16 family;
	u16 addrlen;
	u32 result;
	u32 flags;
	u32 size;
	u64 cookie;
	u16 port;
	u16 reserved;
	u32 scope;
	u32 flow;
	u8 address[16];
};

#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
int spp_diag_trace_runtime_init(void);
int spp_diag_trace_runtime_ready(void);
int spp_diag_trace_runtime_bind_root(const void *task_token);
int spp_diag_trace_runtime_task_alloc_attempt(const void *parent_token,
					      const struct spp_diag_trace_fact_task_alloc *fact);
int spp_diag_trace_runtime_task_created(const void *parent_token,
					const void *child_token,
					const struct spp_diag_trace_fact_task_created *fact);
int spp_diag_trace_runtime_task_exit(const void *task_token, int exit_code);
int spp_diag_trace_runtime_exec_attempt(const void *task_token,
					const struct spp_diag_trace_fact_exec_attempt *fact);
int spp_diag_trace_runtime_exec_reserve(const void *task_token,
					const struct spp_diag_trace_fact_exec_attempt *fact,
					u32 *out_reservation_token);
int spp_diag_trace_runtime_exec_pass(
	const void *task_token,
	const struct spp_diag_trace_fact_exec_attempt *fact);
int spp_diag_trace_runtime_exec_active_operation(const void *task_token,
						 u64 *out_op_ordinal);
int spp_diag_trace_runtime_exec_return(const void *task_token,
					 u32 reservation_token, s64 result);
int spp_diag_trace_runtime_exec_unsupported(const void *task_token);
int spp_diag_trace_runtime_exec_commit(const void *task_token,
				       const struct spp_diag_trace_fact_exec_commit *fact);
int spp_diag_trace_runtime_file_open_attempt(const void *task_token,
					    const struct spp_diag_trace_fact_file_open_attempt *fact,
					    u64 *out_op_ordinal);
int spp_diag_trace_runtime_file_policy_decision(const void *task_token,
						u64 operation_ordinal,
						const struct spp_diag_trace_fact_file_policy *fact);
int spp_diag_trace_runtime_file_gate_observation(const void *task_token,
						 const void *file_token,
						 u64 operation_ordinal,
						 const struct spp_diag_trace_fact_file_policy *fact);
int spp_diag_trace_runtime_mapping_policy_decision(const void *task_token,
						   const struct spp_diag_trace_fact_mapping_policy *fact,
						   u64 *out_op_ordinal);
int spp_diag_trace_runtime_network_policy_decision(const void *task_token,
						   const struct spp_diag_trace_fact_network_policy *fact,
						   u64 *out_op_ordinal);
int spp_diag_trace_runtime_file_open_active_operation(const void *task_token,
						      u64 *out_op_ordinal,
						      u16 *out_access,
						      u16 *out_modifiers);
int spp_diag_trace_runtime_mmap_active_operation(const void *task_token,
						 u64 *out_op_ordinal);
int spp_diag_trace_runtime_mprotect_active_operation(const void *task_token,
						     u64 *out_op_ordinal);
int spp_diag_trace_runtime_connect_active_operation(const void *task_token,
						    u64 *out_op_ordinal);
int spp_diag_trace_runtime_sendmsg_active_operation(const void *task_token,
						    u64 *out_op_ordinal);
int spp_diag_trace_runtime_mapping_unsupported(const void *task_token);
int spp_diag_trace_runtime_network_unsupported(const void *task_token);
int spp_diag_trace_runtime_operation_unsupported(const void *task_token);
int spp_diag_trace_runtime_operation_return(const void *task_token,
					    u64 operation_ordinal, s64 result);
int spp_diag_trace_runtime_operation_return_raw(const void *task_token,
						u64 operation_ordinal, u64 result_bits);
int spp_diag_trace_runtime_file_open_return(const void *task_token,
					    const void *file_token, s64 result);
#else
static inline int spp_diag_trace_runtime_init(void) { return 0; }
static inline int spp_diag_trace_runtime_ready(void) { return 1; }
static inline int spp_diag_trace_runtime_bind_root(const void *task_token) { (void)task_token; return 0; }
static inline int spp_diag_trace_runtime_task_alloc_attempt(const void *parent_token,
							    const struct spp_diag_trace_fact_task_alloc *fact)
{ (void)parent_token; (void)fact; return 0; }
static inline int spp_diag_trace_runtime_task_created(const void *parent_token,
						      const void *child_token,
						      const struct spp_diag_trace_fact_task_created *fact)
{ (void)parent_token; (void)child_token; (void)fact; return 0; }
static inline int spp_diag_trace_runtime_task_exit(const void *task_token, int exit_code)
{ (void)task_token; (void)exit_code; return 0; }
static inline int spp_diag_trace_runtime_exec_attempt(const void *task_token,
						      const struct spp_diag_trace_fact_exec_attempt *fact)
{ (void)task_token; (void)fact; return 0; }
static inline int spp_diag_trace_runtime_exec_reserve(const void *task_token,
						      const struct spp_diag_trace_fact_exec_attempt *fact,
						      u32 *out_reservation_token)
{ (void)task_token; (void)fact; (void)out_reservation_token; return 0; }
static inline int spp_diag_trace_runtime_exec_pass(
	const void *task_token,
	const struct spp_diag_trace_fact_exec_attempt *fact)
{ (void)task_token; (void)fact; return 0; }
static inline int spp_diag_trace_runtime_exec_active_operation(const void *task_token,
							       u64 *out_op_ordinal)
{ (void)task_token; (void)out_op_ordinal; return 0; }
static inline int spp_diag_trace_runtime_exec_return(const void *task_token,
						     u32 reservation_token, s64 result)
{ (void)task_token; (void)reservation_token; (void)result; return 0; }
static inline int spp_diag_trace_runtime_exec_unsupported(const void *task_token)
{ (void)task_token; return 0; }
static inline int spp_diag_trace_runtime_exec_commit(const void *task_token,
						     const struct spp_diag_trace_fact_exec_commit *fact)
{ (void)task_token; (void)fact; return 0; }
static inline int spp_diag_trace_runtime_file_open_attempt(const void *task_token,
							   const struct spp_diag_trace_fact_file_open_attempt *fact,
							   u64 *out_op_ordinal)
{ (void)task_token; (void)fact; (void)out_op_ordinal; return 0; }
static inline int spp_diag_trace_runtime_file_policy_decision(const void *task_token,
							      u64 operation_ordinal,
							      const struct spp_diag_trace_fact_file_policy *fact)
{ (void)task_token; (void)operation_ordinal; (void)fact; return 0; }
static inline int spp_diag_trace_runtime_file_gate_observation(const void *task_token,
							       const void *file_token,
							       u64 operation_ordinal,
							       const struct spp_diag_trace_fact_file_policy *fact)
{ (void)task_token; (void)file_token; (void)operation_ordinal; (void)fact; return 0; }
static inline int spp_diag_trace_runtime_mapping_policy_decision(const void *task_token,
								 const struct spp_diag_trace_fact_mapping_policy *fact,
								 u64 *out_op_ordinal)
{ (void)task_token; (void)fact; (void)out_op_ordinal; return 0; }
static inline int spp_diag_trace_runtime_network_policy_decision(const void *task_token,
								 const struct spp_diag_trace_fact_network_policy *fact,
								 u64 *out_op_ordinal)
{ (void)task_token; (void)fact; (void)out_op_ordinal; return 0; }
static inline int spp_diag_trace_runtime_file_open_active_operation(const void *task_token,
								    u64 *out_op_ordinal,
								    u16 *out_access,
								    u16 *out_modifiers)
{ (void)task_token; (void)out_op_ordinal; (void)out_access; (void)out_modifiers; return 0; }
static inline int spp_diag_trace_runtime_mmap_active_operation(const void *task_token,
							       u64 *out_op_ordinal)
{ (void)task_token; (void)out_op_ordinal; return 0; }
static inline int spp_diag_trace_runtime_mprotect_active_operation(const void *task_token,
								   u64 *out_op_ordinal)
{ (void)task_token; (void)out_op_ordinal; return 0; }
static inline int spp_diag_trace_runtime_connect_active_operation(const void *task_token,
								  u64 *out_op_ordinal)
{ (void)task_token; (void)out_op_ordinal; return 0; }
static inline int spp_diag_trace_runtime_sendmsg_active_operation(const void *task_token,
								  u64 *out_op_ordinal)
{ (void)task_token; (void)out_op_ordinal; return 0; }
static inline int spp_diag_trace_runtime_mapping_unsupported(const void *task_token)
{ (void)task_token; return 0; }
static inline int spp_diag_trace_runtime_network_unsupported(const void *task_token)
{ (void)task_token; return 0; }
static inline int spp_diag_trace_runtime_operation_unsupported(const void *task_token)
{ (void)task_token; return 0; }
static inline int spp_diag_trace_runtime_operation_return(const void *task_token,
							  u64 operation_ordinal, s64 result)
{ (void)task_token; (void)operation_ordinal; (void)result; return 0; }
static inline int spp_diag_trace_runtime_operation_return_raw(const void *task_token,
							      u64 operation_ordinal, u64 result_bits)
{ (void)task_token; (void)operation_ordinal; (void)result_bits; return 0; }
static inline int spp_diag_trace_runtime_file_open_return(const void *task_token,
							  const void *file_token, s64 result)
{ (void)task_token; (void)file_token; (void)result; return 0; }
#endif

#endif
