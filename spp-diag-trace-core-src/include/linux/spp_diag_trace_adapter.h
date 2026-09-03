/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SPP_DIAG_TRACE_ADAPTER_H
#define _LINUX_SPP_DIAG_TRACE_ADAPTER_H

#include <linux/kconfig.h>
#include <linux/types.h>

struct linux_binprm;
struct file;
struct vm_area_struct;
struct socket;
struct msghdr;
struct task_struct;

#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
void spp_diag_trace_adapter_exec_reserve(const char *path,
					 u32 *out_reservation_token);
void spp_diag_trace_adapter_exec_pass(const struct linux_binprm *bprm);
void spp_diag_trace_adapter_exec_commit(const struct linux_binprm *bprm);
void spp_diag_trace_adapter_exec_return(u32 reservation_token, s64 result);
void spp_diag_trace_adapter_exec_unsupported(void);
void spp_diag_trace_adapter_task_alloc(const struct task_struct *parent,
					       u64 clone_flags);
void spp_diag_trace_adapter_task_created(const struct task_struct *parent,
					 struct task_struct *child,
					  u64 clone_flags);
void spp_diag_trace_adapter_task_exit(const struct task_struct *task,
					      int exit_code);
void spp_diag_trace_adapter_file_open_attempt(int dfd, const char *path,
						      unsigned long open_flags);
void spp_diag_trace_adapter_file_open_policy(const struct file *file,
						     s64 result);
void spp_diag_trace_adapter_file_open_return(s64 result, const struct file *file);
void spp_diag_trace_adapter_mapping_policy(const struct file *file,
						  unsigned long prot,
						  unsigned long flags, s64 result);
void spp_diag_trace_adapter_mapping_unsupported(void);
void spp_diag_trace_adapter_mapping_return(u64 result_bits);
void spp_diag_trace_adapter_mprotect_policy(const struct vm_area_struct *vma,
						    unsigned long requested_prot,
						    unsigned long effective_prot,
						    s64 result);
void spp_diag_trace_adapter_mprotect_return(s64 result);
void spp_diag_trace_adapter_connect_policy(const struct socket *sock,
						  const void *address, int address_len,
						  int flags, s64 result);
void spp_diag_trace_adapter_connect_unsupported(const struct socket *sock,
						       const void *address, int address_len,
						       int flags);
void spp_diag_trace_adapter_connect_return(s64 result);
void spp_diag_trace_adapter_sendmsg_policy(const struct socket *sock,
						  const struct msghdr *msg,
						  unsigned int flags, s64 result);
int spp_diag_trace_adapter_sendmsg_precheck(const struct socket *sock,
					   const struct msghdr *msg);
void spp_diag_trace_adapter_sendmsg_unsupported(const struct socket *sock,
						       const struct msghdr *msg,
						       unsigned int flags);
void spp_diag_trace_adapter_sendmsg_return(s64 result);
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static inline void spp_diag_trace_adapter_exec_reserve(const char *path,
						      u32 *out_reservation_token) {}
static inline void spp_diag_trace_adapter_exec_pass(const struct linux_binprm *bprm) {}
static inline void spp_diag_trace_adapter_exec_commit(const struct linux_binprm *bprm) {}
static inline void spp_diag_trace_adapter_exec_return(u32 reservation_token, s64 result) {}
static inline void spp_diag_trace_adapter_exec_unsupported(void) {}
static inline void spp_diag_trace_adapter_task_alloc(const struct task_struct *parent,
							      u64 clone_flags) {}
static inline void spp_diag_trace_adapter_task_created(const struct task_struct *parent,
							struct task_struct *child,
								 u64 clone_flags) {}
static inline void spp_diag_trace_adapter_task_exit(const struct task_struct *task,
							     int exit_code) {}
static inline void spp_diag_trace_adapter_file_open_attempt(int dfd, const char *path,
								     unsigned long open_flags) {}
static inline void spp_diag_trace_adapter_file_open_policy(const struct file *file,
								    s64 result) {}
static inline void spp_diag_trace_adapter_file_open_return(s64 result,
							   const struct file *file) {}
static inline void spp_diag_trace_adapter_mapping_policy(const struct file *file,
								 unsigned long prot,
								 unsigned long flags, s64 result) {}
static inline void spp_diag_trace_adapter_mapping_unsupported(void) {}
static inline void spp_diag_trace_adapter_mapping_return(u64 result_bits) {}
static inline void spp_diag_trace_adapter_mprotect_policy(const struct vm_area_struct *vma,
								   unsigned long requested_prot,
								   unsigned long effective_prot,
								   s64 result) {}
static inline void spp_diag_trace_adapter_mprotect_return(s64 result) {}
static inline void spp_diag_trace_adapter_connect_policy(const struct socket *sock,
								 const void *address, int address_len,
								 int flags, s64 result) {}
static inline void spp_diag_trace_adapter_connect_unsupported(const struct socket *sock,
								      const void *address, int address_len,
								      int flags) {}
static inline void spp_diag_trace_adapter_connect_return(s64 result) {}
static inline void spp_diag_trace_adapter_sendmsg_policy(const struct socket *sock,
								 const struct msghdr *msg,
								 unsigned int flags, s64 result) {}
static inline int spp_diag_trace_adapter_sendmsg_precheck(const struct socket *sock,
								  const struct msghdr *msg)
{ return 0; }
static inline void spp_diag_trace_adapter_sendmsg_unsupported(const struct socket *sock,
								      const struct msghdr *msg,
								      unsigned int flags) {}
static inline void spp_diag_trace_adapter_sendmsg_return(s64 result) {}
#pragma GCC diagnostic pop
#endif

#endif
