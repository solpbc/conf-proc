/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/binfmts.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/kdev_t.h>
#include <linux/memfd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/minmax.h>
#include <linux/sched.h>
#include <linux/sock_diag.h>
#include <linux/socket.h>
#include <linux/string.h>

#include <linux/spp_diag_trace_adapter.h>
#include <linux/spp_diag_trace_runtime.h>

#include <net/sock.h>

#include "protocol_constants.h"
#ifdef SPP_DIAG_TRACE_CORE_HOST_TEST
#include <linux/spp_diag_trace_adapter_shim.h>
#else
#include "../../fs/mount.h"
#endif

static u16 spp_diag_trace_adapter_file_access(unsigned long flags)
{
	switch (flags & O_ACCMODE) {
	case O_WRONLY:
		return SPP_DIAG_TRACE_FILE_ACCESS_WRITE;
	case O_RDWR:
		return SPP_DIAG_TRACE_FILE_ACCESS_READ_WRITE;
	default:
		return (flags & O_PATH) ? SPP_DIAG_TRACE_FILE_ACCESS_PATH_ONLY :
			SPP_DIAG_TRACE_FILE_ACCESS_READ;
	}
}

static u16 spp_diag_trace_adapter_file_modifiers(unsigned long flags)
{
	u16 modifiers = 0;

	if (flags & O_CREAT)
		modifiers |= SPP_DIAG_TRACE_FILE_MOD_CREATE;
	if (flags & O_TRUNC)
		modifiers |= SPP_DIAG_TRACE_FILE_MOD_TRUNCATE;
	if (flags & O_APPEND)
		modifiers |= SPP_DIAG_TRACE_FILE_MOD_APPEND;
	if (flags & O_NOFOLLOW)
		modifiers |= SPP_DIAG_TRACE_FILE_MOD_NOFOLLOW;
	if (flags & O_CLOEXEC)
		modifiers |= SPP_DIAG_TRACE_FILE_MOD_CLOEXEC;
	if (flags & O_DIRECTORY)
		modifiers |= SPP_DIAG_TRACE_FILE_MOD_DIRECTORY;
	return modifiers;
}

static u16 spp_diag_trace_adapter_file_object_kind(const struct inode *inode)
{
	if (!inode)
		return SPP_DIAG_TRACE_FILE_OBJECT_OTHER;
	if (S_ISREG(inode->i_mode))
		return SPP_DIAG_TRACE_FILE_OBJECT_REGULAR;
	if (S_ISDIR(inode->i_mode))
		return SPP_DIAG_TRACE_FILE_OBJECT_DIRECTORY;
	return SPP_DIAG_TRACE_FILE_OBJECT_OTHER;
}

static void spp_diag_trace_adapter_file_metadata(
	const struct file *file, u32 *fs_magic, u32 *dev_major, u32 *dev_minor,
	u64 *inode_number, u64 *mount_identity, u64 *observed_size)
{
	const struct inode *inode;

	*fs_magic = 0;
	*dev_major = 0;
	*dev_minor = 0;
	*inode_number = 0;
	*mount_identity = 0;
	*observed_size = 0;
	if (!file)
		return;

	inode = file_inode(file);
	if (inode) {
		*inode_number = inode->i_ino;
		*observed_size = i_size_read(inode) > 0 ?
			(u64)i_size_read(inode) : 0;
		if (inode->i_sb) {
			*fs_magic = (u32)inode->i_sb->s_magic;
			*dev_major = MAJOR(inode->i_sb->s_dev);
			*dev_minor = MINOR(inode->i_sb->s_dev);
		}
	}
	if (file->f_path.mnt)
		*mount_identity = real_mount(file->f_path.mnt)->mnt_id_unique;
}

static u32 spp_diag_trace_adapter_protection(unsigned long prot)
{
	u32 value = 0;

	if (prot & PROT_READ)
		value |= SPP_DIAG_TRACE_MAPPING_PROT_READ;
	if (prot & PROT_WRITE)
		value |= SPP_DIAG_TRACE_MAPPING_PROT_WRITE;
	if (prot & PROT_EXEC)
		value |= SPP_DIAG_TRACE_MAPPING_PROT_EXEC;
	return value;
}

/* The wire result uses its high bit as the diagnostic failure marker. */
static u32 spp_diag_trace_adapter_result(s64 result)
{
	if (result < 0)
		return 0x80000000u | (u32)(-(result + 1) + 1);
	return (u32)result;
}

static u32 spp_diag_trace_adapter_vm_protection(vm_flags_t flags)
{
	u32 value = 0;

	if (flags & VM_READ)
		value |= SPP_DIAG_TRACE_MAPPING_PROT_READ;
	if (flags & VM_WRITE)
		value |= SPP_DIAG_TRACE_MAPPING_PROT_WRITE;
	if (flags & VM_EXEC)
		value |= SPP_DIAG_TRACE_MAPPING_PROT_EXEC;
	return value;
}

static u16 spp_diag_trace_adapter_mapping_backing(const struct file *file,
							   u32 *seals)
{
	struct inode *inode;

	*seals = 0;
	if (!file)
		return SPP_DIAG_TRACE_MAPPING_BACKING_ANONYMOUS;
	if (memfd_file_seals_ptr((struct file *)file)) {
		*seals = memfd_file_seals((struct file *)file);
		return SPP_DIAG_TRACE_MAPPING_BACKING_MEMFD;
	}
	inode = file_inode(file);
	return inode && S_ISREG(inode->i_mode) ?
		SPP_DIAG_TRACE_MAPPING_BACKING_REGULAR :
		SPP_DIAG_TRACE_MAPPING_BACKING_OTHER;
}

static void spp_diag_trace_adapter_mapping_fact(
	struct spp_diag_trace_fact_mapping_policy *fact, const struct file *file,
	u16 operation, unsigned long requested, unsigned long effective,
	unsigned long prior, unsigned long flags, s64 result)
{
	memset(fact, 0, sizeof(*fact));
	fact->operation = operation;
	fact->decision = result ? SPP_DIAG_TRACE_POLICY_DENY :
		SPP_DIAG_TRACE_POLICY_ALLOW;
	fact->backing = spp_diag_trace_adapter_mapping_backing(file, &fact->seals);
	fact->mode = (flags & MAP_SHARED) ? SPP_DIAG_TRACE_MAPPING_MODE_SHARED :
		SPP_DIAG_TRACE_MAPPING_MODE_PRIVATE;
	fact->requested = spp_diag_trace_adapter_protection(requested);
	fact->effective = spp_diag_trace_adapter_protection(effective);
	fact->prior = spp_diag_trace_adapter_protection(prior);
	fact->result = spp_diag_trace_adapter_result(result);
	spp_diag_trace_adapter_file_metadata(file, &fact->fs_magic,
					     &fact->dev_major, &fact->dev_minor,
					     &fact->inode, &fact->mount_identity,
					     &fact->observed_size);
}

static u16 spp_diag_trace_adapter_socket_kind(const struct socket *sock)
{
	if (!sock)
		return SPP_DIAG_TRACE_NETWORK_SOCKET_OTHER;
	switch (sock->type) {
	case SOCK_STREAM:
		return SPP_DIAG_TRACE_NETWORK_SOCKET_STREAM;
	case SOCK_DGRAM:
		return SPP_DIAG_TRACE_NETWORK_SOCKET_DGRAM;
	case SOCK_RAW:
		return SPP_DIAG_TRACE_NETWORK_SOCKET_RAW;
	case SOCK_SEQPACKET:
		return SPP_DIAG_TRACE_NETWORK_SOCKET_SEQPACKET;
	default:
		return SPP_DIAG_TRACE_NETWORK_SOCKET_OTHER;
	}
}

static void spp_diag_trace_adapter_network_fact(
	struct spp_diag_trace_fact_network_policy *fact, const struct socket *sock,
	const void *address, int address_len, u16 operation, unsigned int flags,
	s64 result, bool connected, bool unsupported)
{
	const struct sockaddr *sa = address;

	memset(fact, 0, sizeof(*fact));
	fact->operation = operation;
	fact->decision = result ? SPP_DIAG_TRACE_POLICY_DENY :
		SPP_DIAG_TRACE_POLICY_ALLOW;
	fact->socket_kind = spp_diag_trace_adapter_socket_kind(sock);
	fact->result = spp_diag_trace_adapter_result(result);
	fact->flags = operation == SPP_DIAG_TRACE_NETWORK_OPERATION_SENDMSG ? flags : 0;
	fact->source = connected ? SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_CONNECTED :
		SPP_DIAG_TRACE_NETWORK_ENDPOINT_SOURCE_EXPLICIT;
	if (sock && sock->sk) {
		fact->protocol = sock->sk->sk_protocol;
		fact->cookie = sock_gen_cookie(sock->sk);
	}

	if (!address) {
		fact->kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_UNRESOLVED;
		fact->family = 0;
		return;
	}
	if (address_len < (int)sizeof(sa_family_t)) {
		fact->kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_MALFORMED;
		fact->family = 0;
		return;
	}
	if (unsupported) {
		fact->kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_UNSUPPORTED;
		fact->family = sa->sa_family;
		fact->addrlen = min_t(int, address_len, 128);
		return;
	}
	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = address;

		if (address_len != sizeof(*sin)) {
			fact->kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_MALFORMED;
			fact->family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET;
			fact->addrlen = min_t(int, address_len, 128);
			return;
		}
		fact->kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV4;
		fact->family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET;
		fact->addrlen = connected ? 0 : sizeof(*sin);
		fact->port = ntohs(sin->sin_port);
		memcpy(fact->address + 12, &sin->sin_addr, sizeof(sin->sin_addr));
		return;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 = address;

		if (address_len != sizeof(*sin6)) {
			fact->kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_MALFORMED;
			fact->family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET6;
			fact->addrlen = min_t(int, address_len, 128);
			return;
		}
		fact->kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_IPV6;
		fact->family = SPP_DIAG_TRACE_NETWORK_FAMILY_AF_INET6;
		fact->addrlen = connected ? 0 : sizeof(*sin6);
		fact->port = ntohs(sin6->sin6_port);
		fact->scope = sin6->sin6_scope_id;
		fact->flow = sin6->sin6_flowinfo;
		memcpy(fact->address, &sin6->sin6_addr, sizeof(sin6->sin6_addr));
		return;
	}
	default:
		fact->kind = SPP_DIAG_TRACE_NETWORK_ENDPOINT_UNSUPPORTED;
		fact->family = sa->sa_family;
		fact->addrlen = min_t(int, address_len, 128);
		return;
	}
}

static void spp_diag_trace_adapter_return(const void *task_token,
						  int (*lookup)(const void *, u64 *), s64 result)
{
	u64 operation_ordinal = 0;

	if (!lookup(task_token, &operation_ordinal) && operation_ordinal)
		spp_diag_trace_runtime_operation_return(task_token, operation_ordinal,
								       result);
}

void spp_diag_trace_adapter_exec_reserve(const char *path,
					 u32 *out_reservation_token)
{
	struct spp_diag_trace_fact_exec_attempt fact;

	if (!path || !out_reservation_token)
		return;
	fact.path = path;
	fact.path_len = strnlen(path, SPP_DIAG_TRACE_MAX_PATH_BYTES + 1u);
	fact.pid = task_pid_nr(current);
	fact.tgid = task_tgid_nr(current);
	spp_diag_trace_runtime_exec_reserve(current, &fact, out_reservation_token);
}

void spp_diag_trace_adapter_exec_pass(const struct linux_binprm *bprm)
{
	struct spp_diag_trace_fact_exec_attempt fact;

	if (!bprm || !bprm->filename)
		return;
	fact.path = bprm->filename;
	fact.path_len = strnlen(fact.path, SPP_DIAG_TRACE_MAX_PATH_BYTES + 1u);
	fact.pid = task_pid_nr(current);
	fact.tgid = task_tgid_nr(current);
	spp_diag_trace_runtime_exec_pass(current, &fact);
}

void spp_diag_trace_adapter_exec_commit(const struct linux_binprm *bprm)
{
	struct spp_diag_trace_fact_exec_commit fact;

	(void)bprm;
	fact.pid = task_pid_nr(current);
	fact.tgid = task_tgid_nr(current);
	spp_diag_trace_runtime_exec_commit(current, &fact);
}

void spp_diag_trace_adapter_exec_return(u32 reservation_token, s64 result)
{
	spp_diag_trace_runtime_exec_return(current, reservation_token, result);
}

void spp_diag_trace_adapter_exec_unsupported(void)
{
	spp_diag_trace_runtime_exec_unsupported(current);
}

void spp_diag_trace_adapter_task_alloc(const struct task_struct *parent,
					       const struct task_struct *child,
					       u64 clone_flags)
{
	struct spp_diag_trace_fact_task_alloc fact = { .clone_flags = clone_flags };

	(void)child;
	spp_diag_trace_runtime_task_alloc_attempt(parent, &fact);
}

void spp_diag_trace_adapter_task_created(const struct task_struct *parent,
					  const struct task_struct *child,
					  u64 clone_flags)
{
	struct spp_diag_trace_fact_task_created fact = {
		.pid = task_pid_nr(child),
		.tgid = task_tgid_nr(child),
		.clone_flags = clone_flags,
	};

	spp_diag_trace_runtime_task_created(parent, child, &fact);
}

void spp_diag_trace_adapter_task_exit(const struct task_struct *task,
					      int exit_code)
{
	spp_diag_trace_runtime_task_exit(task, exit_code);
}

void spp_diag_trace_adapter_file_open_attempt(int dfd, const char *path,
						      unsigned long open_flags)
{
	struct spp_diag_trace_fact_file_open_attempt fact;

	if (!path)
		return;
	fact.path = path;
	fact.path_len = strnlen(path, SPP_DIAG_TRACE_MAX_PATH_BYTES + 1u);
	fact.access = spp_diag_trace_adapter_file_access(open_flags);
	fact.modifiers = spp_diag_trace_adapter_file_modifiers(open_flags);
	fact.dirfd = (u32)dfd;
	spp_diag_trace_runtime_file_open_attempt(current, &fact, &(u64){ 0 });
}

void spp_diag_trace_adapter_file_open_policy(const struct file *file,
						     s64 result)
{
	struct spp_diag_trace_fact_file_policy fact;
	u64 operation_ordinal = 0;
	const struct inode *inode;

	if (!file)
		return;
	if ((file->f_mode & FMODE_EXEC) &&
	    !spp_diag_trace_runtime_exec_active_operation(current, &(u64){ 0 }))
		return;
	if (spp_diag_trace_runtime_file_open_active_operation(current,
									 &operation_ordinal))
		return;
	inode = file_inode(file);
	memset(&fact, 0, sizeof(fact));
	fact.access = spp_diag_trace_adapter_file_access(file->f_flags);
	fact.modifiers = spp_diag_trace_adapter_file_modifiers(file->f_flags);
	fact.decision = result ? SPP_DIAG_TRACE_POLICY_DENY :
		SPP_DIAG_TRACE_POLICY_ALLOW;
	fact.object_kind = spp_diag_trace_adapter_file_object_kind(inode);
	fact.result = (u32)result;
	spp_diag_trace_adapter_file_metadata(file, &fact.fs_magic, &fact.dev_major,
					     &fact.dev_minor, &fact.inode,
					     &fact.mount_identity, &fact.observed_size);
	spp_diag_trace_runtime_file_policy_decision(current, operation_ordinal, &fact);
}

void spp_diag_trace_adapter_file_open_return(s64 result)
{
	spp_diag_trace_adapter_return(current,
					  spp_diag_trace_runtime_file_open_active_operation, result);
}

void spp_diag_trace_adapter_mapping_policy(const struct file *file,
						  unsigned long prot,
						  unsigned long flags, s64 result)
{
	struct spp_diag_trace_fact_mapping_policy fact;

	if (!(prot & PROT_EXEC))
		return;
	spp_diag_trace_adapter_mapping_fact(&fact, file,
		SPP_DIAG_TRACE_MAPPING_OPERATION_MMAP, prot, prot, 0, flags, result);
	spp_diag_trace_runtime_mapping_policy_decision(current, &fact, &(u64){ 0 });
}

void spp_diag_trace_adapter_mapping_unsupported(void)
{
	spp_diag_trace_runtime_mapping_unsupported(current);
}

void spp_diag_trace_adapter_mapping_return(s64 result)
{
	spp_diag_trace_adapter_return(current,
					  spp_diag_trace_runtime_mmap_active_operation, result);
}

void spp_diag_trace_adapter_mprotect_policy(const struct vm_area_struct *vma,
						    unsigned long requested_prot,
						    unsigned long effective_prot,
						    s64 result)
{
	struct spp_diag_trace_fact_mapping_policy fact;
	unsigned long prior;

	if (!vma || !(effective_prot & PROT_EXEC))
		return;
	prior = spp_diag_trace_adapter_vm_protection(vma->vm_flags);
	spp_diag_trace_adapter_mapping_fact(&fact, vma->vm_file,
		SPP_DIAG_TRACE_MAPPING_OPERATION_MPROTECT, requested_prot,
		effective_prot, prior, (vma->vm_flags & VM_SHARED) ? MAP_SHARED : 0,
		result);
	spp_diag_trace_runtime_mapping_policy_decision(current, &fact, &(u64){ 0 });
}

void spp_diag_trace_adapter_mprotect_return(s64 result)
{
	spp_diag_trace_adapter_return(current,
					  spp_diag_trace_runtime_mprotect_active_operation, result);
}

void spp_diag_trace_adapter_connect_policy(const struct socket *sock,
						  const void *address, int address_len,
						  int flags, s64 result)
{
	struct spp_diag_trace_fact_network_policy fact;

	spp_diag_trace_adapter_network_fact(&fact, sock, address, address_len,
		SPP_DIAG_TRACE_NETWORK_OPERATION_CONNECT, 0, result, false, false);
	spp_diag_trace_runtime_network_policy_decision(current, &fact, &(u64){ 0 });
	(void)flags;
}

void spp_diag_trace_adapter_connect_unsupported(const struct socket *sock,
						       const void *address, int address_len,
						       int flags)
{
	(void)sock;
	(void)address;
	(void)address_len;
	(void)flags;
	spp_diag_trace_runtime_network_unsupported(current);
}

void spp_diag_trace_adapter_connect_return(s64 result)
{
	spp_diag_trace_adapter_return(current,
					  spp_diag_trace_runtime_connect_active_operation, result);
}

void spp_diag_trace_adapter_sendmsg_policy(const struct socket *sock,
						  const struct msghdr *msg,
						  unsigned int flags, s64 result)
{
	struct spp_diag_trace_fact_network_policy fact;
	struct sockaddr_storage peer;
	const void *address = msg ? msg->msg_name : NULL;
	int address_len = msg ? msg->msg_namelen : 0;
	bool connected = !address;

	if (connected && sock && sock->ops && sock->ops->getname) {
		address_len = sizeof(peer);
		if (!sock->ops->getname((struct socket *)sock,
					 (struct sockaddr *)&peer, &address_len, 1))
			address = &peer;
	}

	spp_diag_trace_adapter_network_fact(&fact, sock, address, address_len,
		SPP_DIAG_TRACE_NETWORK_OPERATION_SENDMSG, flags, result, connected, false);
	if (msg)
		fact.size = msg_data_left((struct msghdr *)msg);
	spp_diag_trace_runtime_network_policy_decision(current, &fact, &(u64){ 0 });
}

void spp_diag_trace_adapter_sendmsg_unsupported(const struct socket *sock,
						       const struct msghdr *msg,
						       unsigned int flags)
{
	(void)sock;
	(void)msg;
	(void)flags;
	spp_diag_trace_runtime_network_unsupported(current);
}

void spp_diag_trace_adapter_sendmsg_return(s64 result)
{
	spp_diag_trace_adapter_return(current,
					  spp_diag_trace_runtime_sendmsg_active_operation, result);
}
