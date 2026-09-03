/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_SOCKET_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_SOCKET_H

#include <linux/types.h>

typedef u16 sa_family_t;

#define AF_INET 2
#define AF_INET6 10

#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_SEQPACKET 5

struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
};

struct sockaddr_storage {
	sa_family_t ss_family;
	u8 __data[126];
};

struct socket;
struct sock;

struct proto_ops {
	int (*getname)(struct socket *sock, struct sockaddr *addr, int *addr_len,
		       int peer);
};

struct socket {
	int type;
	struct sock *sk;
	const struct proto_ops *ops;
};

struct iov_iter {
	size_t count;
};

struct msghdr {
	void *msg_name;
	int msg_namelen;
	unsigned int msg_flags;
	struct iov_iter msg_iter;
};

static inline size_t msg_data_left(struct msghdr *msg)
{
	return msg ? msg->msg_iter.count : 0;
}

#endif
