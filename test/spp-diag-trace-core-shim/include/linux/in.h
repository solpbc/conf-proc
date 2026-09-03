/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_IN_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_IN_H

#include <linux/socket.h>

struct in_addr {
	u8 s_addr[4];
};

struct sockaddr_in {
	sa_family_t sin_family;
	u16 sin_port;
	struct in_addr sin_addr;
	u8 sin_zero[8];
};

static inline u16 ntohs(u16 value)
{
	return (u16)((value << 8) | (value >> 8));
}

static inline u16 htons(u16 value)
{
	return ntohs(value);
}

#endif
