/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_IN6_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_IN6_H

#include <linux/socket.h>

struct in6_addr {
	u8 s6_addr[16];
};

struct sockaddr_in6 {
	sa_family_t sin6_family;
	u16 sin6_port;
	u32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	u32 sin6_scope_id;
};

#endif
