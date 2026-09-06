/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_UN_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_UN_H
#include <linux/socket.h>
struct sockaddr_un {
	sa_family_t sun_family;
	char sun_path[108];
};
#endif
