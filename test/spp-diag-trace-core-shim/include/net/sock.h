/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_NET_SOCK_H
#define SPP_DIAG_TRACE_CORE_SHIM_NET_SOCK_H

#include <linux/socket.h>

struct sock {
	u16 sk_protocol;
	u64 cookie;
	void *peer;
};

static inline u64 sock_gen_cookie(const struct sock *sk)
{
	return sk ? sk->cookie : 0;
}

#endif
