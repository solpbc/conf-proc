/* SPDX-License-Identifier: GPL-2.0-only */

#include <limits.h>
#include <string.h>

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/spp_diag_trace_adapter.h>

#include <net/sock.h>

#include "conf-proc-spp-diag-trace-core-runtime-adapter-fixture.h"

int main(int argc, char **argv)
{
	struct task_struct root;
	struct sock stream_sk = { .sk_protocol = 6, .cookie = 1 };
	struct sock datagram_sk = { .sk_protocol = 17, .cookie = 2 };
	struct socket stream = { .type = SOCK_STREAM, .sk = &stream_sk };
	struct socket datagram = { .type = SOCK_DGRAM, .sk = &datagram_sk };
	struct sockaddr_in ipv4 = { .sin_family = AF_INET, .sin_port = htons(443),
		.sin_addr = { .s_addr = { 127, 0, 0, 1 } } };
	struct sockaddr_in6 ipv6 = { .sin6_family = AF_INET6, .sin6_port = htons(53),
		.sin6_addr = { .s6_addr = { 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1 } } };
	struct msghdr message = { .msg_name = &ipv6, .msg_namelen = sizeof(ipv6),
		.msg_iter = { .count = INT_MAX } };
	bool unsupported = argc == 2 && (!strcmp(argv[1], "--unsupported") ||
		!strcmp(argv[1], "--connect-unsupported"));

	if (argc > 2 || (argc == 2 && !unsupported) || spp_adapter_fixture_start(&root))
		return 64;
	if (unsupported) {
		/* Cached sendmmsg and the two kernel-only helpers all take this red path. */
		if (!strcmp(argv[1], "--connect-unsupported"))
			spp_diag_trace_adapter_connect_unsupported(&stream, &ipv4, sizeof(ipv4), 0);
		else
			spp_diag_trace_adapter_sendmsg_unsupported(&datagram, &message, 0);
		return spp_diag_trace_core_is_green() ? 2 : 42;
	}
	spp_diag_trace_adapter_connect_policy(&stream, &ipv4, sizeof(ipv4), 0, 0);
	spp_diag_trace_adapter_connect_return(0);
	spp_diag_trace_adapter_sendmsg_policy(&datagram, &message, 0x55, -13);
	spp_diag_trace_adapter_sendmsg_return(-13);
	if (!spp_diag_trace_core_is_green())
		return 3;
	return spp_adapter_fixture_stream() ? 4 : 0;
}
