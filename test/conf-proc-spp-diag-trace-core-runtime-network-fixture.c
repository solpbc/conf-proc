/* SPDX-License-Identifier: GPL-2.0-only */

#include <limits.h>
#include <string.h>

#include <linux/errno.h>
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
		.sin6_flowinfo = htonl(0x11223344), .sin6_scope_id = 0x55667788,
		.sin6_addr = { .s6_addr = { 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 1 } } };
	struct msghdr message = { .msg_name = &ipv6, .msg_namelen = sizeof(ipv6),
		.msg_iter = { .count = INT_MAX } };
	bool unsupported = argc == 2 && (!strcmp(argv[1], "--unsupported") ||
		!strcmp(argv[1], "--connect-unsupported"));
	bool connected = argc == 2 && !strcmp(argv[1], "--connected");
	bool oversized = argc == 2 && !strcmp(argv[1], "--oversized");
	bool bad_family = argc == 2 && !strcmp(argv[1], "--bad-family");
	bool bad_length = argc == 2 && !strcmp(argv[1], "--bad-length");

	if (argc > 2 || (argc == 2 && !unsupported && !connected && !oversized &&
					  !bad_family && !bad_length) ||
	    spp_adapter_fixture_start(&root))
		return 64;
	if (unsupported) {
		/* Cached sendmmsg and the two kernel-only helpers all take this red path. */
		if (!strcmp(argv[1], "--connect-unsupported"))
			spp_diag_trace_adapter_connect_unsupported(&stream, &ipv4, sizeof(ipv4), 0);
		else
			spp_diag_trace_adapter_sendmsg_unsupported(&datagram, &message, 0);
		return spp_diag_trace_core_is_green() ? 2 : 42;
	}
	if (connected || oversized) {
		if (connected)
			message.msg_name = NULL;
		else
			message.msg_iter.count = (size_t)INT_MAX + 1;
		if (spp_diag_trace_adapter_sendmsg_precheck(&datagram, &message) != -EIO)
			return 5;
		return spp_diag_trace_core_is_green() ? 2 : 42;
	}
	if (bad_family || bad_length) {
		if (bad_family)
			ipv4.sin_family = 99;
		spp_diag_trace_adapter_connect_policy(
			&stream, &ipv4, bad_length ? sizeof(ipv4) - 1 : sizeof(ipv4), 0, 0);
		return spp_diag_trace_core_is_green() ? 2 : 42;
	}
	spp_diag_trace_adapter_connect_policy(&stream, &ipv4, sizeof(ipv4), 0, 0);
	spp_diag_trace_adapter_connect_return(0);
	if (spp_diag_trace_adapter_sendmsg_precheck(&datagram, &message))
		return 5;
	spp_diag_trace_adapter_sendmsg_policy(&datagram, &message, 0x55, -13);
	spp_diag_trace_adapter_sendmsg_return(-13);
	if (!spp_diag_trace_core_is_green())
		return 3;
	return spp_adapter_fixture_stream() ? 4 : 0;
}
