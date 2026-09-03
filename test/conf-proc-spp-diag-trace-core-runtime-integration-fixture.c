/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <string.h>

#include <linux/binfmts.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/kdev_t.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/spp_diag_trace_adapter.h>
#include <linux/spp_diag_trace_adapter_shim.h>

#include <net/sock.h>

#include "conf-proc-spp-diag-trace-core-runtime-adapter-fixture.h"

int main(int argc, char **argv)
{
	struct task_struct root;
	const char exec_path[] = "/usr/bin/python3";
	const char file_path[] = "/etc/ld.so.cache";
	struct linux_binprm bprm = { .filename = exec_path };
	struct super_block file_sb = { .s_magic = 0xef53, .s_dev = MKDEV(8, 1) };
	struct inode file_inode_value = { .i_mode = S_IFREG, .i_ino = 12345,
		.i_size = 4096, .i_sb = &file_sb };
	struct mount file_mount = { .mnt_id_unique = 67890 };
	struct file file = { .f_inode = &file_inode_value,
		.f_flags = O_RDONLY | O_NOFOLLOW, .f_path = { .mnt = &file_mount.mnt } };
	struct super_block map_sb = { .s_magic = 0xef53, .s_dev = MKDEV(8, 1) };
	struct inode map_inode = { .i_mode = S_IFREG, .i_ino = 2000,
		.i_size = 8192, .i_sb = &map_sb };
	struct mount map_mount = { .mnt_id_unique = 3000 };
	struct file map_file = { .f_inode = &map_inode,
		.f_path = { .mnt = &map_mount.mnt } };
	struct vm_area_struct vma = { .vm_file = &map_file, .vm_flags = VM_READ };
	struct sock connect_sk = { .sk_protocol = 6, .cookie = 0x1122334455667788ull };
	struct socket connect_sock = { .type = SOCK_STREAM, .sk = &connect_sk };
	struct sockaddr_in connect_address = { .sin_family = AF_INET,
		.sin_port = htons(443), .sin_addr = { .s_addr = { 10, 0, 0, 1 } } };
	struct sock send_sk = { .sk_protocol = 17, .cookie = 0x99aabbccddeeff00ull };
	struct socket send_sock = { .type = SOCK_DGRAM, .sk = &send_sk };
	struct sockaddr_in6 send_address = { .sin6_family = AF_INET6,
		.sin6_port = htons(53), .sin6_flowinfo = htonl(2), .sin6_scope_id = 1,
		.sin6_addr = { .s6_addr = { 0x20, 0x01, 0x0d, 0xb8,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };
	struct msghdr send_msg = { .msg_name = &send_address,
		.msg_namelen = sizeof(send_address), .msg_iter = { .count = 512 } };
	u32 reservation = 0;
	bool wrong_token = argc == 2 && !strcmp(argv[1], "--wrong-token");

	if (argc > 2 || (argc == 2 && !wrong_token))
		return 64;
	if (spp_adapter_fixture_start(&root))
		return 1;

	/* Simulates reserve-before-open, then the first bprm handler pass. */
	spp_diag_trace_adapter_exec_reserve(exec_path, &reservation);
	spp_diag_trace_adapter_exec_pass(&bprm);
	spp_diag_trace_adapter_exec_pass(&bprm);
	spp_diag_trace_adapter_exec_commit(&bprm);
	spp_diag_trace_adapter_exec_return(wrong_token ? reservation + 1 : reservation, 0);
	if (wrong_token)
		return spp_diag_trace_core_is_green() ? 2 : 42;
	if (!spp_diag_trace_core_is_green())
		return 3;

	spp_diag_trace_adapter_file_open_attempt(-100, file_path, O_RDONLY | O_NOFOLLOW);
	spp_diag_trace_adapter_file_open_policy(&file, 0);
	spp_diag_trace_adapter_file_open_return(0, &file);
	if (!spp_diag_trace_core_is_green())
		return 10;
	spp_diag_trace_adapter_mapping_policy(&map_file, PROT_READ | PROT_EXEC, 0, 0);
	spp_diag_trace_adapter_mapping_return(0);
	if (!spp_diag_trace_core_is_green())
		return 11;
	spp_diag_trace_adapter_mprotect_policy(&vma, PROT_READ | PROT_WRITE | PROT_EXEC,
		PROT_READ | PROT_WRITE | PROT_EXEC, 0);
	spp_diag_trace_adapter_mprotect_policy(&vma, PROT_READ | PROT_WRITE | PROT_EXEC,
		PROT_READ | PROT_WRITE | PROT_EXEC, -1);
	spp_diag_trace_adapter_mprotect_return(-1);
	if (!spp_diag_trace_core_is_green())
		return 12;
	spp_diag_trace_adapter_connect_policy(&connect_sock, &connect_address,
		sizeof(connect_address), 0, 0);
	spp_diag_trace_adapter_connect_return(0);
	if (!spp_diag_trace_core_is_green())
		return 13;
	if (spp_diag_trace_adapter_sendmsg_precheck(&send_sock, &send_msg))
		return 14;
	spp_diag_trace_adapter_sendmsg_policy(&send_sock, &send_msg, 0, -13);
	spp_diag_trace_adapter_sendmsg_return(-13);
	if (!spp_diag_trace_core_is_green())
		return 4;
	return spp_adapter_fixture_stream() ? 5 : 0;
}
