/* SPDX-License-Identifier: GPL-2.0-only */

#include <string.h>

#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/spp_diag_trace_adapter.h>

#include "conf-proc-spp-diag-trace-core-runtime-adapter-fixture.h"

int main(int argc, char **argv)
{
	struct task_struct root, child = { .pid = 42, .tgid = 42 };
	struct task_struct kparent = { .flags = PF_KTHREAD };
	struct task_struct kchild = { .flags = PF_KTHREAD };
	const char kernel_path[] = "/sbin/init";
	const char user_path[] = "/usr/bin/env";
	struct linux_binprm kernel_bprm = { .filename = kernel_path };
	struct linux_binprm user_bprm = { .filename = user_path };
	u32 kernel_reservation = 0, user_reservation = 0, denied_reservation = 0;
	bool wrong = argc == 2 && !strcmp(argv[1], "--wrong-token");
	bool unsupported = argc == 2 && !strcmp(argv[1], "--unsupported");

	if (argc > 2 || (argc == 2 && !wrong && !unsupported) ||
	    spp_adapter_fixture_start(&root))
		return 64;
	if (unsupported) {
		spp_diag_trace_adapter_exec_unsupported();
		return spp_diag_trace_core_is_green() ? 2 : 42;
	}
	/* Parent/child lifecycle occurs before either task is runnable. */
	spp_diag_trace_adapter_task_alloc(&root, &child, 0x1234);
	spp_diag_trace_adapter_task_created(&root, &child, 0x1234);

	/* Two reservations coexist before their first bprm pass. */
	host_current_task_ptr = &root;
	spp_diag_trace_adapter_exec_reserve(kernel_path, &kernel_reservation);
	host_current_task_ptr = &child;
	spp_diag_trace_adapter_exec_reserve(user_path, &user_reservation);
	host_current_task_ptr = &root;
	if (wrong) {
		spp_diag_trace_adapter_exec_return(user_reservation, -1);
		return spp_diag_trace_core_is_green() ? 2 : 42;
	}
	/* The original path is supplied at every recursive binfmt handler pass. */
	spp_diag_trace_adapter_exec_pass(&kernel_bprm);
	spp_diag_trace_adapter_exec_pass(&kernel_bprm);
	spp_diag_trace_adapter_exec_commit(&kernel_bprm);
	spp_diag_trace_adapter_exec_return(kernel_reservation, 0);

	host_current_task_ptr = &child;
	spp_diag_trace_adapter_exec_pass(&user_bprm);
	spp_diag_trace_adapter_exec_commit(&user_bprm);
	spp_diag_trace_adapter_exec_return(user_reservation, -13);
	/* A denial before commit still releases its one reservation. */
	spp_diag_trace_adapter_exec_reserve("/missing", &denied_reservation);
	spp_diag_trace_adapter_exec_return(denied_reservation, -2);
	spp_diag_trace_adapter_task_exit(&child, 17);

	/* Both documented untracked PF_KTHREAD exceptions stay non-recording. */
	spp_diag_trace_adapter_task_alloc(&kparent, &kchild, 0);
	spp_diag_trace_adapter_task_created(&kparent, &kchild, 0);
	spp_diag_trace_adapter_task_exit(&kchild, 0);
	if (!spp_diag_trace_core_is_green())
		return 3;
	return spp_adapter_fixture_stream() ? 4 : 0;
}
