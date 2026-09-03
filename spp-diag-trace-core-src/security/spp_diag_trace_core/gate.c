/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/binfmts.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/string.h>

#include <linux/spp_diag_trace_bootstrap.h>

#include "core.h"

int spp_diag_trace_bootstrap_bprm_check(struct linux_binprm *bprm)
{
	const char *path = bprm ? bprm->filename : NULL;
	size_t path_length = 0;
	int pid = task_pid_nr(current);
	int tgid = task_tgid_nr(current);

	if (path)
		path_length = strnlen(path, SPP_DIAG_TRACE_MAX_PATH_BYTES + 1u);
	return spp_diag_trace_core_bootstrap_gate(path, path_length,
					  pid > 0 ? (u32)pid : 0,
					  tgid > 0 ? (u32)tgid : 0);
}
