/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/errno.h>
#include <linux/ima.h>
#include <linux/kmod.h>
#include <linux/panic.h>
#include <linux/pid.h>
#include <linux/sched.h>

#include <linux/spp_diag_trace_bootstrap.h>
#include <linux/spp_diag_trace_runtime.h>

#include "core.h"

static const char ima_label[] = "sol_spp_diag_trace";

static void __init fail_stop(const char *message)
{
	spp_diag_trace_core_mark_failure(WIRE_STATE);
	panic(message);
}

void __init spp_diag_trace_bootstrap_ima_ready(void)
{
	if (spp_diag_trace_core_bootstrap_ima_available())
		fail_stop("spp diag trace IMA availability");
}

void __init spp_diag_trace_bootstrap_release(void)
{
	char *argv[] = { (char *)SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH, NULL };
	char *envp[] = { NULL };
	u8 record[SPP_DIAG_TRACE_IMA_SIZE];
	int pid;
	int tgid;

	if (call_usermodehelper(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH, argv, envp,
				UMH_WAIT_EXEC) != -EACCES) {
		fail_stop("spp diag trace canary");
		return;
	}
	if (spp_diag_trace_core_bootstrap_prepare_ready(record)) {
		fail_stop("spp diag trace READY append");
		return;
	}
	if (ima_measure_critical_data(ima_label, "sol-spp-diag-ready-v1", record,
				      sizeof(record), false, NULL, 0)) {
		fail_stop("spp diag trace READY measurement");
		return;
	}
	if (spp_diag_trace_core_bootstrap_ready_measured()) {
		fail_stop("spp diag trace READY state");
		return;
	}

	pid = task_pid_nr(current);
	tgid = task_tgid_nr(current);
	if (pid != 1 || tgid != 1 ||
	    spp_diag_trace_core_bootstrap_prepare_release((u32)pid, (u32)tgid,
							 record)) {
		fail_stop("spp diag trace release state");
		return;
	}
	if (ima_measure_critical_data(ima_label, "sol-spp-diag-release-v1", record,
				      sizeof(record), false, NULL, 0)) {
		fail_stop("spp diag trace RELEASE measurement");
		return;
	}
	if (spp_diag_trace_core_bootstrap_release_measured()) {
		fail_stop("spp diag trace release publication");
		return;
	}
	if (!spp_diag_trace_runtime_ready()) {
		fail_stop("spp diag trace runtime readiness");
		return;
	}
	if (spp_diag_trace_core_bootstrap_publish()) {
		fail_stop("spp diag trace release publication");
		return;
	}
	if (spp_diag_trace_runtime_bind_root(current)) {
		fail_stop("spp diag trace runtime bind root");
		return;
	}
}
