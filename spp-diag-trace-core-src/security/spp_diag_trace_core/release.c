/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/errno.h>
#include <linux/ima.h>
#include <linux/kmod.h>
#include <linux/panic.h>
#include <linux/pid.h>
#include <linux/sched.h>

#include <linux/spp_diag_trace_bootstrap.h>

#include "core.h"

static const char canary_path[] = "/usr/local/libexec/solstone/pre-release-denied";
static const char ima_label[] = "sol_spp_diag_trace";

static void store_u32be(u8 *p, u32 value)
{
	p[0] = (u8)(value >> 24);
	p[1] = (u8)(value >> 16);
	p[2] = (u8)(value >> 8);
	p[3] = (u8)value;
}

static void store_u64be(u8 *p, u64 value)
{
	p[0] = (u8)(value >> 56);
	p[1] = (u8)(value >> 48);
	p[2] = (u8)(value >> 40);
	p[3] = (u8)(value >> 32);
	p[4] = (u8)(value >> 24);
	p[5] = (u8)(value >> 16);
	p[6] = (u8)(value >> 8);
	p[7] = (u8)value;
}

static int check_ready(void)
{
	return spp_diag_trace_bootstrap_denial_count() == 1 &&
		spp_diag_trace_core_is_green();
}

void __init spp_diag_trace_bootstrap_ima_ready(void)
{
	char *argv[] = { (char *)canary_path, NULL };
	char *envp[] = { NULL };
	u8 payload[8];
	u8 record[SPP_DIAG_TRACE_IMA_SIZE];
	int result;

	result = call_usermodehelper(canary_path, argv, envp, UMH_WAIT_EXEC);
	if (result != -EACCES || !check_ready()) {
		panic("spp diag trace canary");
		return;
	}
	store_u64be(payload, (u64)spp_diag_trace_bootstrap_denial_count());
	result = spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_IMA_READY, 0, 0,
					    0, 0,
					    SPP_DIAG_TRACE_PHASE_PRE_RELEASE,
					    payload, sizeof(payload));
	if (result) {
		panic("spp diag trace ima append");
		return;
	}
	spp_diag_trace_bootstrap_note_frame(SPP_DIAG_TRACE_EVENT_IMA_READY, 0, 0,
					    0, 0,
					    SPP_DIAG_TRACE_PHASE_PRE_RELEASE,
					    payload, sizeof(payload));
	spp_diag_trace_bootstrap_ima_record(SPP_DIAG_TRACE_IMA_KIND_READY,
					    (u64)spp_diag_trace_bootstrap_denial_count(), record);
	if (ima_measure_critical_data(ima_label, "sol-spp-diag-ready-v1", record,
				      sizeof(record), false, NULL, 0)) {
		panic("spp diag trace ready measurement");
		return;
	}
}

void __init spp_diag_trace_bootstrap_release(void)
{
	u8 payload[16];
	u8 record[SPP_DIAG_TRACE_IMA_SIZE];
	int result;

	if (!check_ready() || !task_pid_nr(current) || !task_tgid_nr(current)) {
		panic("spp diag trace release state");
		return;
	}
	store_u32be(payload, (u32)task_pid_nr(current));
	store_u32be(payload + 4, (u32)task_tgid_nr(current));
	store_u64be(payload + 8, (u64)spp_diag_trace_bootstrap_denial_count());
	result = spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE,
					    0, 1, 0, 0,
					    SPP_DIAG_TRACE_PHASE_PRE_RELEASE,
					    payload, sizeof(payload));
	if (result) {
		panic("spp diag trace release append");
		return;
	}
	spp_diag_trace_bootstrap_note_frame(SPP_DIAG_TRACE_EVENT_USERSPACE_RELEASE,
					    0, 1, 0, 0,
					    SPP_DIAG_TRACE_PHASE_PRE_RELEASE,
					    payload, sizeof(payload));
	spp_diag_trace_bootstrap_ima_record(SPP_DIAG_TRACE_IMA_KIND_RELEASED,
					    (u64)spp_diag_trace_bootstrap_denial_count(), record);
	if (ima_measure_critical_data(ima_label, "sol-spp-diag-release-v1", record,
				      sizeof(record), false, NULL, 0)) {
		panic("spp diag trace release measurement");
		return;
	}
	spp_diag_trace_bootstrap_publish_release();
}
