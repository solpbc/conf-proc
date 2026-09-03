/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_RUNTIME_ADAPTER_FIXTURE_H
#define SPP_DIAG_TRACE_CORE_RUNTIME_ADAPTER_FIXTURE_H

#include <stdio.h>
#include <string.h>

#include <linux/ima.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/spp_diag_trace_bootstrap.h>
#include <linux/spp_diag_trace_runtime.h>

#include "core.h"

static const char spp_adapter_valid_command_line[] =
	"ima_policy=critical_data "
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static int spp_adapter_fixture_emit(const void *data, size_t length)
{
	u8 size[4] = {
		(u8)(length >> 24), (u8)(length >> 16),
		(u8)(length >> 8), (u8)length,
	};

	return fwrite(size, 1, sizeof(size), stdout) == sizeof(size) &&
		fwrite(data, 1, length, stdout) == length ? 0 : -1;
}

static int spp_adapter_fixture_start(struct task_struct *root)
{
	spp_diag_trace_core_reset();
	spp_diag_trace_core_set_op_caps(SPP_DIAG_TRACE_MAX_FRAMES,
					       SPP_DIAG_TRACE_MAX_STREAM_BYTES);
	host_kmod_reset();
	host_ima_reset();
	*root = (struct task_struct){ .pid = 1, .tgid = 1, .flags = 0 };
	host_current_task_ptr = root;
	host_saved_command_line_set(spp_adapter_valid_command_line);
	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();
	if (spp_diag_trace_runtime_init())
		return -1;
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_release();
	return spp_diag_trace_runtime_ready() && spp_diag_trace_core_is_green() ? 0 : -1;
}

static __attribute__((unused)) int spp_adapter_fixture_stream(void)
{
	u8 snapshot_buffer[65536];
	struct spp_diag_trace_core_snapshot *snapshot =
		(struct spp_diag_trace_core_snapshot *)snapshot_buffer;
	size_t required;

	if (spp_diag_trace_core_snapshot(snapshot_buffer, sizeof(snapshot_buffer), &required))
		return -1;
	return spp_adapter_fixture_emit(snapshot_buffer + sizeof(*snapshot), snapshot->stream_len);
}

#endif
