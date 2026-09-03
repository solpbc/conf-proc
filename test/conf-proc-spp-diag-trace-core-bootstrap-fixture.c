/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <string.h>

#include <crypto/sha2.h>
#include <linux/errno.h>

#include "core.h"

static const char command_line[] =
	"ima_policy=critical_data "
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static int emit_blob(const void *data, size_t length)
{
	u8 size[4] = {
		(u8)(length >> 24), (u8)(length >> 16),
		(u8)(length >> 8), (u8)length,
	};

	return fwrite(size, 1, sizeof(size), stdout) == sizeof(size) &&
	       fwrite(data, 1, length, stdout) == length ? 0 : -1;
}

int main(void)
{
	u8 challenge[32], run[32], control[32], command_hash[32];
	u8 ready[SPP_DIAG_TRACE_IMA_SIZE];
	u8 released[SPP_DIAG_TRACE_IMA_SIZE];
	u8 snapshot_buffer[8192];
	struct spp_diag_trace_core_snapshot *snapshot =
		(struct spp_diag_trace_core_snapshot *)snapshot_buffer;
	size_t required;
	size_t i;

	for (i = 0; i < 32; i++) {
		challenge[i] = (u8)i;
		run[i] = (u8)(i + 32);
		control[i] = (u8)(i + 64);
	}
	sha256((const u8 *)command_line, strlen(command_line), command_hash);
	spp_diag_trace_core_reset();
	if (spp_diag_trace_core_init(challenge, run, control, command_hash) ||
	    spp_diag_trace_core_bootstrap_ima_available() ||
	    spp_diag_trace_core_bootstrap_gate(
		SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH,
		strlen(SPP_DIAG_TRACE_BOOTSTRAP_CANARY_PATH), 1, 1) != -EACCES ||
	    spp_diag_trace_core_bootstrap_prepare_ready(ready) ||
	    spp_diag_trace_core_bootstrap_ready_measured() ||
	    spp_diag_trace_core_bootstrap_prepare_release(1, 1, released) ||
	    spp_diag_trace_core_snapshot(snapshot_buffer, sizeof(snapshot_buffer),
					 &required))
		return 1;
	if (emit_blob(snapshot_buffer + sizeof(*snapshot), snapshot->stream_len) ||
	    emit_blob(ready, sizeof(ready)) || emit_blob(released, sizeof(released)))
		return 1;
	return 0;
}
