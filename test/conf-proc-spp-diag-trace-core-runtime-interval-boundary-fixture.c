/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <string.h>

#include <linux/ima.h>
#include <linux/sched.h>
#include <linux/spp_diag_trace_adapter.h>

#include "conf-proc-spp-diag-trace-core-runtime-adapter-fixture.h"

static int sealing_status;
static struct task_struct sealing_kthread = { .flags = PF_KTHREAD };

static int prebind_start(struct task_struct *root)
{
	spp_diag_trace_core_reset();
	spp_diag_trace_core_set_op_caps(SPP_DIAG_TRACE_MAX_FRAMES,
					       SPP_DIAG_TRACE_MAX_STREAM_BYTES);
	host_kmod_reset();
	host_ima_reset();
	*root = (struct task_struct){ .pid = 1, .tgid = 1 };
	host_current_task_ptr = root;
	host_saved_command_line_set(spp_adapter_valid_command_line);
	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();
	return spp_diag_trace_runtime_init() || !spp_diag_trace_core_is_green() ? -1 : 0;
}

static void sealing_hook(const struct host_ima_call *call)
{
	(void)call;
	sealing_status = spp_diag_trace_core_runtime_task_exit(&sealing_kthread, 0);
}

static int command(u16 kind, u16 phase)
{
	u8 raw[SPP_DIAG_TRACE_COMMAND_SIZE] = { SPP_DIAG_TRACE_MAGIC_COMMAND_BYTES };
	u8 challenge[32], run[32], control[32];
	size_t i;

	for (i = 0; i < 32; i++) {
		challenge[i] = (u8)i;
		run[i] = (u8)(32 + i);
		control[i] = (u8)(64 + i);
	}
	raw[9] = 1;
	raw[10] = (u8)(kind >> 8);
	raw[11] = (u8)kind;
	raw[15] = SPP_DIAG_TRACE_COMMAND_SIZE;
	memcpy(raw + 16, challenge, sizeof(challenge));
	memcpy(raw + 48, run, sizeof(run));
	memcpy(raw + 80, control, sizeof(control));
	raw[112] = (u8)(phase >> 8);
	raw[113] = (u8)phase;
	return spp_diag_trace_core_runtime_handle_command(raw, sizeof(raw));
}

static int advance_to_final(void)
{
	u16 phase;

	for (phase = 2; phase <= SPP_DIAG_TRACE_PHASE_EVIDENCE_FINALIZE; phase++) {
		int err = command(SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, phase);

		if (err) {
			fprintf(stderr, "advance failed phase=%u err=%d green=%d\n", phase, err,
				spp_diag_trace_core_is_green());
			return -1;
		}
	}
	return 0;
}

int main(void)
{
	struct task_struct root;
	struct task_struct kthread = { .flags = PF_KTHREAD };
	int prebind, active, sealed;

	if (prebind_start(&root))
		return 1;
	prebind = spp_diag_trace_core_runtime_task_exit(&kthread, 0);
	if (prebind != SPP_DIAG_TRACE_ERR_INACTIVE || !spp_diag_trace_core_is_green())
		return 1;
	if (spp_adapter_fixture_start(&root))
		return 2;
	spp_diag_trace_adapter_task_exit(&kthread, 0);
	active = spp_diag_trace_core_is_green() ? 0 : -1;
	if (active || advance_to_final())
		return 3;
	sealing_status = 0;
	host_ima_set_hook(sealing_hook);
	if (command(SPP_DIAG_TRACE_CMD_SEAL, SPP_DIAG_TRACE_PHASE_SEALED) == 0 ||
	    sealing_status == 0 || spp_diag_trace_core_is_green())
		return 4;
	host_ima_set_hook(NULL);
	if (spp_adapter_fixture_start(&root) || advance_to_final() ||
	    command(SPP_DIAG_TRACE_CMD_SEAL, SPP_DIAG_TRACE_PHASE_SEALED))
		return 5;
	sealed = spp_diag_trace_core_runtime_task_exit(&kthread, 0);
	if (sealed != SPP_DIAG_TRACE_ERR_INACTIVE || !spp_diag_trace_core_is_green())
		return 6;
	printf("prebind=%d active=%d sealing=%d sealed=%d\n", prebind, active,
		sealing_status, sealed);
	return 0;
}
