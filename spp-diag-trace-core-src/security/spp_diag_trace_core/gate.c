/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/panic.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/string.h>

#include <linux/spp_diag_trace_bootstrap.h>

#include "core.h"

static atomic_long_t denial_count = ATOMIC_LONG_INIT(0);
static bool released;

static void store_u16be(u8 *p, u16 value)
{
	p[0] = (u8)(value >> 8);
	p[1] = (u8)value;
}

static void store_u32be(u8 *p, u32 value)
{
	p[0] = (u8)(value >> 24);
	p[1] = (u8)(value >> 16);
	p[2] = (u8)(value >> 8);
	p[3] = (u8)value;
}

long spp_diag_trace_bootstrap_denial_count(void)
{
	return atomic_long_read(&denial_count);
}

void spp_diag_trace_bootstrap_publish_release(void)
{
	smp_store_release(&released, true);
}

int spp_diag_trace_bootstrap_bprm_check(struct linux_binprm *bprm)
{
	const char *path;
	size_t path_length;
	long count;
	u8 payload[SPP_DIAG_TRACE_MAX_PAYLOAD_BYTES];
	int result;

	if (smp_load_acquire(&released))
		return 0;
	count = atomic_long_inc_return(&denial_count);
	if (count != 1) {
		spp_diag_trace_core_mark_failure(WIRE_STATE);
		return -EACCES;
	}
	if (!bprm || !bprm->filename) {
		panic("spp diag trace gate pathname");
		return -EACCES;
	}
	path = bprm->filename;
	path_length = strlen(path);
	if (!path_length || path_length > SPP_DIAG_TRACE_MAX_PATH_BYTES ||
	    !task_pid_nr(current) || !task_tgid_nr(current)) {
		panic("spp diag trace gate payload");
		return -EACCES;
	}
	store_u16be(payload, 13);
	store_u16be(payload + 2, (u16)path_length);
	store_u32be(payload + 4, (u32)task_pid_nr(current));
	store_u32be(payload + 8, (u32)task_tgid_nr(current));
	memset(payload + 12, 0, 8);
	memcpy(payload + 20, path, path_length);
	result = spp_diag_trace_core_append(
		SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED, 0, 0, 0, 1,
		SPP_DIAG_TRACE_PHASE_PRE_RELEASE, payload, 20 + path_length);
	if (result) {
		panic("spp diag trace denial append");
		return -EACCES;
	}
	spp_diag_trace_bootstrap_note_frame(
		SPP_DIAG_TRACE_EVENT_PRE_RELEASE_EXEC_DENIED, 0, 0, 0, 1,
		SPP_DIAG_TRACE_PHASE_PRE_RELEASE, payload, 20 + path_length);
	return -EACCES;
}

#if IS_ENABLED(CONFIG_KUNIT)
void spp_diag_trace_bootstrap_gate_test_reset(void)
{
	atomic_long_set(&denial_count, 0);
	WRITE_ONCE(released, false);
}
#endif
