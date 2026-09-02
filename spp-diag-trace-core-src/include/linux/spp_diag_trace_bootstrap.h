/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _LINUX_SPP_DIAG_TRACE_BOOTSTRAP_H
#define _LINUX_SPP_DIAG_TRACE_BOOTSTRAP_H

#include <linux/kconfig.h>
#include <linux/init.h>
#include <linux/types.h>

struct linux_binprm;

#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP)
void __init spp_diag_trace_bootstrap_init(void);
int spp_diag_trace_bootstrap_bprm_check(struct linux_binprm *bprm);
void __init spp_diag_trace_bootstrap_ima_ready(void);
void __init spp_diag_trace_bootstrap_release(void);

long spp_diag_trace_bootstrap_denial_count(void);
void spp_diag_trace_bootstrap_publish_release(void);
void spp_diag_trace_bootstrap_note_frame(u16 event_type, u16 flags,
					u64 task_ordinal, u64 parent_task_ordinal,
					u64 operation_ordinal, u16 phase,
					const void *payload, size_t payload_length);
void spp_diag_trace_bootstrap_ima_record(u16 kind, u64 denied_count,
					u8 out[256]);
#if IS_ENABLED(CONFIG_KUNIT)
void spp_diag_trace_bootstrap_test_reset(void);
void spp_diag_trace_bootstrap_gate_test_reset(void);
#endif
#else
static inline void spp_diag_trace_bootstrap_init(void) {}
static inline int spp_diag_trace_bootstrap_bprm_check(struct linux_binprm *bprm)
{
	(void)bprm;
	return 0;
}
static inline void spp_diag_trace_bootstrap_ima_ready(void) {}
static inline void spp_diag_trace_bootstrap_release(void) {}
#endif

#endif
