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
#if IS_ENABLED(CONFIG_KUNIT)
int spp_diag_trace_bootstrap_test_parse(const char *command_line,
					size_t command_line_len,
					u8 challenge[32], u8 run[32],
					u8 control_plan[32]);
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
