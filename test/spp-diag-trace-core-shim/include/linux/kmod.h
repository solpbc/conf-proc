/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_KMOD_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_KMOD_H

#include <linux/binfmts.h>

#define UMH_NO_WAIT 0x00
#define UMH_WAIT_EXEC 0x01

struct host_kmod_call {
	const char *path;
	char *const *argv;
	char *const *envp;
	int wait;
	unsigned int calls;
};

int call_usermodehelper(const char *path, char **argv, char **envp, int wait);
void host_kmod_reset(void);
void host_kmod_set_result(int result, int forced);
void host_kmod_set_gate(int (*gate)(struct linux_binprm *));
const struct host_kmod_call *host_kmod_last_call(void);

#endif
