/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_BINFMT_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_BINFMT_H

struct linux_binprm {
	const char *filename;
};

#endif
