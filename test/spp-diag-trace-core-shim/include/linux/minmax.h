/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_MINMAX_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_MINMAX_H

#define min_t(type, a, b) ((type)((a) < (b) ? (a) : (b)))

#endif
