/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_RUNTIME_REDIRECT_H
#define SPP_DIAG_TRACE_CORE_RUNTIME_REDIRECT_H

#include <linux/kconfig.h>

#if IS_ENABLED(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME)
#define spp_diag_trace_core_append spp_diag_trace_core_append_gated
#endif

#endif
