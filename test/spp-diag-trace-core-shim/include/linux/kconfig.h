/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_KCONFIG_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_KCONFIG_H

#define __ARG_PLACEHOLDER_1 0,
#define __take_second_arg(__ignored, val, ...) val
#define ___is_defined(val) ____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk) __take_second_arg(arg1_or_junk 1, 0)
#define __is_defined(x) ___is_defined(x)
#define IS_ENABLED(option) __is_defined(option)

#endif
