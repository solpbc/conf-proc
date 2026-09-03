/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_INIT_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_INIT_H

#define __init
#define core_initcall(fn) static int (*__host_initcall_##fn)(void) __attribute__((unused)) = fn
#define fs_initcall(fn) static int (*__host_initcall_##fn)(void) __attribute__((unused)) = fn

extern char *saved_command_line;
extern unsigned int saved_command_line_len;
void host_saved_command_line_set(const char *value);

#endif
