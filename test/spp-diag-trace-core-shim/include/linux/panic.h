/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_PANIC_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_PANIC_H

#include <setjmp.h>

void host_panic_arm(jmp_buf *target);
void host_panic_disarm(void);
const char *host_panic_message(void);
void host_panic(const char *message);

#define panic(message) host_panic(message)

#endif
