/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_IRQFLAGS_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_IRQFLAGS_H

static _Thread_local int spp_diag_trace_core_irqs_disabled;

#define local_irq_save(flags)                          \
	do {                                           \
		(flags) = spp_diag_trace_core_irqs_disabled; \
		spp_diag_trace_core_irqs_disabled = 1; \
	} while (0)

#define local_irq_restore(flags)                       \
	do {                                           \
		spp_diag_trace_core_irqs_disabled = (int)(flags); \
	} while (0)

static inline int irqs_disabled(void)
{
	return spp_diag_trace_core_irqs_disabled != 0;
}

#endif
