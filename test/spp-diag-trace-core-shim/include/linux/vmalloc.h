/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_VMALLOC_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_VMALLOC_H

struct host_vmalloc_record {
	unsigned long last_alloc_size;
	unsigned alloc_count;
	unsigned free_count;
	int last_alloc_irqs_disabled;
	int last_alloc_lock_held;
	int last_free_irqs_disabled;
	int last_free_lock_held;
};

void *vmalloc(unsigned long size);
void vfree(const void *addr);
void host_vmalloc_reset_instrumentation(void);
struct host_vmalloc_record host_vmalloc_record(void);
void host_vmalloc_reap(void);

#endif
