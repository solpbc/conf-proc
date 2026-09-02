/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Synthetic call-graph twins. Each compile defines the three production
 * entry names and hides one forbidden primitive at least three helper
 * calls deep. Never linked with core.c or into any real binary.
 */

#include <stddef.h>

#if defined(HIDE_VMALLOC)
void *vmalloc(unsigned long size);
static void *depth3(void)
{
	return vmalloc(8);
}
#elif defined(HIDE_SLEEP)
void might_sleep(void);
static void depth3(void)
{
	might_sleep();
}
#elif defined(HIDE_MUTEX)
void mutex_lock(void);
static void depth3(void)
{
	mutex_lock();
}
#elif defined(HIDE_ALT_LOCK)
void raw_spin_lock(void);
static void depth3(void)
{
	raw_spin_lock();
}
#else
#error "define HIDE_VMALLOC, HIDE_SLEEP, HIDE_MUTEX, or HIDE_ALT_LOCK"
#endif

static void depth2(void)
{
	(void)depth3();
}

static void depth1(void)
{
	depth2();
}

int spp_diag_trace_core_is_green(void)
{
	depth1();
	return 0;
}

int spp_diag_trace_core_append(unsigned event, unsigned flags,
			       unsigned long long task, unsigned long long parent,
			       unsigned long long operation, unsigned phase,
			       const void *payload, unsigned long payload_length)
{
	(void)event;
	(void)flags;
	(void)task;
	(void)parent;
	(void)operation;
	(void)phase;
	(void)payload;
	(void)payload_length;
	depth1();
	return 0;
}

int spp_diag_trace_core_mark_failure(int reason)
{
	(void)reason;
	depth1();
	return 0;
}
