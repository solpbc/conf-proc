/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_ATOMIC_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_ATOMIC_H

#include <stdatomic.h>

typedef struct {
	_Atomic long counter;
} atomic_long_t;

#define ATOMIC_LONG_INIT(value) { .counter = (value) }

static inline long atomic_long_inc_return(atomic_long_t *value)
{
	return atomic_fetch_add_explicit(&value->counter, 1, memory_order_relaxed) + 1;
}

static inline long atomic_long_read(const atomic_long_t *value)
{
	return atomic_load_explicit(&value->counter, memory_order_relaxed);
}

static inline void atomic_long_set(atomic_long_t *value, long next)
{
	atomic_store_explicit(&value->counter, next, memory_order_relaxed);
}

#endif
