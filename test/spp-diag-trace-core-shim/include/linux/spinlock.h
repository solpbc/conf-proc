/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_SPINLOCK_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_SPINLOCK_H

#include <pthread.h>
#include <sched.h>

typedef struct {
	pthread_mutex_t mutex;
	int inited;
} spinlock_t;

static inline void spin_lock_init(spinlock_t *lock)
{
	pthread_mutex_init(&lock->mutex, NULL);
	lock->inited = 1;
}

#ifdef SPP_DIAG_TRACE_CORE_NOP_LOCK

#define spin_lock_irqsave(lock, flags) \
	do {                           \
		(flags) = 0;           \
		(void)(lock);          \
		sched_yield();         \
	} while (0)

#define spin_unlock_irqrestore(lock, flags) \
	do {                                \
		(void)(lock);               \
		(void)(flags);             \
		sched_yield();             \
	} while (0)

#else

static inline void spp_diag_trace_core_lock(spinlock_t *lock, unsigned long *flags)
{
	*flags = 0;
	if (!lock->inited)
		spin_lock_init(lock);
	pthread_mutex_lock(&lock->mutex);
}

static inline void spp_diag_trace_core_unlock(spinlock_t *lock, unsigned long flags)
{
	(void)flags;
	pthread_mutex_unlock(&lock->mutex);
}

#define spin_lock_irqsave(lock, flags) spp_diag_trace_core_lock((lock), &(flags))
#define spin_unlock_irqrestore(lock, flags) \
	spp_diag_trace_core_unlock((lock), (flags))

#endif

#endif
