/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_SPINLOCK_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_SPINLOCK_H

#include <pthread.h>
#include <sched.h>
#include <stddef.h>

typedef struct {
	pthread_mutex_t mutex;
	int inited;
} spinlock_t;

#define DEFINE_SPINLOCK(name) \
	spinlock_t name = { .mutex = PTHREAD_MUTEX_INITIALIZER, .inited = 1 }

enum spp_diag_trace_core_locktrace_kind {
	SPP_DIAG_TRACE_CORE_LOCKTRACE_ATTEMPT = 1,
	SPP_DIAG_TRACE_CORE_LOCKTRACE_ENTER = 2,
	SPP_DIAG_TRACE_CORE_LOCKTRACE_EXIT = 3
};

struct spp_diag_trace_core_lock_event {
	unsigned seq;
	int kind;
	pthread_t tid;
};

void spp_diag_trace_core_locktrace_reset(void);
size_t spp_diag_trace_core_locktrace_copy(
	struct spp_diag_trace_core_lock_event *out, size_t cap);
int spp_diag_trace_core_lock_is_held(void);
void spp_diag_trace_core_locktrace_record_attempt(void);
void spp_diag_trace_core_locktrace_record_enter(void);
void spp_diag_trace_core_locktrace_record_exit(void);
void spp_diag_trace_core_lock_held_set(int held);
void spp_diag_trace_core_cs_hold_arm(int waiters);
void spp_diag_trace_core_cs_hold_wait_entered(int n);
void spp_diag_trace_core_cs_hold_release(void);
void spp_diag_trace_core_lock_maybe_cs_hold(void);

static inline void spin_lock_init(spinlock_t *lock)
{
	pthread_mutex_init(&lock->mutex, NULL);
	lock->inited = 1;
}

#ifdef SPP_DIAG_TRACE_CORE_NOP_LOCK

#define spin_lock_irqsave(lock, flags)              \
	do {                                        \
		(flags) = 0;                        \
		(void)(lock);                       \
		spp_diag_trace_core_locktrace_record_attempt(); \
		spp_diag_trace_core_locktrace_record_enter();   \
		spp_diag_trace_core_lock_maybe_cs_hold();       \
		sched_yield();                      \
	} while (0)

#define spin_unlock_irqrestore(lock, flags)         \
	do {                                        \
		(void)(lock);                       \
		(void)(flags);                      \
		spp_diag_trace_core_locktrace_record_exit();    \
		sched_yield();                      \
	} while (0)

#else

static inline void spp_diag_trace_core_shim_lock(spinlock_t *lock,
						 unsigned long *flags)
{
	*flags = 0;
	if (!lock->inited)
		spin_lock_init(lock);
	spp_diag_trace_core_locktrace_record_attempt();
	pthread_mutex_lock(&lock->mutex);
	spp_diag_trace_core_lock_held_set(1);
	spp_diag_trace_core_locktrace_record_enter();
	spp_diag_trace_core_lock_maybe_cs_hold();
}

static inline void spp_diag_trace_core_shim_unlock(spinlock_t *lock,
						   unsigned long flags)
{
	(void)flags;
	spp_diag_trace_core_lock_held_set(0);
	pthread_mutex_unlock(&lock->mutex);
	spp_diag_trace_core_locktrace_record_exit();
}

#define spin_lock_irqsave(lock, flags) \
	spp_diag_trace_core_shim_lock((lock), &(flags))
#define spin_unlock_irqrestore(lock, flags) \
	spp_diag_trace_core_shim_unlock((lock), (flags))

#endif

#endif
