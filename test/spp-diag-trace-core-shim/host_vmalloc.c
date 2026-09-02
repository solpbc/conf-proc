/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Host stand-in for vmalloc/vfree, plus the lock-trace ring shared by the
 * spinlock shim (one TU so attempt/enter/exit are visible to tests).
 */

#include <linux/irqflags.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#include <stdlib.h>

#define LOCKTRACE_CAP 256

static pthread_mutex_t locktrace_mu = PTHREAD_MUTEX_INITIALIZER;
static struct spp_diag_trace_core_lock_event locktrace_ring[LOCKTRACE_CAP];
static size_t locktrace_len;
static unsigned locktrace_seq;
static int lock_held;

static pthread_mutex_t vmalloc_mu = PTHREAD_MUTEX_INITIALIZER;
static struct host_vmalloc_record vmalloc_rec;

#define VMALLOC_LIVE_CAP 16
static void *vmalloc_live[VMALLOC_LIVE_CAP];
static int vmalloc_live_n;

static pthread_mutex_t cshold_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cshold_cv = PTHREAD_COND_INITIALIZER;
static int cshold_arm;
static int cshold_entered;
static int cshold_release;

void spp_diag_trace_core_locktrace_reset(void)
{
	pthread_mutex_lock(&locktrace_mu);
	locktrace_len = 0;
	locktrace_seq = 0;
	pthread_mutex_unlock(&locktrace_mu);
}

size_t spp_diag_trace_core_locktrace_copy(
	struct spp_diag_trace_core_lock_event *out, size_t cap)
{
	size_t n;
	size_t i;

	pthread_mutex_lock(&locktrace_mu);
	n = locktrace_len;
	if (n > cap)
		n = cap;
	for (i = 0; i < n; i++)
		out[i] = locktrace_ring[i];
	pthread_mutex_unlock(&locktrace_mu);
	return n;
}

int spp_diag_trace_core_lock_is_held(void)
{
	int held;

	pthread_mutex_lock(&locktrace_mu);
	held = lock_held;
	pthread_mutex_unlock(&locktrace_mu);
	return held;
}

void spp_diag_trace_core_lock_held_set(int held)
{
	pthread_mutex_lock(&locktrace_mu);
	lock_held = held ? 1 : 0;
	pthread_mutex_unlock(&locktrace_mu);
}

static void locktrace_record(int kind)
{
	pthread_mutex_lock(&locktrace_mu);
	if (locktrace_len < LOCKTRACE_CAP) {
		locktrace_ring[locktrace_len].seq = ++locktrace_seq;
		locktrace_ring[locktrace_len].kind = kind;
		locktrace_ring[locktrace_len].tid = pthread_self();
		locktrace_len++;
	} else {
		locktrace_seq++;
	}
	pthread_mutex_unlock(&locktrace_mu);
}

void spp_diag_trace_core_locktrace_record_attempt(void)
{
	locktrace_record(SPP_DIAG_TRACE_CORE_LOCKTRACE_ATTEMPT);
}

void spp_diag_trace_core_locktrace_record_enter(void)
{
	locktrace_record(SPP_DIAG_TRACE_CORE_LOCKTRACE_ENTER);
}

void spp_diag_trace_core_locktrace_record_exit(void)
{
	locktrace_record(SPP_DIAG_TRACE_CORE_LOCKTRACE_EXIT);
}

void spp_diag_trace_core_cs_hold_arm(int waiters)
{
	pthread_mutex_lock(&cshold_mu);
	cshold_arm = waiters;
	cshold_entered = 0;
	cshold_release = 0;
	pthread_mutex_unlock(&cshold_mu);
}

void spp_diag_trace_core_cs_hold_wait_entered(int n)
{
	pthread_mutex_lock(&cshold_mu);
	while (cshold_entered < n)
		pthread_cond_wait(&cshold_cv, &cshold_mu);
	pthread_mutex_unlock(&cshold_mu);
}

void spp_diag_trace_core_cs_hold_release(void)
{
	pthread_mutex_lock(&cshold_mu);
	cshold_release = 1;
	cshold_arm = 0;
	pthread_cond_broadcast(&cshold_cv);
	pthread_mutex_unlock(&cshold_mu);
}

void spp_diag_trace_core_lock_maybe_cs_hold(void)
{
	pthread_mutex_lock(&cshold_mu);
	if (cshold_arm > 0) {
		cshold_entered++;
		pthread_cond_broadcast(&cshold_cv);
		while (!cshold_release)
			pthread_cond_wait(&cshold_cv, &cshold_mu);
	}
	pthread_mutex_unlock(&cshold_mu);
}

void host_vmalloc_reset_instrumentation(void)
{
	pthread_mutex_lock(&vmalloc_mu);
	vmalloc_rec.last_alloc_size = 0;
	vmalloc_rec.alloc_count = 0;
	vmalloc_rec.free_count = 0;
	vmalloc_rec.last_alloc_irqs_disabled = 0;
	vmalloc_rec.last_alloc_lock_held = 0;
	vmalloc_rec.last_free_irqs_disabled = 0;
	vmalloc_rec.last_free_lock_held = 0;
	pthread_mutex_unlock(&vmalloc_mu);
}

static void live_add(void *ptr)
{
	if (ptr == NULL || vmalloc_live_n >= VMALLOC_LIVE_CAP)
		return;
	vmalloc_live[vmalloc_live_n++] = ptr;
}

static void live_del(const void *ptr)
{
	int i;

	for (i = 0; i < vmalloc_live_n; i++) {
		if (vmalloc_live[i] == ptr) {
			vmalloc_live[i] = vmalloc_live[vmalloc_live_n - 1];
			vmalloc_live_n--;
			return;
		}
	}
}

void host_vmalloc_reap(void)
{
	int i;

	pthread_mutex_lock(&vmalloc_mu);
	for (i = 0; i < vmalloc_live_n; i++) {
		free(vmalloc_live[i]);
		vmalloc_rec.free_count++;
		vmalloc_live[i] = NULL;
	}
	vmalloc_live_n = 0;
	pthread_mutex_unlock(&vmalloc_mu);
}

struct host_vmalloc_record host_vmalloc_record(void)
{
	struct host_vmalloc_record copy;

	pthread_mutex_lock(&vmalloc_mu);
	copy = vmalloc_rec;
	pthread_mutex_unlock(&vmalloc_mu);
	return copy;
}

void *vmalloc(unsigned long size)
{
	void *ptr;
	int irqs;
	int held;

	irqs = irqs_disabled();
	held = spp_diag_trace_core_lock_is_held();
	ptr = malloc(size);
	pthread_mutex_lock(&vmalloc_mu);
	vmalloc_rec.last_alloc_size = size;
	vmalloc_rec.alloc_count++;
	vmalloc_rec.last_alloc_irqs_disabled = irqs;
	vmalloc_rec.last_alloc_lock_held = held;
	live_add(ptr);
	pthread_mutex_unlock(&vmalloc_mu);
	return ptr;
}

void vfree(const void *addr)
{
	int irqs;
	int held;

	if (addr == NULL)
		return;
	irqs = irqs_disabled();
	held = spp_diag_trace_core_lock_is_held();
	pthread_mutex_lock(&vmalloc_mu);
	live_del(addr);
	vmalloc_rec.free_count++;
	vmalloc_rec.last_free_irqs_disabled = irqs;
	vmalloc_rec.last_free_lock_held = held;
	pthread_mutex_unlock(&vmalloc_mu);
	free((void *)addr);
}
