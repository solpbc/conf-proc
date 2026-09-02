/* SPDX-License-Identifier: GPL-2.0-only */

#include "core.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define THREADS 2
#define APPENDS_PER_THREAD 3

struct hold {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int entered;
	int release;
	int passing;
};

struct worker {
	struct spp_diag_trace_core *core;
	int ok_count;
};

#ifndef SPP_DIAG_TRACE_CORE_NOP_LOCK
static void barrier_wait(void *arg)
{
	struct hold *hold = arg;

	pthread_mutex_lock(&hold->mutex);
	hold->entered++;
	pthread_cond_broadcast(&hold->cond);
	while (!hold->release)
		pthread_cond_wait(&hold->cond, &hold->mutex);
	pthread_mutex_unlock(&hold->mutex);
}
#endif

#ifndef SPP_DIAG_TRACE_CORE_NOP_LOCK
static void *append_worker(void *arg)
{
	struct worker *worker = arg;
	int i;

	for (i = 0; i < APPENDS_PER_THREAD; i++) {
		int rc = spp_diag_trace_core_append(
			worker->core, SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0, 0, 0,
			SPP_DIAG_TRACE_PHASE_SEALED, NULL, 0);
		if (rc == WIRE_OK)
			worker->ok_count++;
	}
	return NULL;
}
#endif

static int init_core(struct spp_diag_trace_core *core)
{
	u8 id[32];

	memset(core, 0, sizeof(*core));
	memset(id, 0x3c, sizeof(id));
	return spp_diag_trace_core_init(core, id, id, id, id);
}

#ifndef SPP_DIAG_TRACE_CORE_NOP_LOCK
static int test_contiguous_sequences(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	struct worker workers[THREADS];
	pthread_t threads[THREADS];
	int i;
	int ok_sum = 0;

	if (init_core(&core) != WIRE_OK)
		return 1;
	for (i = 0; i < THREADS; i++) {
		workers[i].core = &core;
		workers[i].ok_count = 0;
		if (pthread_create(&threads[i], NULL, append_worker, &workers[i]) !=
		    0)
			return 1;
	}
	for (i = 0; i < THREADS; i++) {
		pthread_join(threads[i], NULL);
		ok_sum += workers[i].ok_count;
	}
	if (spp_diag_trace_core_snapshot(&core, &snap) != WIRE_OK)
		return 1;
	if (snap.failed)
		return 1;
	if (snap.frame_count != 1ull + (unsigned)ok_sum)
		return 1;
	if (snap.sequence != snap.frame_count)
		return 1;
	if (ok_sum != THREADS * APPENDS_PER_THREAD)
		return 1;
	return 0;
}
#endif

#ifndef SPP_DIAG_TRACE_CORE_NOP_LOCK
struct mark_args {
	struct spp_diag_trace_core *core;
	int rc;
};

static void *mark_worker(void *arg)
{
	struct mark_args *args = arg;

	args->rc = spp_diag_trace_core_mark_failure(args->core, WIRE_CAP);
	return NULL;
}
#endif

static void *append_once_worker(void *arg)
{
	struct worker *worker = arg;

	if (spp_diag_trace_core_append(worker->core, SPP_DIAG_TRACE_EVENT_TERMINAL,
				       0, 0, 0, 0, SPP_DIAG_TRACE_PHASE_SEALED,
				       NULL, 0) == WIRE_OK)
		worker->ok_count = 1;
	else
		worker->ok_count = 0;
	return NULL;
}

#ifndef SPP_DIAG_TRACE_CORE_NOP_LOCK
static int test_append_vs_mark(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	struct hold hold;
	struct mark_args marker_args;
	struct worker appender;
	pthread_t marker_thread;
	pthread_t append_thread;

	if (init_core(&core) != WIRE_OK)
		return 1;
	memset(&hold, 0, sizeof(hold));
	pthread_mutex_init(&hold.mutex, NULL);
	pthread_cond_init(&hold.cond, NULL);
	spp_diag_trace_core_set_pre_lock_barrier(&core, barrier_wait, &hold);

	marker_args.core = &core;
	marker_args.rc = 0;
	if (pthread_create(&marker_thread, NULL, mark_worker, &marker_args) != 0)
		return 1;
	pthread_mutex_lock(&hold.mutex);
	while (hold.entered < 1)
		pthread_cond_wait(&hold.cond, &hold.mutex);
	pthread_mutex_unlock(&hold.mutex);

	appender.core = &core;
	appender.ok_count = -1;
	if (pthread_create(&append_thread, NULL, append_once_worker, &appender) !=
	    0)
		return 1;
	usleep(20000);

	pthread_mutex_lock(&hold.mutex);
	hold.release = 1;
	pthread_cond_broadcast(&hold.cond);
	pthread_mutex_unlock(&hold.mutex);
	pthread_join(marker_thread, NULL);
	pthread_join(append_thread, NULL);

	if (spp_diag_trace_core_snapshot(&core, &snap) != WIRE_OK)
		return 1;
	if (!snap.failed || snap.reason != WIRE_CAP)
		return 1;
	if (marker_args.rc != WIRE_CAP)
		return 1;
	if (appender.ok_count != 0)
		return 1;
	if (snap.frame_count != 1)
		return 1;
	return 0;
}
#endif

#ifdef SPP_DIAG_TRACE_CORE_NOP_LOCK
static void overlap_barrier(void *arg)
{
	struct hold *hold = arg;

	pthread_mutex_lock(&hold->mutex);
	hold->entered++;
	pthread_cond_broadcast(&hold->cond);
	while (!hold->release)
		pthread_cond_wait(&hold->cond, &hold->mutex);
	hold->passing++;
	pthread_cond_broadcast(&hold->cond);
	while (hold->passing < 2)
		pthread_cond_wait(&hold->cond, &hold->mutex);
	pthread_mutex_unlock(&hold->mutex);
	usleep(2000);
}

static int test_negative_unlocked_overlap(void)
{
	struct spp_diag_trace_core core;
	struct spp_diag_trace_core_snapshot snap;
	struct hold hold;
	pthread_t first;
	pthread_t second;
	struct worker worker_a;
	struct worker worker_b;
	unsigned published;
	int trial;

	for (trial = 0; trial < 50; trial++) {
	if (init_core(&core) != WIRE_OK)
		return 1;
	memset(&hold, 0, sizeof(hold));
	pthread_mutex_init(&hold.mutex, NULL);
	pthread_cond_init(&hold.cond, NULL);
	spp_diag_trace_core_set_pre_lock_barrier(&core, overlap_barrier, &hold);

	worker_a.core = &core;
	worker_a.ok_count = 0;
	worker_b.core = &core;
	worker_b.ok_count = 0;
	if (pthread_create(&first, NULL, append_once_worker, &worker_a) != 0)
		return 1;
	if (pthread_create(&second, NULL, append_once_worker, &worker_b) != 0)
		return 1;

	pthread_mutex_lock(&hold.mutex);
	while (hold.entered < 2)
		pthread_cond_wait(&hold.cond, &hold.mutex);
	hold.release = 1;
	pthread_cond_broadcast(&hold.cond);
	pthread_mutex_unlock(&hold.mutex);
	pthread_join(first, NULL);
	pthread_join(second, NULL);

	if (spp_diag_trace_core_snapshot(&core, &snap) != WIRE_OK)
		return 1;
	published = (unsigned)worker_a.ok_count + (unsigned)worker_b.ok_count;
	/*
	 * Overlapping unlocked publishes reuse sequence 0+1 or drop a
	 * counter update. A fully serialized run has two OKs, frame_count
	 * 3, and last-frame sequence 2.
	 */
	if (published == 2) {
		u64 last_seq = ((u64)snap.last_frame[8] << 56) |
			       ((u64)snap.last_frame[9] << 48) |
			       ((u64)snap.last_frame[10] << 40) |
			       ((u64)snap.last_frame[11] << 32) |
			       ((u64)snap.last_frame[12] << 24) |
			       ((u64)snap.last_frame[13] << 16) |
			       ((u64)snap.last_frame[14] << 8) |
			       (u64)snap.last_frame[15];
		if (snap.frame_count != 3 || last_seq == 1)
			return 0;
	}
	}
	return 1;
}
#endif

int main(void)
{
	if (!IS_ENABLED(CONFIG_KUNIT)) {
		fputs("race selftest requires CONFIG_KUNIT=1\n", stderr);
		return 2;
	}
#ifdef SPP_DIAG_TRACE_CORE_NOP_LOCK
	if (test_negative_unlocked_overlap() != 0) {
		fputs("FAIL negative unlocked race did not observably fail\n",
		      stderr);
		return 1;
	}
	puts("ok   spp-diag-trace-core-race-selftest negative (unlocked overlap observed)");
	return 0;
#else
	if (test_contiguous_sequences() != 0) {
		fputs("FAIL contiguous sequences\n", stderr);
		return 1;
	}
	if (test_append_vs_mark() != 0) {
		fputs("FAIL append-vs-mark\n", stderr);
		return 1;
	}
	puts("ok   spp-diag-trace-core-race-selftest");
	return 0;
#endif
}
