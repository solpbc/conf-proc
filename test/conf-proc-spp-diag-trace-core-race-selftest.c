/* SPDX-License-Identifier: GPL-2.0-only */

#include "core.h"

#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#define SNAP_BUF_CAP (sizeof(struct spp_diag_trace_core_snapshot) + 4096)
#define LOCKTRACE_CAP 64
#define NEG_TRIALS 50
#define APPENDS_PER_THREAD 3

struct order_gate {
	pthread_mutex_t mu;
	pthread_cond_t cv;
	int expected;
	int arrived;
	int released[2];
};

struct race_worker {
	int id;
	int rc;
	void (*op)(struct race_worker *);
	const u8 *ch;
	const u8 *run;
	const u8 *ctl;
	const u8 *cmd;
	int mark_reason;
	unsigned char *snap_buf;
	size_t snap_need;
};

static __thread int tls_id;
static struct order_gate g_gate;
static unsigned char snap_store[2][SNAP_BUF_CAP];

static u32 load_u32be(const u8 *p)
{
	return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) |
	       (u32)p[3];
}

static u64 load_u64be(const u8 *p)
{
	return ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) |
	       ((u64)p[3] << 32) | ((u64)p[4] << 24) | ((u64)p[5] << 16) |
	       ((u64)p[6] << 8) | (u64)p[7];
}

static void fill_ident(u8 *ch, u8 *run, u8 *ctl, u8 *cmd, u8 seed)
{
	memset(ch, seed, 32);
	memset(run, (u8)(seed + 1), 32);
	memset(ctl, (u8)(seed + 2), 32);
	memset(cmd, (u8)(seed + 3), 32);
}

static int take_snap(struct spp_diag_trace_core_snapshot *snap)
{
	unsigned char buf[SNAP_BUF_CAP];
	size_t need = 0;
	int rc;

	rc = spp_diag_trace_core_snapshot(buf, sizeof(buf), &need);
	if (rc != WIRE_OK)
		return rc;
	if (need < sizeof(*snap))
		return WIRE_LENGTH;
	memcpy(snap, buf, sizeof(*snap));
	return WIRE_OK;
}

static int snapshot_coherent(const unsigned char *blob, size_t need)
{
	struct spp_diag_trace_core_snapshot meta;
	const u8 *stream;
	size_t off;
	u64 frames = 0;
	u32 flen;
	const u8 *last = NULL;
	u32 last_len = 0;

	if (need < sizeof(meta))
		return 1;
	memcpy(&meta, blob, sizeof(meta));
	if (need != sizeof(meta) + (size_t)meta.stream_len)
		return 1;
	if (meta.stream_len != meta.stream_byte_count)
		return 1;
	if (meta.sequence != meta.frame_count)
		return 1;
	stream = blob + sizeof(meta);
	if (meta.stream_len == 0)
		return meta.frame_count == 0 ? 0 : 1;
	if (meta.stream_len < 4)
		return 1;
	if (load_u32be(stream) != SPP_DIAG_TRACE_HEADER_SIZE)
		return 1;
	off = 4 + SPP_DIAG_TRACE_HEADER_SIZE;
	while (off < (size_t)meta.stream_len) {
		if ((size_t)meta.stream_len - off < 4)
			return 1;
		flen = load_u32be(stream + off);
		if (flen < SPP_DIAG_TRACE_FRAME_HEADER_SIZE ||
		    off + 4 + flen > (size_t)meta.stream_len)
			return 1;
		last = stream + off + 4;
		last_len = flen;
		frames++;
		off += 4 + flen;
	}
	if (off != (size_t)meta.stream_len)
		return 1;
	if (frames != meta.frame_count)
		return 1;
	if (last == NULL || last_len != meta.last_frame_len)
		return 1;
	if (memcmp(last, meta.last_frame, last_len) != 0)
		return 1;
	return 0;
}

static int append_terminal(void)
{
	return spp_diag_trace_core_append(SPP_DIAG_TRACE_EVENT_TERMINAL, 0, 0, 0,
					  0, SPP_DIAG_TRACE_PHASE_SEALED, NULL,
					  0);
}

static void op_init(struct race_worker *w)
{
	w->rc = spp_diag_trace_core_init(w->ch, w->run, w->ctl, w->cmd);
}

static void op_mark(struct race_worker *w)
{
	w->rc = spp_diag_trace_core_mark_failure(w->mark_reason);
}

static void op_append_ok(struct race_worker *w)
{
	w->rc = append_terminal();
}

static void op_append_bad(struct race_worker *w)
{
	w->rc = spp_diag_trace_core_append(0, 0, 0, 0, 0, 0, NULL, 0);
}

static void op_query(struct race_worker *w)
{
	w->rc = spp_diag_trace_core_is_green();
}

static void op_snapshot(struct race_worker *w)
{
	w->rc = spp_diag_trace_core_snapshot(w->snap_buf, SNAP_BUF_CAP,
					     &w->snap_need);
}

static void order_gate_init(struct order_gate *g, int n)
{
	memset(g, 0, sizeof(*g));
	pthread_mutex_init(&g->mu, NULL);
	pthread_cond_init(&g->cv, NULL);
	g->expected = n;
}

static void order_gate_arrive(struct order_gate *g, int id)
{
	pthread_mutex_lock(&g->mu);
	g->arrived++;
	pthread_cond_broadcast(&g->cv);
	while (g->arrived < g->expected)
		pthread_cond_wait(&g->cv, &g->mu);
	while (!g->released[id])
		pthread_cond_wait(&g->cv, &g->mu);
	pthread_mutex_unlock(&g->mu);
}

static int order_gate_wait_arrived(struct order_gate *g)
{
	pthread_mutex_lock(&g->mu);
	while (g->arrived < g->expected)
		pthread_cond_wait(&g->cv, &g->mu);
	if (g->arrived != g->expected) {
		pthread_mutex_unlock(&g->mu);
		return 1;
	}
	pthread_mutex_unlock(&g->mu);
	return 0;
}

static void order_gate_release(struct order_gate *g, int id)
{
	pthread_mutex_lock(&g->mu);
	g->released[id] = 1;
	pthread_cond_broadcast(&g->cv);
	pthread_mutex_unlock(&g->mu);
}

static void gate_barrier(void *arg)
{
	order_gate_arrive(arg, tls_id);
}

static void *worker_main(void *arg)
{
	struct race_worker *w = arg;

	tls_id = w->id;
	w->op(w);
	return NULL;
}

#ifndef SPP_DIAG_TRACE_CORE_NOP_LOCK
static int wait_attempt(pthread_t tid)
{
	struct spp_diag_trace_core_lock_event ev[LOCKTRACE_CAP];
	unsigned spins = 0;
	size_t n;
	size_t i;

	for (;;) {
		n = spp_diag_trace_core_locktrace_copy(ev, LOCKTRACE_CAP);
		for (i = 0; i < n; i++) {
			if (pthread_equal(ev[i].tid, tid) &&
			    ev[i].kind == SPP_DIAG_TRACE_CORE_LOCKTRACE_ATTEMPT)
				return 0;
		}
		if (++spins > 100000000u)
			return 1;
		sched_yield();
	}
}

static int locktrace_loser_during_winner(pthread_t winner, pthread_t loser)
{
	struct spp_diag_trace_core_lock_event ev[LOCKTRACE_CAP];
	size_t n;
	size_t i;
	unsigned enter = 0;
	unsigned exit_seq = 0;
	unsigned attempt = 0;

	n = spp_diag_trace_core_locktrace_copy(ev, LOCKTRACE_CAP);
	for (i = 0; i < n; i++) {
		if (pthread_equal(ev[i].tid, winner) &&
		    ev[i].kind == SPP_DIAG_TRACE_CORE_LOCKTRACE_ENTER &&
		    enter == 0)
			enter = ev[i].seq;
		if (pthread_equal(ev[i].tid, winner) &&
		    ev[i].kind == SPP_DIAG_TRACE_CORE_LOCKTRACE_EXIT &&
		    enter != 0 && exit_seq == 0)
			exit_seq = ev[i].seq;
		if (pthread_equal(ev[i].tid, loser) &&
		    ev[i].kind == SPP_DIAG_TRACE_CORE_LOCKTRACE_ATTEMPT &&
		    attempt == 0)
			attempt = ev[i].seq;
	}
	if (enter == 0 || exit_seq == 0 || attempt == 0)
		return 1;
	if (!(enter < attempt && attempt < exit_seq))
		return 1;
	return 0;
}
#endif

static int finish_race(struct race_worker *w, int winner)
{
	pthread_t th[2];
	int loser = 1 - winner;
	int i;

	order_gate_init(&g_gate, 2);
	spp_diag_trace_core_set_pre_lock_barrier(gate_barrier, &g_gate);
	for (i = 0; i < 2; i++) {
		w[i].id = i;
		if (pthread_create(&th[i], NULL, worker_main, &w[i]) != 0)
			return 2;
	}
	if (order_gate_wait_arrived(&g_gate) != 0)
		return 2;
	spp_diag_trace_core_locktrace_reset();
#ifdef SPP_DIAG_TRACE_CORE_NOP_LOCK
	spp_diag_trace_core_cs_hold_arm(2);
	order_gate_release(&g_gate, winner);
	order_gate_release(&g_gate, loser);
	spp_diag_trace_core_cs_hold_wait_entered(2);
	spp_diag_trace_core_cs_hold_release();
#else
	spp_diag_trace_core_cs_hold_arm(1);
	order_gate_release(&g_gate, winner);
	spp_diag_trace_core_cs_hold_wait_entered(1);
	order_gate_release(&g_gate, loser);
	if (wait_attempt(th[loser]) != 0)
		return 2;
	spp_diag_trace_core_cs_hold_release();
#endif
	pthread_join(th[0], NULL);
	pthread_join(th[1], NULL);
#ifndef SPP_DIAG_TRACE_CORE_NOP_LOCK
	if (locktrace_loser_during_winner(th[winner], th[loser]) != 0)
		return 2;
#endif
	return 0;
}

static void fresh(void)
{
	spp_diag_trace_core_reset();
	spp_diag_trace_core_cs_hold_release();
	host_vmalloc_reap();
	host_vmalloc_reset_instrumentation();
	spp_diag_trace_core_locktrace_reset();
}

static int init_with(const u8 *ch, const u8 *run, const u8 *ctl, const u8 *cmd)
{
	return spp_diag_trace_core_init(ch, run, ctl, cmd);
}

static int init_seed(u8 seed)
{
	u8 ch[32], run[32], ctl[32], cmd[32];

	fill_ident(ch, run, ctl, cmd, seed);
	return init_with(ch, run, ctl, cmd);
}

struct append_loop {
	int ok_count;
};

#ifndef SPP_DIAG_TRACE_CORE_NOP_LOCK
static void *append_loop_worker(void *arg)
{
	struct append_loop *w = arg;
	int i;

	for (i = 0; i < APPENDS_PER_THREAD; i++) {
		if (append_terminal() == WIRE_OK)
			w->ok_count++;
	}
	return NULL;
}

static int test_contiguous_sequences(void)
{
	struct spp_diag_trace_core_snapshot snap;
	struct append_loop workers[2];
	pthread_t threads[2];
	int i;
	int ok_sum = 0;

	fresh();
	if (init_seed(0x3c) != WIRE_OK)
		return 1;
	for (i = 0; i < 2; i++) {
		workers[i].ok_count = 0;
		if (pthread_create(&threads[i], NULL, append_loop_worker,
				   &workers[i]) != 0)
			return 1;
	}
	for (i = 0; i < 2; i++) {
		pthread_join(threads[i], NULL);
		ok_sum += workers[i].ok_count;
	}
	if (take_snap(&snap) != WIRE_OK)
		return 1;
	if (snap.failed)
		return 1;
	if (snap.frame_count != 1ull + (unsigned)ok_sum)
		return 1;
	if (snap.sequence != snap.frame_count)
		return 1;
	if (ok_sum != 2 * APPENDS_PER_THREAD)
		return 1;
	return 0;
}
#endif

static int race_concurrent_init(int winner)
{
	struct race_worker w[2];
	struct spp_diag_trace_core_snapshot snap;
	struct host_vmalloc_record rec;
	u8 a_ch[32], a_run[32], a_ctl[32], a_cmd[32];
	u8 b_ch[32], b_run[32], b_ctl[32], b_cmd[32];
	int run_rc;
	int ok0;
	int ok1;

	fill_ident(a_ch, a_run, a_ctl, a_cmd, 0x11);
	fill_ident(b_ch, b_run, b_ctl, b_cmd, 0x22);
	fresh();
	memset(w, 0, sizeof(w));
	w[0].op = op_init;
	w[0].ch = a_ch;
	w[0].run = a_run;
	w[0].ctl = a_ctl;
	w[0].cmd = a_cmd;
	w[1].op = op_init;
	w[1].ch = b_ch;
	w[1].run = b_run;
	w[1].ctl = b_ctl;
	w[1].cmd = b_cmd;
	run_rc = finish_race(w, winner);
	if (run_rc != 0)
		return 2;
	if (take_snap(&snap) != WIRE_OK)
		return 2;
	rec = host_vmalloc_record();
	ok0 = w[0].rc == WIRE_OK;
	ok1 = w[1].rc == WIRE_OK;
	if (ok0 == ok1)
		return 1;
	if (w[winner].rc != WIRE_OK)
		return 1;
	if (w[1 - winner].rc != WIRE_STATE)
		return 1;
	if (!snap.initialized || !snap.failed || snap.reason != WIRE_STATE)
		return 1;
	if (snap.stream_len == 0)
		return 1;
	if (memcmp(snap.header + 52, winner == 0 ? a_ch : b_ch, 32) != 0)
		return 1;
	if (memcmp(snap.header + 52, winner == 0 ? b_ch : a_ch, 32) == 0)
		return 1;
	if (rec.alloc_count != 2 || rec.free_count != 1)
		return 1;
	if (spp_diag_trace_core_is_green() != 0)
		return 1;
	return 0;
}

static int race_init_vs_mark(int init_first, int valid)
{
	struct race_worker w[2];
	struct spp_diag_trace_core_snapshot snap;
	struct host_vmalloc_record rec;
	u8 ch[32], run[32], ctl[32], cmd[32];
	int init_id;
	int mark_id;
	int want_mark;
	int run_rc;

	fill_ident(ch, run, ctl, cmd, 0x31);
	want_mark = valid ? WIRE_CAP : WIRE_VALUE;
	init_id = init_first ? 0 : 1;
	mark_id = 1 - init_id;
	fresh();
	memset(w, 0, sizeof(w));
	w[init_id].op = op_init;
	w[init_id].ch = ch;
	w[init_id].run = run;
	w[init_id].ctl = ctl;
	w[init_id].cmd = cmd;
	w[mark_id].op = op_mark;
	w[mark_id].mark_reason = valid ? WIRE_CAP : 0;
	run_rc = finish_race(w, init_first ? init_id : mark_id);
	if (run_rc != 0)
		return 2;
	if (take_snap(&snap) != WIRE_OK)
		return 2;
	rec = host_vmalloc_record();
	if (w[mark_id].rc != want_mark)
		return 1;
	if (init_first) {
		if (w[init_id].rc != WIRE_OK)
			return 1;
		if (!snap.initialized || !snap.failed ||
		    snap.reason != want_mark)
			return 1;
		if (snap.stream_len == 0)
			return 1;
		if (spp_diag_trace_core_is_green() != 0)
			return 1;
		if (rec.alloc_count != 1 || rec.free_count != 0)
			return 1;
	} else {
		if (w[init_id].rc != want_mark)
			return 1;
		if (snap.initialized || !snap.failed ||
		    snap.reason != want_mark)
			return 1;
		if (snap.stream_len != 0)
			return 1;
		if (spp_diag_trace_core_is_green() != 0)
			return 1;
		if (rec.alloc_count != 1 || rec.free_count != 1)
			return 1;
	}
	return 0;
}

static int race_append_vs_append(int winner)
{
	struct race_worker w[2];
	struct spp_diag_trace_core_snapshot snap;
	int run_rc;

	fresh();
	if (init_seed(0x41) != WIRE_OK)
		return 2;
	memset(w, 0, sizeof(w));
	w[0].op = op_append_ok;
	w[1].op = op_append_ok;
	run_rc = finish_race(w, winner);
	if (run_rc != 0)
		return 2;
	if (take_snap(&snap) != WIRE_OK)
		return 2;
	if (w[0].rc != WIRE_OK || w[1].rc != WIRE_OK)
		return 1;
	if (snap.failed)
		return 1;
	if (snap.frame_count != 3 || snap.sequence != 3)
		return 1;
	if (load_u64be(snap.last_frame + 8) != 2)
		return 1;
	return 0;
}

static int race_snapshot_vs_append(int snap_first)
{
	struct race_worker w[2];
	struct spp_diag_trace_core_snapshot live;
	struct spp_diag_trace_core_snapshot shot;
	int snap_id = snap_first ? 0 : 1;
	int append_id = 1 - snap_id;
	int run_rc;

	fresh();
	if (init_seed(0x42) != WIRE_OK)
		return 2;
	memset(w, 0, sizeof(w));
	w[snap_id].op = op_snapshot;
	w[snap_id].snap_buf = snap_store[snap_id];
	w[append_id].op = op_append_ok;
	run_rc = finish_race(w, snap_first ? snap_id : append_id);
	if (run_rc != 0)
		return 2;
	if (w[append_id].rc != WIRE_OK || w[snap_id].rc != WIRE_OK)
		return 1;
	if (snapshot_coherent(w[snap_id].snap_buf, w[snap_id].snap_need) != 0)
		return 1;
	memcpy(&shot, w[snap_id].snap_buf, sizeof(shot));
	if (take_snap(&live) != WIRE_OK)
		return 2;
	if (live.frame_count != 2 || live.failed)
		return 1;
	if (snap_first) {
		if (shot.frame_count != 1 || shot.stream_len != 244)
			return 1;
	} else if (shot.frame_count != 2) {
		return 1;
	}
	return 0;
}

static int race_append_vs_mark(int append_first)
{
	struct race_worker w[2];
	struct spp_diag_trace_core_snapshot snap;
	int append_id = append_first ? 0 : 1;
	int mark_id = 1 - append_id;
	int run_rc;

	fresh();
	if (init_seed(0x43) != WIRE_OK)
		return 2;
	memset(w, 0, sizeof(w));
	w[append_id].op = op_append_ok;
	w[mark_id].op = op_mark;
	w[mark_id].mark_reason = WIRE_CAP;
	run_rc = finish_race(w, append_first ? append_id : mark_id);
	if (run_rc != 0)
		return 2;
	if (take_snap(&snap) != WIRE_OK)
		return 2;
	if (w[mark_id].rc != WIRE_CAP)
		return 1;
	if (!snap.failed || snap.reason != WIRE_CAP)
		return 1;
	if (spp_diag_trace_core_is_green() != 0)
		return 1;
	if (append_first) {
		if (w[append_id].rc != WIRE_OK)
			return 1;
		if (snap.frame_count != 2)
			return 1;
	} else {
		if (w[append_id].rc != WIRE_CAP)
			return 1;
		if (snap.frame_count != 1)
			return 1;
	}
	return 0;
}

static int race_init_vs_query(int init_first)
{
	struct race_worker w[2];
	int init_id = init_first ? 0 : 1;
	int query_id = 1 - init_id;
	u8 ch[32], run[32], ctl[32], cmd[32];
	int run_rc;

	fill_ident(ch, run, ctl, cmd, 0x44);
	fresh();
	memset(w, 0, sizeof(w));
	w[init_id].op = op_init;
	w[init_id].ch = ch;
	w[init_id].run = run;
	w[init_id].ctl = ctl;
	w[init_id].cmd = cmd;
	w[query_id].op = op_query;
	run_rc = finish_race(w, init_first ? init_id : query_id);
	if (run_rc != 0)
		return 2;
	if (w[init_id].rc != WIRE_OK)
		return 1;
	if (spp_diag_trace_core_is_green() != 1)
		return 1;
	if (init_first) {
		if (w[query_id].rc != 1)
			return 1;
	} else if (w[query_id].rc != 0) {
		return 1;
	}
	return 0;
}

static int race_mark_vs_query(int mark_first)
{
	struct race_worker w[2];
	int mark_id = mark_first ? 0 : 1;
	int query_id = 1 - mark_id;
	int run_rc;

	fresh();
	if (init_seed(0x45) != WIRE_OK)
		return 2;
	if (spp_diag_trace_core_is_green() != 1)
		return 2;
	memset(w, 0, sizeof(w));
	w[mark_id].op = op_mark;
	w[mark_id].mark_reason = WIRE_CAP;
	w[query_id].op = op_query;
	run_rc = finish_race(w, mark_first ? mark_id : query_id);
	if (run_rc != 0)
		return 2;
	if (w[mark_id].rc != WIRE_CAP)
		return 1;
	if (spp_diag_trace_core_is_green() != 0)
		return 1;
	if (mark_first) {
		if (w[query_id].rc != 0)
			return 1;
	} else if (w[query_id].rc != 1) {
		return 1;
	}
	return 0;
}

static int race_failing_append_vs_query(int append_first)
{
	struct race_worker w[2];
	struct spp_diag_trace_core_snapshot snap;
	int append_id = append_first ? 0 : 1;
	int query_id = 1 - append_id;
	int run_rc;

	fresh();
	if (init_seed(0x46) != WIRE_OK)
		return 2;
	memset(w, 0, sizeof(w));
	w[append_id].op = op_append_bad;
	w[query_id].op = op_query;
	run_rc = finish_race(w, append_first ? append_id : query_id);
	if (run_rc != 0)
		return 2;
	if (take_snap(&snap) != WIRE_OK)
		return 2;
	if (w[append_id].rc != WIRE_EVENT)
		return 1;
	if (!snap.failed || snap.reason != WIRE_EVENT || snap.frame_count != 1)
		return 1;
	if (spp_diag_trace_core_is_green() != 0)
		return 1;
	if (append_first) {
		if (w[query_id].rc != 0)
			return 1;
	} else if (w[query_id].rc != 1) {
		return 1;
	}
	return 0;
}

static int race_one_frame(int winner)
{
	struct race_worker w[2];
	struct spp_diag_trace_core_snapshot snap;
	int run_rc;
	int ok_count;

	fresh();
	spp_diag_trace_core_set_op_caps(2, 1024);
	if (init_seed(0x47) != WIRE_OK)
		return 2;
	memset(w, 0, sizeof(w));
	w[0].op = op_append_ok;
	w[1].op = op_append_ok;
	run_rc = finish_race(w, winner);
	if (run_rc != 0)
		return 2;
	if (take_snap(&snap) != WIRE_OK)
		return 2;
	ok_count = (w[0].rc == WIRE_OK) + (w[1].rc == WIRE_OK);
	if (ok_count != 1)
		return 1;
	if (w[winner].rc != WIRE_OK)
		return 1;
	if (w[1 - winner].rc != WIRE_CAP)
		return 1;
	if (!snap.failed || snap.reason != WIRE_CAP)
		return 1;
	if (snap.frame_count != 2)
		return 1;
	return 0;
}

static int race_one_byte(int winner)
{
	struct race_worker w[2];
	struct spp_diag_trace_core_snapshot snap;
	int run_rc;
	int ok_count;
	const u64 max_bytes = 244ull + 48ull;

	fresh();
	spp_diag_trace_core_set_op_caps(8, max_bytes);
	if (init_seed(0x48) != WIRE_OK)
		return 2;
	memset(w, 0, sizeof(w));
	w[0].op = op_append_ok;
	w[1].op = op_append_ok;
	run_rc = finish_race(w, winner);
	if (run_rc != 0)
		return 2;
	if (take_snap(&snap) != WIRE_OK)
		return 2;
	ok_count = (w[0].rc == WIRE_OK) + (w[1].rc == WIRE_OK);
	if (ok_count != 1)
		return 1;
	if (w[winner].rc != WIRE_OK)
		return 1;
	if (w[1 - winner].rc != WIRE_CAP)
		return 1;
	if (!snap.failed || snap.reason != WIRE_CAP)
		return 1;
	if (snap.frame_count != 2)
		return 1;
	if (snap.stream_byte_count != max_bytes)
		return 1;
	return 0;
}

#ifndef SPP_DIAG_TRACE_CORE_NOP_LOCK
static int test_append_before_init(void)
{
	struct spp_diag_trace_core_snapshot snap;
	struct host_vmalloc_record rec;
	int rc;

	fresh();
	rc = append_terminal();
	if (rc != WIRE_STATE)
		return 1;
	if (take_snap(&snap) != WIRE_OK)
		return 1;
	if (!snap.failed || snap.reason != WIRE_STATE || snap.initialized)
		return 1;
	if (init_seed(0x51) != WIRE_STATE)
		return 1;
	if (spp_diag_trace_core_is_green() != 0)
		return 1;
	if (take_snap(&snap) != WIRE_OK)
		return 1;
	if (snap.initialized || snap.stream_len != 0)
		return 1;
	rec = host_vmalloc_record();
	if (rec.alloc_count != rec.free_count)
		return 1;
	return 0;
}

static int test_mark_before_init(int valid)
{
	struct spp_diag_trace_core_snapshot snap;
	struct host_vmalloc_record rec;
	int want = valid ? WIRE_CAP : WIRE_VALUE;
	int rc;

	fresh();
	rc = spp_diag_trace_core_mark_failure(valid ? WIRE_CAP : 0);
	if (rc != want)
		return 1;
	if (take_snap(&snap) != WIRE_OK)
		return 1;
	if (!snap.failed || snap.reason != want || snap.initialized)
		return 1;
	if (init_seed(0x52) != want)
		return 1;
	if (spp_diag_trace_core_is_green() != 0)
		return 1;
	if (take_snap(&snap) != WIRE_OK)
		return 1;
	if (snap.initialized || snap.stream_len != 0 || snap.reason != want)
		return 1;
	rec = host_vmalloc_record();
	if (rec.alloc_count != rec.free_count)
		return 1;
	return 0;
}

static int fail_named(const char *name, int rc)
{
	if (rc != 0) {
		fprintf(stderr, "FAIL %s rc=%d\n", name, rc);
		return 1;
	}
	printf("ok   %s\n", name);
	return 0;
}
#endif

#ifdef SPP_DIAG_TRACE_CORE_NOP_LOCK
static int until_torn(int (*fn)(void), const char *name)
{
	int trial;
	int rc;

	for (trial = 0; trial < NEG_TRIALS; trial++) {
		rc = fn();
		if (rc == 2) {
			fprintf(stderr, "FAIL negative %s setup\n", name);
			return 1;
		}
		if (rc == 1) {
			printf("ok   race-negative %s trial=%d\n", name,
			       trial + 1);
			fresh();
			return 0;
		}
		fresh();
	}
	fprintf(stderr, "FAIL negative %s did not observably fail\n", name);
	return 1;
}

static int neg_concurrent_init(void)
{
	return race_concurrent_init(0);
}

static int neg_init_vs_valid_mark(void)
{
	return race_init_vs_mark(1, 1);
}

static int neg_init_vs_invalid_mark(void)
{
	return race_init_vs_mark(1, 0);
}

static int neg_append_vs_append(void)
{
	return race_append_vs_append(0);
}

static int neg_snapshot_vs_append(void)
{
	int rc = race_snapshot_vs_append(0);

	if (rc != 0)
		return rc;
	return race_snapshot_vs_append(1);
}

static int neg_append_vs_mark(void)
{
	return race_append_vs_mark(0);
}

static int neg_init_vs_query(void)
{
	return race_init_vs_query(1);
}

static int neg_mark_vs_query(void)
{
	return race_mark_vs_query(1);
}

static int neg_failing_append_vs_query(void)
{
	return race_failing_append_vs_query(1);
}

static int neg_one_frame(void)
{
	return race_one_frame(0);
}

static int neg_one_byte(void)
{
	return race_one_byte(0);
}
#endif

int main(void)
{
	int fails = 0;

	if (!IS_ENABLED(CONFIG_KUNIT)) {
		fputs("race selftest requires CONFIG_KUNIT=1\n", stderr);
		return 2;
	}

#ifdef SPP_DIAG_TRACE_CORE_NOP_LOCK
	fails += until_torn(neg_concurrent_init, "concurrent-init");
	fails += until_torn(neg_init_vs_valid_mark, "init-vs-valid-mark");
	fails += until_torn(neg_init_vs_invalid_mark, "init-vs-invalid-mark");
	fails += until_torn(neg_append_vs_append, "append-vs-append");
	fails += until_torn(neg_snapshot_vs_append, "snapshot-vs-append");
	fails += until_torn(neg_append_vs_mark, "append-vs-mark");
	fails += until_torn(neg_init_vs_query, "init-vs-query");
	fails += until_torn(neg_mark_vs_query, "mark-vs-query");
	fails += until_torn(neg_failing_append_vs_query,
			   "failing-append-vs-query");
	fails += until_torn(neg_one_frame, "one-frame");
	fails += until_torn(neg_one_byte, "one-byte");
	if (fails) {
		fputs("FAIL spp-diag-trace-core-race-selftest negative\n",
		      stderr);
		return 1;
	}
	puts("ok   spp-diag-trace-core-race-selftest negative (unlocked overlap observed)");
	return 0;
#else
	int order;
	char name[80];

	if (test_contiguous_sequences() != 0) {
		fputs("FAIL contiguous sequences\n", stderr);
		fails++;
	} else {
		puts("ok   race-contiguous-sequences");
	}

	for (order = 0; order < 2; order++) {
		snprintf(name, sizeof(name), "race-concurrent-init order=%d",
			 order);
		fails += fail_named(name, race_concurrent_init(order));
		snprintf(name, sizeof(name),
			 "race-init-vs-valid-mark init_first=%d", order);
		fails += fail_named(name, race_init_vs_mark(order, 1));
		snprintf(name, sizeof(name),
			 "race-init-vs-invalid-mark init_first=%d", order);
		fails += fail_named(name, race_init_vs_mark(order, 0));
		snprintf(name, sizeof(name), "race-append-vs-append order=%d",
			 order);
		fails += fail_named(name, race_append_vs_append(order));
		snprintf(name, sizeof(name),
			 "race-snapshot-vs-append snap_first=%d", order);
		fails += fail_named(name, race_snapshot_vs_append(order));
		snprintf(name, sizeof(name),
			 "race-append-vs-mark append_first=%d", order);
		fails += fail_named(name, race_append_vs_mark(order));
		snprintf(name, sizeof(name), "race-init-vs-query init_first=%d",
			 order);
		fails += fail_named(name, race_init_vs_query(order));
		snprintf(name, sizeof(name), "race-mark-vs-query mark_first=%d",
			 order);
		fails += fail_named(name, race_mark_vs_query(order));
		snprintf(name, sizeof(name),
			 "race-failing-append-vs-query append_first=%d", order);
		fails += fail_named(name, race_failing_append_vs_query(order));
		snprintf(name, sizeof(name), "race-one-frame order=%d", order);
		fails += fail_named(name, race_one_frame(order));
		snprintf(name, sizeof(name), "race-one-byte order=%d", order);
		fails += fail_named(name, race_one_byte(order));
	}
	fails += fail_named("race-append-before-init", test_append_before_init());
	fails += fail_named("race-valid-mark-before-init",
			    test_mark_before_init(1));
	fails += fail_named("race-invalid-mark-before-init",
			    test_mark_before_init(0));
	if (fails) {
		fputs("FAIL spp-diag-trace-core-race-selftest\n", stderr);
		return 1;
	}
	puts("ok   spp-diag-trace-core-race-selftest");
	return 0;
#endif
}
