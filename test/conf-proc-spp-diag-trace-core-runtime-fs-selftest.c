/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ima.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/panic.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/spp_diag_trace_bootstrap.h>
#include <linux/spp_diag_trace_runtime.h>
#include "protocol_constants.h"
#include "runtime_types.h"
#include "core.h"

#define ASSERT(cond, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL: %s (%s:%d): %s\n", __func__, __FILE__, __LINE__, msg); \
			exit(1); \
		} \
	} while (0)

static const char valid_command_line[] =
	"ima_policy=critical_data "
	"sol_spp_diag.challenge=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
	"sol_spp_diag.run=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
	"sol_spp_diag.control_plan=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

static const u8 expected_challenge[32] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static const u8 expected_run_id[32] = {
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
	0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
};

static const u8 expected_control_plan[32] = {
	0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
	0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
};

static void setup_published_runtime(struct task_struct **out_root)
{
	spp_diag_trace_core_reset();
	spp_diag_trace_core_set_op_caps(SPP_DIAG_TRACE_MAX_FRAMES, SPP_DIAG_TRACE_MAX_STREAM_BYTES);
	host_kmod_reset();
	host_ima_reset();
	host_securityfs_reset();
	host_current_task.pid = 1;
	host_current_task.tgid = 1;
	host_current_task.flags = 0;
	host_current_task_ptr = NULL;
	host_saved_command_line_set(valid_command_line);

	spp_diag_trace_bootstrap_init();
	spp_diag_trace_bootstrap_ima_ready();
	ASSERT(spp_diag_trace_runtime_init() == 0, "runtime init");
	host_kmod_set_gate(spp_diag_trace_bootstrap_bprm_check);
	spp_diag_trace_bootstrap_release();
	ASSERT(spp_diag_trace_runtime_ready() == 1, "runtime ready");
	ASSERT(spp_diag_trace_core_is_green() == 1, "green after release");
	if (out_root)
		*out_root = &host_current_task;
}

static void build_command(u8 *buf, u16 kind, u16 requested_phase)
{
	static const u8 magic[8] = { SPP_DIAG_TRACE_MAGIC_COMMAND_BYTES };

	memset(buf, 0, SPP_DIAG_TRACE_COMMAND_SIZE);
	memcpy(buf + 0, magic, 8);
	buf[8] = 0; buf[9] = 1; /* version = 1 */
	buf[10] = (u8)(kind >> 8); buf[11] = (u8)(kind & 0xff); /* kind */
	buf[12] = 0; buf[13] = 0; buf[14] = 0; buf[15] = 128; /* length = 128 */
	memcpy(buf + 16, expected_challenge, 32);
	memcpy(buf + 48, expected_run_id, 32);
	memcpy(buf + 80, expected_control_plan, 32);
	buf[112] = (u8)(requested_phase >> 8); buf[113] = (u8)(requested_phase & 0xff);
}

static void test_securityfs_registration(void)
{
	const struct file_operations *ctrl_fops;
	const struct file_operations *stream_fops;
	struct dentry *ctrl_dentry;
	struct dentry *stream_dentry;

	setup_published_runtime(NULL);

	ctrl_fops = host_securityfs_get_fops("control");
	stream_fops = host_securityfs_get_fops("stream");
	ctrl_dentry = host_securityfs_get_dentry("control");
	stream_dentry = host_securityfs_get_dentry("stream");

	ASSERT(ctrl_fops != NULL, "control fops registered");
	ASSERT(stream_fops != NULL, "stream fops registered");
	ASSERT(ctrl_fops->write != NULL, "control write registered");
	ASSERT(stream_fops->read != NULL, "stream read registered");
	ASSERT(stream_fops->llseek != NULL, "stream llseek registered");
	ASSERT(ctrl_dentry != NULL, "control dentry exists");
	ASSERT(stream_dentry != NULL, "stream dentry exists");
	printf("PASS: test_securityfs_registration\n");
}

static void test_command_write_size_validation(void)
{
	const struct file_operations *ctrl_fops;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE + 10];
	loff_t pos = 0;
	ssize_t ret;

	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);

	/* Short write */
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, 127, &pos);
	ASSERT(ret == -EINVAL, "short write rejected with -EINVAL");
	ASSERT(spp_diag_trace_core_is_green() == 0, "short write is sticky error");

	/* Reset and test long write */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, 129, &pos);
	ASSERT(ret == -EINVAL, "long write rejected with -EINVAL");
	ASSERT(spp_diag_trace_core_is_green() == 0, "long write is sticky error");

	/* Reset and test zero write */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, 0, &pos);
	ASSERT(ret == -EINVAL, "zero write rejected with -EINVAL");
	ASSERT(spp_diag_trace_core_is_green() == 0, "zero write is sticky error");

	printf("PASS: test_command_write_size_validation\n");
}

static void test_command_header_field_validations(void)
{
	const struct file_operations *ctrl_fops;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos;
	ssize_t ret;

	/* Wrong magic */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	cmd[0] = 'X';
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "wrong magic rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "wrong magic sticky error");

	/* Wrong version */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	cmd[9] = 2; /* version 2 */
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "wrong version rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "wrong version sticky error");

	/* Wrong kind (e.g. 0 or 3) */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, 3, 2);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "wrong kind rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "wrong kind sticky error");

	/* Wrong internal length (e.g. 64) */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	cmd[15] = 64;
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "wrong length field rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "wrong length field sticky error");

	/* Nonzero reserved bytes */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	cmd[120] = 1;
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "nonzero reserved bytes rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "nonzero reserved sticky error");

	/* Wrong challenge */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	cmd[20] ^= 0xff;
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "wrong challenge rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "wrong challenge sticky error");

	/* Wrong run_identity */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	cmd[50] ^= 0xff;
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "wrong run_identity rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "wrong run_identity sticky error");

	/* Wrong control_plan_address */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	cmd[90] ^= 0xff;
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "wrong control_plan rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "wrong control_plan sticky error");

	printf("PASS: test_command_header_field_validations\n");
}

static void test_caller_identity_enforcement(void)
{
	const struct file_operations *ctrl_fops;
	struct task_struct *root;
	struct task_struct child_ts;
	struct task_struct untracked_fake_ts;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos = 0;
	ssize_t ret;
	struct spp_diag_trace_fact_task_alloc fa = { .clone_flags = 0 };
	struct spp_diag_trace_fact_task_created fc = { .pid = 2, .tgid = 1, .clone_flags = 0 };

	setup_published_runtime(&root);

	/* Create a child task */
	memset(&child_ts, 0, sizeof(child_ts));
	child_ts.pid = 2; child_ts.tgid = 1;
	ASSERT(spp_diag_trace_runtime_task_alloc_attempt(root, &fa) == 0, "alloc attempt");
	ASSERT(spp_diag_trace_runtime_task_created(root, &child_ts, &fc) == 0, "task created");

	/* 1. Attempt control write from child task token */
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	host_current_task_ptr = &child_ts;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EPERM, "child task write rejected with -EPERM");
	ASSERT(spp_diag_trace_core_is_green() == 0, "child write is sticky failure");

	/* 2. Reset and test untracked task with numeric pid=1, tgid=1 */
	setup_published_runtime(&root);
	ctrl_fops = host_securityfs_get_fops("control");
	memset(&untracked_fake_ts, 0, sizeof(untracked_fake_ts));
	untracked_fake_ts.pid = 1;
	untracked_fake_ts.tgid = 1;
	host_current_task_ptr = &untracked_fake_ts; /* Different pointer/token than root! */
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EPERM, "fake root pointer rejected with -EPERM");
	ASSERT(spp_diag_trace_core_is_green() == 0, "fake root write is sticky failure");

	host_current_task_ptr = NULL;
	printf("PASS: test_caller_identity_enforcement\n");
}

static void test_advance_phase_and_seal_happy_path(void)
{
	const struct file_operations *ctrl_fops;
	const struct file_operations *stream_fops;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos;
	ssize_t ret;
	u16 phase;
	const struct host_ima_call *ima_call;
	u8 buf[4096];
	size_t snapshot_cap = 0;
	u8 snapshot_buf[4096];

	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	stream_fops = host_securityfs_get_fops("stream");

	/* Before seal: reading stream returns -EAGAIN */
	pos = 0;
	ret = stream_fops->read(NULL, (char __user *)buf, sizeof(buf), &pos);
	ASSERT(ret == -EAGAIN, "stream read returns -EAGAIN before seal");

	/* Advance phase from 2 through 14 */
	for (phase = 2; phase <= 14; phase++) {
		build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, phase);
		pos = 0;
		ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
		ASSERT(ret == SPP_DIAG_TRACE_COMMAND_SIZE, "advance phase succeeded");
		ASSERT(spp_diag_trace_core_is_green() == 1, "core remains green");
	}

	/* Now at phase 14. Issue SEAL at phase 15 */
	build_command(cmd, SPP_DIAG_TRACE_CMD_SEAL, 15);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == SPP_DIAG_TRACE_COMMAND_SIZE, "seal succeeded");
	ASSERT(spp_diag_trace_core_is_green() == 1, "core remains green");
	ASSERT(spp_diag_trace_core_runtime_is_sealed() == 1, "core is sealed");

	/* Verify IMA measurement record */
	ima_call = host_ima_last_call();
	ASSERT(ima_call->calls == 3, "three IMA measurements made (ready, released, sealed)");
	ASSERT(strcmp(ima_call->event_label, "sol_spp_diag_trace") == 0, "event label is sol_spp_diag_trace");
	ASSERT(strcmp(ima_call->event_name, "sol-spp-diag-sealed-v1") == 0, "event name is sol-spp-diag-sealed-v1");
	ASSERT(ima_call->buf_len == 256, "record length is 256 bytes");

	/* Verify IMA record content field offsets:
	 * required_hook_mask @ 220 (u64)
	 * denied_exec_count @ 228 (u64)
	 * committed_exec_count @ 236 (u64)
	 * loss_count @ 244 (u32)
	 * overflow_count @ 248 (u32)
	 * reserved32 @ 252 (u32)
	 */
	ASSERT(memcmp(ima_call->record + 0, "SPPIMA1\0", 8) == 0, "IMA magic is SPPIMA1");
	ASSERT(ima_call->record[10] == 0 && ima_call->record[11] == 3, "IMA kind is SEALED (3)");
	ASSERT(ima_call->record[14] == 1 && ima_call->record[15] == 0, "IMA length is 256");
	ASSERT(ima_call->record[20] == 0 && ima_call->record[21] == 3, "IMA state is LIST_SEALED (3)");
	ASSERT(ima_call->record[22] == 0 && ima_call->record[23] == 0, "IMA state reserved is 0");
	ASSERT(memcmp(ima_call->record + 44, expected_challenge, 32) == 0, "challenge matches");
	ASSERT(memcmp(ima_call->record + 76, expected_run_id, 32) == 0, "run_id matches");
	ASSERT(memcmp(ima_call->record + 108, expected_control_plan, 32) == 0, "control_plan matches");

	/* Required hook mask @ 220 = 0xffffull (SPP_DIAG_TRACE_HOOK_MASK_PROVENANCE) */
	ASSERT(ima_call->record[226] == 0xff && ima_call->record[227] == 0xff, "hook mask is 0xffff");
	ASSERT(ima_call->record[220] == 0 && ima_call->record[221] == 0, "hook mask top bytes zero");
	/* Loss count @ 244 = 0 */
	ASSERT(ima_call->record[244] == 0 && ima_call->record[245] == 0 &&
	       ima_call->record[246] == 0 && ima_call->record[247] == 0, "loss count is 0");
	/* Overflow count @ 248 = 0 */
	ASSERT(ima_call->record[248] == 0 && ima_call->record[249] == 0 &&
	       ima_call->record[250] == 0 && ima_call->record[251] == 0, "overflow count is 0");
	/* Reserved32 @ 252 = 0 */
	ASSERT(ima_call->record[252] == 0 && ima_call->record[253] == 0 &&
	       ima_call->record[254] == 0 && ima_call->record[255] == 0, "reserved32 is 0");

	/* Post-seal stream read */
	pos = 0;
	ret = stream_fops->read(NULL, (char __user *)buf, sizeof(buf), &pos);
	ASSERT(ret > 0, "post-seal stream read returns bytes");
	ASSERT(pos == ret, "pos advanced by bytes read");

	/* Verify reading matches snapshot */
	ASSERT(spp_diag_trace_core_snapshot(snapshot_buf, sizeof(snapshot_buf), &snapshot_cap) == WIRE_OK, "snapshot");
	struct spp_diag_trace_core_snapshot *meta = (struct spp_diag_trace_core_snapshot *)snapshot_buf;
	ASSERT((size_t)ret == (size_t)meta->stream_len, "stream read size matches stream length");
	ASSERT(memcmp(buf, snapshot_buf + sizeof(*meta), ret) == 0, "stream read content matches snapshot stream bytes");

	printf("PASS: test_advance_phase_and_seal_happy_path\n");
}

static void test_phase_ordering_and_skips(void)
{
	const struct file_operations *ctrl_fops;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos;
	ssize_t ret;

	/* Skip phase: jump from 1 directly to 3 */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 3);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "skipped phase rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "skipped phase sticky failure");

	/* Duplicate phase: advance to 2, then try 2 again */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == SPP_DIAG_TRACE_COMMAND_SIZE, "phase 2 ok");
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "duplicate phase rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "duplicate phase sticky failure");

	/* Backward phase: advance to 2, then try 1 */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == SPP_DIAG_TRACE_COMMAND_SIZE, "phase 2 ok");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 1);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "backward phase rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "backward phase sticky failure");

	/* Premature SEAL at phase 1 (requested 15) */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_SEAL, 15);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "premature seal rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "premature seal sticky failure");

	/* Out of range phase (e.g. 16) */
	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 16);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EINVAL, "out of range phase rejected");
	ASSERT(spp_diag_trace_core_is_green() == 0, "out of range phase sticky failure");

	printf("PASS: test_phase_ordering_and_skips\n");
}

static void test_quiescence_enforcement(void)
{
	const struct file_operations *ctrl_fops;
	struct task_struct *root;
	struct task_struct child_ts;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos;
	ssize_t ret;
	struct spp_diag_trace_fact_task_alloc fa = { .clone_flags = 0 };
	struct spp_diag_trace_fact_task_created fc = { .pid = 2, .tgid = 1, .clone_flags = 0 };
	struct spp_diag_trace_fact_file_open_attempt foa = {
		.path = "/test/file", .path_len = 10, .access = 1, .modifiers = 0, .dirfd = -100
	};
	u64 op_ord = 0;

	/* 1. Advance phase rejected while child task is LIVE */
	setup_published_runtime(&root);
	memset(&child_ts, 0, sizeof(child_ts));
	child_ts.pid = 2; child_ts.tgid = 1;
	ASSERT(spp_diag_trace_runtime_task_alloc_attempt(root, &fa) == 0, "alloc attempt");
	ASSERT(spp_diag_trace_runtime_task_created(root, &child_ts, &fc) == 0, "task created");

	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EBUSY, "advance phase with live child rejected with -EBUSY");
	ASSERT(spp_diag_trace_core_is_green() == 0, "live child during advance is sticky failure");

	/* 2. Advance phase rejected while operation is OPEN */
	setup_published_runtime(&root);
	ASSERT(spp_diag_trace_runtime_file_open_attempt(root, &foa, &op_ord) == 0, "open attempt");

	ctrl_fops = host_securityfs_get_fops("control");
	build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, 2);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EBUSY, "advance phase with open op rejected with -EBUSY");
	ASSERT(spp_diag_trace_core_is_green() == 0, "open op during advance is sticky failure");

	printf("PASS: test_quiescence_enforcement\n");
}

static void test_stream_read_and_seek_post_seal(void)
{
	const struct file_operations *ctrl_fops;
	const struct file_operations *stream_fops;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos;
	ssize_t ret;
	u16 phase;
	u8 full_stream[4096];
	size_t full_len;
	u8 part[32];
	struct file mock_file;

	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	stream_fops = host_securityfs_get_fops("stream");

	for (phase = 2; phase <= 14; phase++) {
		build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, phase);
		pos = 0;
		ASSERT(ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos) == SPP_DIAG_TRACE_COMMAND_SIZE, "phase");
	}
	build_command(cmd, SPP_DIAG_TRACE_CMD_SEAL, 15);
	pos = 0;
	ASSERT(ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos) == SPP_DIAG_TRACE_COMMAND_SIZE, "seal");

	/* Read entire stream */
	pos = 0;
	ret = stream_fops->read(NULL, (char __user *)full_stream, sizeof(full_stream), &pos);
	ASSERT(ret > 0, "full stream read");
	full_len = (size_t)ret;

	/* Test repeated reads return identical bytes */
	pos = 0;
	u8 repeated[4096];
	ret = stream_fops->read(NULL, (char __user *)repeated, sizeof(repeated), &pos);
	ASSERT((size_t)ret == full_len, "repeated read length matches");
	ASSERT(memcmp(full_stream, repeated, full_len) == 0, "repeated read content matches exactly");

	/* Test chunked reads */
	pos = 0;
	size_t total_chunked = 0;
	while (total_chunked < full_len) {
		ret = stream_fops->read(NULL, (char __user *)part, sizeof(part), &pos);
		ASSERT(ret > 0, "chunk read > 0");
		ASSERT(memcmp(part, full_stream + total_chunked, (size_t)ret) == 0, "chunk content matches");
		total_chunked += (size_t)ret;
	}
	ASSERT(total_chunked == full_len, "chunked read reached EOF exactly");

	/* Subsequent read at EOF returns 0 */
	ret = stream_fops->read(NULL, (char __user *)part, sizeof(part), &pos);
	ASSERT(ret == 0, "read at EOF returns 0");

	/* Test llseek: SEEK_SET, SEEK_CUR, SEEK_END */
	memset(&mock_file, 0, sizeof(mock_file));
	mock_file.f_pos = 0;

	/* Seek SET */
	ASSERT(stream_fops->llseek(&mock_file, 50, SEEK_SET) == 50, "llseek SEEK_SET");
	ASSERT(mock_file.f_pos == 50, "f_pos updated");

	/* Seek CUR */
	ASSERT(stream_fops->llseek(&mock_file, 20, SEEK_CUR) == 70, "llseek SEEK_CUR");
	ASSERT(mock_file.f_pos == 70, "f_pos updated");

	/* Seek END */
	ASSERT(stream_fops->llseek(&mock_file, -10, SEEK_END) == (loff_t)full_len - 10, "llseek SEEK_END");
	ASSERT(mock_file.f_pos == (loff_t)full_len - 10, "f_pos updated");

	/* Seek past EOF returns -EINVAL */
	ASSERT(stream_fops->llseek(&mock_file, (loff_t)full_len + 1, SEEK_SET) == -EINVAL, "seek past EOF invalid");

	/* Seek negative returns -EINVAL */
	ASSERT(stream_fops->llseek(&mock_file, -1, SEEK_SET) == -EINVAL, "seek negative invalid");

	printf("PASS: test_stream_read_and_seek_post_seal\n");
}

static int g_hook_called = 0;
static bool g_hook_lock_held = true;

static void test_copy_hook_fn(bool lock_held)
{
	g_hook_called++;
	g_hook_lock_held = lock_held;
}

static void test_lock_not_held_during_copy_seam(void)
{
	const struct file_operations *ctrl_fops;
	const struct file_operations *stream_fops;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos;
	u16 phase;
	u8 buf[64];

	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	stream_fops = host_securityfs_get_fops("stream");

	for (phase = 2; phase <= 14; phase++) {
		build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, phase);
		pos = 0;
		ASSERT(ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos) == SPP_DIAG_TRACE_COMMAND_SIZE, "phase");
	}
	build_command(cmd, SPP_DIAG_TRACE_CMD_SEAL, 15);
	pos = 0;
	ASSERT(ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos) == SPP_DIAG_TRACE_COMMAND_SIZE, "seal");

	g_hook_called = 0;
	g_hook_lock_held = true;
	spp_diag_trace_core_set_read_copy_hook(test_copy_hook_fn);

	pos = 0;
	stream_fops->read(NULL, (char __user *)buf, sizeof(buf), &pos);

	ASSERT(g_hook_called > 0, "read copy hook was called");
	ASSERT(g_hook_lock_held == false, "copy ran outside the spinlock");

	spp_diag_trace_core_set_read_copy_hook(NULL);
	printf("PASS: test_lock_not_held_during_copy_seam\n");
}

static void test_post_seal_terminal_behavior_and_entry_point_cutoff(void)
{
	const struct file_operations *ctrl_fops;
	struct task_struct *root;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos;
	u16 phase;
	struct spp_diag_trace_fact_task_alloc fa = { .clone_flags = 0 };
	struct spp_diag_trace_fact_task_created fc = { .pid = 2, .tgid = 1, .clone_flags = 0 };
	struct spp_diag_trace_fact_exec_attempt ea = { .path = "/bin/sh", .path_len = 7, .pid = 1, .tgid = 1 };
	struct spp_diag_trace_fact_exec_commit ec = { .pid = 1, .tgid = 1 };
	struct spp_diag_trace_fact_file_open_attempt foa = { .path = "/etc/hosts", .path_len = 10, .access = 1, .modifiers = 0, .dirfd = -100 };
	struct spp_diag_trace_fact_file_policy fp = { .access = 1, .modifiers = 0, .decision = SPP_DIAG_TRACE_POLICY_ALLOW, .object_kind = 1, .result = 0, .fs_magic = 0, .dev_major = 0, .dev_minor = 0, .inode = 1, .mount_identity = 1, .observed_size = 0 };
	struct spp_diag_trace_fact_mapping_policy mp = { .operation = 1, .decision = SPP_DIAG_TRACE_POLICY_ALLOW, .backing = 1, .mode = 1, .requested = 1, .effective = 1, .prior = 0, .result = 0, .fs_magic = 0, .dev_major = 0, .dev_minor = 0, .seals = 0, .inode = 1, .mount_identity = 1, .observed_size = 0 };
	struct spp_diag_trace_fact_network_policy np = { .operation = 1, .decision = SPP_DIAG_TRACE_POLICY_ALLOW, .kind = 1, .source = 1, .socket_kind = 1, .protocol = 6, .family = 2, .addrlen = 16, .result = 0, .flags = 0, .size = 0, .cookie = 0, .port = 80, .reserved = 0, .scope = 0, .flow = 0, .address = {0} };
	u64 op_ord = 0;
	size_t snapshot_cap_before, snapshot_cap_after;
	u8 snap_before[4096], snap_after[4096];

	setup_published_runtime(&root);
	ctrl_fops = host_securityfs_get_fops("control");

	for (phase = 2; phase <= 14; phase++) {
		build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, phase);
		pos = 0;
		ASSERT(ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos) == SPP_DIAG_TRACE_COMMAND_SIZE, "phase");
	}
	build_command(cmd, SPP_DIAG_TRACE_CMD_SEAL, 15);
	pos = 0;
	ASSERT(ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos) == SPP_DIAG_TRACE_COMMAND_SIZE, "seal");

	ASSERT(spp_diag_trace_core_snapshot(snap_before, sizeof(snap_before), &snapshot_cap_before) == WIRE_OK, "snap before");

	/* Every typed provenance entry point must return SPP_DIAG_TRACE_ERR_INACTIVE (-ESHUTDOWN = -108) */
	ASSERT(spp_diag_trace_runtime_bind_root(root) == SPP_DIAG_TRACE_ERR_INACTIVE, "bind_root returns ERR_INACTIVE");
	ASSERT(spp_diag_trace_runtime_task_alloc_attempt(root, &fa) == SPP_DIAG_TRACE_ERR_INACTIVE, "alloc returns ERR_INACTIVE");
	ASSERT(spp_diag_trace_runtime_task_created(root, root, &fc) == SPP_DIAG_TRACE_ERR_INACTIVE, "created returns ERR_INACTIVE");
	ASSERT(spp_diag_trace_runtime_task_exit(root, 0) == SPP_DIAG_TRACE_ERR_INACTIVE, "exit returns ERR_INACTIVE");
	ASSERT(spp_diag_trace_runtime_exec_attempt(root, &ea) == SPP_DIAG_TRACE_ERR_INACTIVE, "exec_attempt returns ERR_INACTIVE");
	ASSERT(spp_diag_trace_runtime_exec_commit(root, &ec) == SPP_DIAG_TRACE_ERR_INACTIVE, "exec_commit returns ERR_INACTIVE");
	ASSERT(spp_diag_trace_runtime_file_open_attempt(root, &foa, &op_ord) == SPP_DIAG_TRACE_ERR_INACTIVE, "open_attempt returns ERR_INACTIVE");
	ASSERT(spp_diag_trace_runtime_file_policy_decision(root, 1, &fp) == SPP_DIAG_TRACE_ERR_INACTIVE, "file_policy returns ERR_INACTIVE");
	ASSERT(spp_diag_trace_runtime_mapping_policy_decision(root, &mp, &op_ord) == SPP_DIAG_TRACE_ERR_INACTIVE, "mapping returns ERR_INACTIVE");
	ASSERT(spp_diag_trace_runtime_network_policy_decision(root, &np, &op_ord) == SPP_DIAG_TRACE_ERR_INACTIVE, "network returns ERR_INACTIVE");
	ASSERT(spp_diag_trace_runtime_operation_return(root, 1, 1, 0) == SPP_DIAG_TRACE_ERR_INACTIVE, "return returns ERR_INACTIVE");

	/* Subsequent control write returns -ESHUTDOWN */
	build_command(cmd, SPP_DIAG_TRACE_CMD_SEAL, 15);
	pos = 0;
	ASSERT(ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos) == -ESHUTDOWN, "post-seal control write returns -ESHUTDOWN");

	/* Verify zero state change and core remains green (not failed) */
	ASSERT(spp_diag_trace_core_is_green() == 1, "core is still green");
	ASSERT(spp_diag_trace_core_snapshot(snap_after, sizeof(snap_after), &snapshot_cap_after) == WIRE_OK, "snap after");
	ASSERT(snapshot_cap_before == snapshot_cap_after, "snapshot size unchanged");
	ASSERT(memcmp(snap_before, snap_after, snapshot_cap_before) == 0, "snapshot bytes byte-identical");

	printf("PASS: test_post_seal_terminal_behavior_and_entry_point_cutoff\n");
}

static void test_ima_measurement_failure_prevents_publication(void)
{
	const struct file_operations *ctrl_fops;
	const struct file_operations *stream_fops;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos;
	ssize_t ret;
	u16 phase;
	u8 buf[64];

	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	stream_fops = host_securityfs_get_fops("stream");

	for (phase = 2; phase <= 14; phase++) {
		build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, phase);
		pos = 0;
		ASSERT(ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos) == SPP_DIAG_TRACE_COMMAND_SIZE, "phase");
	}

	/* Force IMA failure */
	host_ima_set_result(-EIO);

	build_command(cmd, SPP_DIAG_TRACE_CMD_SEAL, 15);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret == -EIO, "seal returns -EIO on IMA failure");
	ASSERT(spp_diag_trace_core_is_green() == 0, "core marked sticky failed");
	ASSERT(spp_diag_trace_core_runtime_is_sealed() == 0, "runtime is not sealed");

	/* Stream read must return -EAGAIN */
	pos = 0;
	ret = stream_fops->read(NULL, (char __user *)buf, sizeof(buf), &pos);
	ASSERT(ret == -EAGAIN, "stream unreadable after IMA failure");

	printf("PASS: test_ima_measurement_failure_prevents_publication\n");
}

static void kthread_alloc_sealing_hook(const struct host_ima_call *call)
{
	(void)call;
	struct task_struct parent_kthread = { .flags = PF_KTHREAD, .pid = 50, .tgid = 50 };
	int err = spp_diag_trace_runtime_task_alloc_attempt(&parent_kthread, 0);
	ASSERT(err != 0, "kthread task alloc attempt during sealing returns error");
	ASSERT(spp_diag_trace_core_is_green() == 0, "core is red after kthread alloc during sealing");
}

static void test_kthread_task_creation_during_sealing_turns_sticky_red(void)
{
	const struct file_operations *ctrl_fops;
	const struct file_operations *stream_fops;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos;
	ssize_t ret;
	u16 phase;
	u8 buf[64];

	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	stream_fops = host_securityfs_get_fops("stream");

	for (phase = 2; phase <= 14; phase++) {
		build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, phase);
		pos = 0;
		ASSERT(ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos) == SPP_DIAG_TRACE_COMMAND_SIZE, "phase");
	}

	host_ima_set_hook(kthread_alloc_sealing_hook);

	build_command(cmd, SPP_DIAG_TRACE_CMD_SEAL, 15);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret < 0, "seal failed due to producer activity during sealing");
	ASSERT(spp_diag_trace_core_is_green() == 0, "core remains red");
	ASSERT(spp_diag_trace_core_runtime_is_sealed() == 0, "runtime is not sealed");

	/* Stream read must return -EAGAIN */
	pos = 0;
	ret = stream_fops->read(NULL, (char __user *)buf, sizeof(buf), &pos);
	ASSERT(ret == -EAGAIN, "stream unreadable after failed seal");

	printf("PASS: test_kthread_task_creation_during_sealing_turns_sticky_red\n");
}

static void kthread_exit_sealing_hook(const struct host_ima_call *call)
{
	(void)call;
	struct task_struct untracked_kthread = { .flags = PF_KTHREAD, .pid = 60, .tgid = 60 };
	int err = spp_diag_trace_runtime_task_exit(&untracked_kthread, 0);
	ASSERT(err != 0, "untracked kthread exit during sealing returns error");
	ASSERT(spp_diag_trace_core_is_green() == 0, "core is red after kthread exit during sealing");
}

static void test_kthread_task_exit_during_sealing_turns_sticky_red(void)
{
	const struct file_operations *ctrl_fops;
	const struct file_operations *stream_fops;
	u8 cmd[SPP_DIAG_TRACE_COMMAND_SIZE];
	loff_t pos;
	ssize_t ret;
	u16 phase;
	u8 buf[64];

	setup_published_runtime(NULL);
	ctrl_fops = host_securityfs_get_fops("control");
	stream_fops = host_securityfs_get_fops("stream");

	for (phase = 2; phase <= 14; phase++) {
		build_command(cmd, SPP_DIAG_TRACE_CMD_ADVANCE_PHASE, phase);
		pos = 0;
		ASSERT(ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos) == SPP_DIAG_TRACE_COMMAND_SIZE, "phase");
	}

	host_ima_set_hook(kthread_exit_sealing_hook);

	build_command(cmd, SPP_DIAG_TRACE_CMD_SEAL, 15);
	pos = 0;
	ret = ctrl_fops->write(NULL, (const char __user *)cmd, sizeof(cmd), &pos);
	ASSERT(ret < 0, "seal failed due to task exit during sealing");
	ASSERT(spp_diag_trace_core_is_green() == 0, "core remains red");
	ASSERT(spp_diag_trace_core_runtime_is_sealed() == 0, "runtime is not sealed");

	/* Stream read must return -EAGAIN */
	pos = 0;
	ret = stream_fops->read(NULL, (char __user *)buf, sizeof(buf), &pos);
	ASSERT(ret == -EAGAIN, "stream unreadable after failed seal");

	printf("PASS: test_kthread_task_exit_during_sealing_turns_sticky_red\n");
}

int main(void)
{
	test_securityfs_registration();
	test_command_write_size_validation();
	test_command_header_field_validations();
	test_caller_identity_enforcement();
	test_advance_phase_and_seal_happy_path();
	test_phase_ordering_and_skips();
	test_quiescence_enforcement();
	test_stream_read_and_seek_post_seal();
	test_lock_not_held_during_copy_seam();
	test_post_seal_terminal_behavior_and_entry_point_cutoff();
	test_ima_measurement_failure_prevents_publication();
	test_kthread_task_creation_during_sealing_turns_sticky_red();
	test_kthread_task_exit_during_sealing_turns_sticky_red();

	printf("All runtime securityfs selftest checks passed successfully.\n");
	return 0;
}
