/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/uaccess.h>

#include "core.h"
#include "protocol_constants.h"
#include "runtime_types.h"

static struct dentry *trace_dir;
static struct dentry *control_file;
static struct dentry *stream_file;

static ssize_t spp_diag_trace_fs_control_write(struct file *file,
					       const char __user *ubuf,
					       size_t count, loff_t *ppos)
{
	u8 raw[SPP_DIAG_TRACE_COMMAND_SIZE];
	int err;

	(void)file;
	if (spp_diag_trace_core_runtime_is_sealed())
		return -ESHUTDOWN;

	if (count != SPP_DIAG_TRACE_COMMAND_SIZE) {
		spp_diag_trace_core_mark_failure(WIRE_LENGTH);
		return -EINVAL;
	}

	if (copy_from_user(raw, ubuf, SPP_DIAG_TRACE_COMMAND_SIZE)) {
		spp_diag_trace_core_mark_failure(WIRE_STATE);
		return -EFAULT;
	}

	err = spp_diag_trace_core_runtime_handle_command(raw, sizeof(raw));
	if (err)
		return err;

	if (ppos)
		*ppos += SPP_DIAG_TRACE_COMMAND_SIZE;

	return SPP_DIAG_TRACE_COMMAND_SIZE;
}

static ssize_t spp_diag_trace_fs_stream_read(struct file *file,
					     char __user *ubuf,
					     size_t count, loff_t *ppos)
{
	(void)file;
	return spp_diag_trace_core_runtime_stream_read(ubuf, count, ppos);
}

static loff_t spp_diag_trace_fs_stream_llseek(struct file *file,
					      loff_t offset, int whence)
{
	return spp_diag_trace_core_runtime_stream_llseek(file, offset, whence);
}

static int spp_diag_trace_fs_stream_open(struct inode *inode, struct file *file)
{
	(void)inode;
	if (file)
		file->f_pos = 0;
	return 0;
}

static const struct file_operations control_fops = {
	.write = spp_diag_trace_fs_control_write,
};

static const struct file_operations stream_fops = {
	.read = spp_diag_trace_fs_stream_read,
	.llseek = spp_diag_trace_fs_stream_llseek,
	.open = spp_diag_trace_fs_stream_open,
};

int spp_diag_trace_runtime_fs_init(void)
{
	trace_dir = securityfs_create_dir("sol_spp_diag_trace", NULL);
	if (IS_ERR_OR_NULL(trace_dir)) {
		trace_dir = NULL;
		return -ENOMEM;
	}

	control_file = securityfs_create_file("control", S_IWUSR, trace_dir,
					      NULL, &control_fops);
	if (IS_ERR_OR_NULL(control_file)) {
		control_file = NULL;
		securityfs_remove(trace_dir);
		trace_dir = NULL;
		return -ENOMEM;
	}

	stream_file = securityfs_create_file("stream", S_IRUSR, trace_dir,
					     NULL, &stream_fops);
	if (IS_ERR_OR_NULL(stream_file)) {
		stream_file = NULL;
		securityfs_remove(control_file);
		securityfs_remove(trace_dir);
		control_file = NULL;
		trace_dir = NULL;
		return -ENOMEM;
	}

	return 0;
}

void spp_diag_trace_runtime_fs_exit(void)
{
	if (stream_file) {
		securityfs_remove(stream_file);
		stream_file = NULL;
	}
	if (control_file) {
		securityfs_remove(control_file);
		control_file = NULL;
	}
	if (trace_dir) {
		securityfs_remove(trace_dir);
		trace_dir = NULL;
	}
}
