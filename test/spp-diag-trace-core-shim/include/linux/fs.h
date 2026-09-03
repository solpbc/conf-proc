/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_FS_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_FS_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/stddef.h>

#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifndef SEEK_CUR
#define SEEK_CUR 1
#endif
#ifndef SEEK_END
#define SEEK_END 2
#endif

#ifndef S_IWUSR
#define S_IWUSR 0200
#endif
#ifndef S_IRUSR
#define S_IRUSR 0400
#endif

struct inode {
	umode_t i_mode;
	void *i_private;
};

struct file {
	loff_t f_pos;
	void *private_data;
	const struct file_operations *f_op;
};

struct file_operations {
	ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
	loff_t (*llseek)(struct file *, loff_t, int);
	int (*open)(struct inode *, struct file *);
	int (*release)(struct inode *, struct file *);
};

#endif
