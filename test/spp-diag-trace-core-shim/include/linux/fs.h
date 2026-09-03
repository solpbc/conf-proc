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
	u64 i_ino;
	loff_t i_size;
	struct super_block *i_sb;
};

struct super_block {
	unsigned long s_magic;
	dev_t s_dev;
};

struct vfsmount;

struct path {
	struct vfsmount *mnt;
};

struct file {
	loff_t f_pos;
	void *private_data;
	const struct file_operations *f_op;
	struct inode *f_inode;
	unsigned long f_flags;
	unsigned int f_mode;
	struct path f_path;
	u32 memfd_seals;
};

#define FMODE_EXEC 0x0020u
#define __FMODE_EXEC 0x40000000u

#define S_IFMT 0170000
#define S_IFREG 0100000
#define S_IFDIR 0040000
#define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)

static inline struct inode *file_inode(const struct file *file)
{
	return file ? file->f_inode : NULL;
}

static inline loff_t i_size_read(const struct inode *inode)
{
	return inode ? inode->i_size : 0;
}

struct file_operations {
	ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
	loff_t (*llseek)(struct file *, loff_t, int);
	int (*open)(struct inode *, struct file *);
	int (*release)(struct inode *, struct file *);
};

#endif
