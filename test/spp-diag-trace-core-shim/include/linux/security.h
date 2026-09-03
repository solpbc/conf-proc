/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_SECURITY_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_SECURITY_H

#include <linux/fs.h>
#include <linux/types.h>

struct dentry;

struct dentry *securityfs_create_dir(const char *name, struct dentry *parent);
struct dentry *securityfs_create_file(const char *name, umode_t mode,
				     struct dentry *parent, void *data,
				     const struct file_operations *fops);
void securityfs_remove(struct dentry *dentry);

/* Test / host inspection helpers */
void host_securityfs_reset(void);
void host_securityfs_set_fail_dir(int fail);
void host_securityfs_set_fail_file(int fail);
const struct file_operations *host_securityfs_get_fops(const char *path);
struct dentry *host_securityfs_get_dentry(const char *path);

#endif
