/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/security.h>
#include <linux/string.h>

#define MAX_DENTRIES 256

struct host_dentry {
	char name[64];
	umode_t mode;
	struct host_dentry *parent;
	void *data;
	const struct file_operations *fops;
	int active;
};

static struct host_dentry dentries[MAX_DENTRIES];
static int fail_dir_flag = 0;
static int fail_file_flag = 0;

void host_securityfs_reset(void)
{
	memset(dentries, 0, sizeof(dentries));
	fail_dir_flag = 0;
	fail_file_flag = 0;
}

void host_securityfs_set_fail_dir(int fail)
{
	fail_dir_flag = fail;
}

void host_securityfs_set_fail_file(int fail)
{
	fail_file_flag = fail;
}

struct dentry *securityfs_create_dir(const char *name, struct dentry *parent)
{
	size_t i;

	if (fail_dir_flag)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < MAX_DENTRIES; i++) {
		if (!dentries[i].active) {
			strncpy(dentries[i].name, name, sizeof(dentries[i].name) - 1);
			dentries[i].mode = 0700;
			dentries[i].parent = (struct host_dentry *)parent;
			dentries[i].data = NULL;
			dentries[i].fops = NULL;
			dentries[i].active = 1;
			return (struct dentry *)&dentries[i];
		}
	}
	return ERR_PTR(-ENOSPC);
}

struct dentry *securityfs_create_file(const char *name, umode_t mode,
				     struct dentry *parent, void *data,
				     const struct file_operations *fops)
{
	size_t i;

	if (fail_file_flag)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < MAX_DENTRIES; i++) {
		if (!dentries[i].active) {
			strncpy(dentries[i].name, name, sizeof(dentries[i].name) - 1);
			dentries[i].mode = mode;
			dentries[i].parent = (struct host_dentry *)parent;
			dentries[i].data = data;
			dentries[i].fops = fops;
			dentries[i].active = 1;
			return (struct dentry *)&dentries[i];
		}
	}
	return ERR_PTR(-ENOSPC);
}

void securityfs_remove(struct dentry *dentry)
{
	struct host_dentry *d = (struct host_dentry *)dentry;
	if (d && !IS_ERR(d)) {
		memset(d, 0, sizeof(*d));
	}
}

const struct file_operations *host_securityfs_get_fops(const char *name)
{
	size_t i;

	for (i = 0; i < MAX_DENTRIES; i++) {
		if (dentries[i].active && strcmp(dentries[i].name, name) == 0)
			return dentries[i].fops;
	}
	return NULL;
}

struct dentry *host_securityfs_get_dentry(const char *name)
{
	size_t i;

	for (i = 0; i < MAX_DENTRIES; i++) {
		if (dentries[i].active && strcmp(dentries[i].name, name) == 0)
			return (struct dentry *)&dentries[i];
	}
	return NULL;
}
