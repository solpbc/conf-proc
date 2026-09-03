/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_ADAPTER_MOUNT_H
#define SPP_DIAG_TRACE_CORE_SHIM_ADAPTER_MOUNT_H

#include <linux/mount.h>
#include <linux/types.h>

struct mount {
	struct vfsmount mnt;
	u64 mnt_id_unique;
};

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return (struct mount *)mnt;
}

#endif
