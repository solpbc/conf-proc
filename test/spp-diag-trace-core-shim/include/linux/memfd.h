/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_MEMFD_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_MEMFD_H

#include <linux/fs.h>

static inline void *memfd_file_seals_ptr(struct file *file)
{
	return file && file->memfd_seals ? &file->memfd_seals : NULL;
}

static inline u32 memfd_file_seals(struct file *file)
{
	return file ? file->memfd_seals : 0;
}

#endif
