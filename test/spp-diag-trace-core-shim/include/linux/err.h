/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_ERR_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_ERR_H

#include <linux/types.h>

static inline bool IS_ERR(const void *ptr)
{
	return (unsigned long)ptr >= (unsigned long)-4095;
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR(ptr);
}

static inline long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline void *ERR_PTR(long error)
{
	return (void *)error;
}

#endif
