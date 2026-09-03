/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_UACCESS_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_UACCESS_H

#include <linux/string.h>
#include <linux/types.h>

static inline unsigned long copy_from_user(void *to, const void *from, unsigned long n)
{
	if (!to || !from)
		return n;
	memcpy(to, from, n);
	return 0;
}

static inline unsigned long copy_to_user(void *to, const void *from, unsigned long n)
{
	if (!to || !from)
		return n;
	memcpy(to, from, n);
	return 0;
}

#endif
