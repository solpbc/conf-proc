/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_KDEV_T_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_KDEV_T_H

#include <linux/types.h>

#define MAJOR(dev) ((u32)(((dev) >> 8) & 0xfff))
#define MINOR(dev) ((u32)((dev) & 0xff))
#define MKDEV(major, minor) (((dev_t)(major) << 8) | (minor))

#endif
