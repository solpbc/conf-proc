/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_ERRNO_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_ERRNO_H

#include <errno.h>

#ifndef EAGAIN
#define EAGAIN 11
#endif
#ifndef ENOENT
#define ENOENT 2
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif
#ifndef EACCES
#define EACCES 13
#endif
#ifndef EFAULT
#define EFAULT 14
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOSPC
#define ENOSPC 28
#endif
#ifndef EPERM
#define EPERM 1
#endif
#ifndef EIO
#define EIO 5
#endif
#ifndef EBUSY
#define EBUSY 16
#endif
#ifndef ESHUTDOWN
#define ESHUTDOWN 108
#endif

#endif
