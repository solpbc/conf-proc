/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_MM_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_MM_H

#include <linux/fs.h>

typedef unsigned long vm_flags_t;

#define VM_READ   0x00000001ul
#define VM_WRITE  0x00000002ul
#define VM_EXEC   0x00000004ul
#define VM_MAYEXEC 0x00000008ul
#define VM_SHARED 0x00000010ul

struct vm_area_struct {
	struct file *vm_file;
	vm_flags_t vm_flags;
};

#endif
