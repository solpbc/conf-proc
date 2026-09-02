/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_COMPILER_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_COMPILER_H

#define smp_load_acquire(pointer) __atomic_load_n((pointer), __ATOMIC_ACQUIRE)
#define smp_store_release(pointer, value) __atomic_store_n((pointer), (value), __ATOMIC_RELEASE)
#define WRITE_ONCE(pointer, value) __atomic_store_n(&(pointer), (value), __ATOMIC_RELAXED)

#endif
