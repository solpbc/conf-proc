/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_TYPES_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_TYPES_H

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint16_t umode_t;
typedef int64_t loff_t;

#ifndef __user
#define __user
#endif

#endif
