/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_CRYPTO_SHA2_H
#define SPP_DIAG_TRACE_CORE_SHIM_CRYPTO_SHA2_H

#include <linux/types.h>

void sha256(const u8 *data, unsigned int len, u8 *out);

#endif
