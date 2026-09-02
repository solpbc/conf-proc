/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_CRYPTO_SHA2_H
#define SPP_DIAG_TRACE_CORE_SHIM_CRYPTO_SHA2_H

#include <linux/types.h>

void sha256(const u8 *data, unsigned int len, u8 *out);

void host_sha256_reset_instrumentation(void);
unsigned host_sha256_call_count(void);
void host_sha256_push_sentinel(const u8 digest[32]);
unsigned host_sha256_preimage_count(void);
int host_sha256_get_preimage(unsigned i, u8 *out, unsigned *len);

#endif
