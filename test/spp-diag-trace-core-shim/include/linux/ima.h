/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_IMA_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_IMA_H

#include <linux/types.h>

struct host_ima_call {
	const char *event_label;
	const char *event_name;
	const void *buf;
	size_t buf_len;
	bool hash;
	u8 *digest;
	size_t digest_len;
	unsigned int calls;
	u8 record[256];
};

int ima_measure_critical_data(const char *event_label, const char *event_name,
			      const void *buf, size_t buf_len, bool hash,
			      u8 *digest, size_t digest_len);
void host_ima_reset(void);
void host_ima_set_result(int result);
const struct host_ima_call *host_ima_last_call(void);

#endif
