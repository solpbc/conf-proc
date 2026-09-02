/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/ima.h>
#include <linux/string.h>

static struct host_ima_call last_call;
static int ima_result;

int ima_measure_critical_data(const char *event_label, const char *event_name,
			      const void *buf, size_t buf_len, bool hash,
			      u8 *digest, size_t digest_len)
{
	last_call.event_label = event_label;
	last_call.event_name = event_name;
	last_call.buf = buf;
	last_call.buf_len = buf_len;
	last_call.hash = hash;
	last_call.digest = digest;
	last_call.digest_len = digest_len;
	if (buf_len <= sizeof(last_call.record))
		memcpy(last_call.record, buf, buf_len);
	last_call.calls++;
	return ima_result;
}

void host_ima_reset(void)
{
	last_call.event_label = NULL;
	last_call.event_name = NULL;
	last_call.buf = NULL;
	last_call.buf_len = 0;
	last_call.hash = false;
	last_call.digest = NULL;
	last_call.digest_len = 0;
	last_call.calls = 0;
	memset(last_call.record, 0, sizeof(last_call.record));
	ima_result = 0;
}

void host_ima_set_result(int result)
{
	ima_result = result;
}

const struct host_ima_call *host_ima_last_call(void)
{
	return &last_call;
}
