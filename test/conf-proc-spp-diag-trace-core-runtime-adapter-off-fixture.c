/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/spp_diag_trace_adapter.h>

void spp_diag_trace_adapter_off_fixture(void)
{
	spp_diag_trace_adapter_exec_unsupported();
	spp_diag_trace_adapter_mapping_unsupported();
	spp_diag_trace_adapter_connect_return(0);
}
