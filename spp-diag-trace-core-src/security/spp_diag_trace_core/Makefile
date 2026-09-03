# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE) += spp_diag_trace_core.o
spp_diag_trace_core-y := core.o
spp_diag_trace_core-$(CONFIG_KUNIT) += core_kunit.o
spp_diag_trace_core-$(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP) += bootstrap.o gate.o release.o
spp_diag_trace_core-$(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME) += runtime_state.o runtime_fs.o adapter.o
spp_diag_trace_core-$(CONFIG_KUNIT) += $(if $(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP),bootstrap_kunit.o) $(if $(CONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME),runtime_kunit.o)
