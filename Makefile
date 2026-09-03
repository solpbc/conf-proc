PYTHON ?= python3
CC ?= cc
C11FLAGS := -std=c11 -Wall -Wextra -Werror -pedantic
CORE_CFLAGS := -std=gnu11 -Wall -Wextra -Werror
SPP_DIAG_TRACE_SRC := conf_proc_spp_diag_trace.c
SPP_DIAG_TRACE_TEST := test/conf-proc-spp-diag-trace-selftest.c
SPP_DIAG_TRACE_ORACLE := test/conf-proc-spp-diag-trace-oracle-selftest.py
SPP_DIAG_TRACE_ORACLE_HARNESS := test/conf-proc-spp-diag-trace-oracle-harness.c
SPP_DIAG_TRACE_FRAME_TEST := test/conf-proc-spp-diag-trace-frame-selftest.c
SPP_DIAG_TRACE_STREAM_TEST := test/conf-proc-spp-diag-trace-stream-selftest.c
SPP_DIAG_TRACE_PROVENANCE_TEST := test/conf-proc-spp-diag-trace-provenance-selftest.c
SPP_DIAG_TRACE_FILE_POLICY_TEST := test/conf-proc-spp-diag-trace-file-policy-decision-selftest.c
SPP_DIAG_TRACE_EXEC_MAPPING_TEST := test/conf-proc-spp-diag-trace-exec-mapping-policy-decision-selftest.c
SPP_DIAG_TRACE_NETWORK_POLICY_TEST := test/conf-proc-spp-diag-trace-network-policy-decision-selftest.c
SPP_DIAG_TRACE_OPERATION_RETURN_TEST := test/conf-proc-spp-diag-trace-operation-return-selftest.c
SPP_DIAG_TRACE_TASK_EXIT_TEST := test/conf-proc-spp-diag-trace-task-exit-selftest.c
SPP_DIAG_TRACE_POLICY2_TEST := test/conf-proc-spp-diag-trace-policy2-selftest.c
SPP_DIAG_TRACE_CHAIN_SRC := conf_proc_spp_diag_trace_chain.py
SPP_DIAG_TRACE_CHAIN_VECTORS := test/conf_proc_spp_diag_trace_chain_vectors.py
SPP_DIAG_TRACE_CHAIN_ORACLE := test/conf-proc-spp-diag-trace-chain-oracle-selftest.py
SPP_DIAG_TRACE_CHAIN_TEST := test/conf-proc-spp-diag-trace-chain-selftest.py
SPP_DIAG_TRACE_CHECKPOINT_SRC := conf_proc_spp_diag_trace_checkpoints.py
SPP_DIAG_TRACE_CHECKPOINT_VECTORS := test/conf_proc_spp_diag_trace_checkpoint_vectors.py
SPP_DIAG_TRACE_CHECKPOINT_ORACLE := test/conf-proc-spp-diag-trace-checkpoints-oracle-selftest.py
SPP_DIAG_TRACE_CHECKPOINT_TEST := test/conf-proc-spp-diag-trace-checkpoints-selftest.py
SPP_DIAG_TRACE_SEMANTIC_REASONS := conf_proc_spp_diag_trace_semantic_reasons.py
SPP_DIAG_TRACE_SEMANTICS_SRC := conf_proc_spp_diag_trace_semantics.py
SPP_DIAG_TRACE_SEMANTICS_FIXTURE := test/conf_proc_spp_diag_trace_semantic_fixture.py
SPP_DIAG_TRACE_SEMANTICS_ORACLE_SRC := test/conf_proc_spp_diag_trace_semantics_oracle.py
SPP_DIAG_TRACE_SEMANTICS_ORACLE := test/conf-proc-spp-diag-trace-semantics-oracle-selftest.py
SPP_DIAG_TRACE_SEMANTICS_TEST := test/conf-proc-spp-diag-trace-semantics-selftest.py
SPP_DIAG_IMA_REASONS := conf_proc_spp_diag_ima_reasons.py
SPP_DIAG_IMA_SRC := conf_proc_spp_diag_ima.py
SPP_DIAG_IMA_FIXTURE := test/conf_proc_spp_diag_ima_fixture.py
SPP_DIAG_IMA_ORACLE := test/conf-proc-spp-diag-ima-oracle-selftest.py
SPP_DIAG_IMA_TEST := test/conf-proc-spp-diag-ima-selftest.py
SPP_DIAG_ATTEST_FIXTURE := test/conf_proc_spp_diag_attest_fixture.py
SPP_DIAG_ATTEST_FIXTURE_TEST := test/conf-proc-spp-diag-attest-fixture-selftest.py
SPP_DIAG_ATTEST_REASONS := conf_proc_spp_diag_attest_reasons.py
SPP_DIAG_ATTEST_SRC := conf_proc_spp_diag_attest.py
SPP_DIAG_ATTEST_ORACLE := test/conf-proc-spp-diag-attest-oracle-selftest.py
SPP_DIAG_ATTEST_TEST := test/conf-proc-spp-diag-attest-selftest.py
SPP_DIAG_TRACE_CORE_DIR := spp-diag-trace-core-src/security/spp_diag_trace_core
SPP_DIAG_TRACE_CORE_SRC := $(SPP_DIAG_TRACE_CORE_DIR)/core.c
SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC := $(SPP_DIAG_TRACE_CORE_DIR)/bootstrap.c $(SPP_DIAG_TRACE_CORE_DIR)/gate.c $(SPP_DIAG_TRACE_CORE_DIR)/release.c
SPP_DIAG_TRACE_CORE_CONSTANTS := $(SPP_DIAG_TRACE_CORE_DIR)/protocol_constants.h
SPP_DIAG_TRACE_CORE_SHIM_INC := test/spp-diag-trace-core-shim/include
SPP_DIAG_TRACE_CORE_HOST_INC := -I $(SPP_DIAG_TRACE_CORE_SHIM_INC) -I spp-diag-trace-core-src/include -I $(SPP_DIAG_TRACE_CORE_DIR)
SPP_DIAG_TRACE_CORE_HOST_SHA := test/spp-diag-trace-core-shim/host_sha256.c
SPP_DIAG_TRACE_CORE_HOST_VMALLOC := test/spp-diag-trace-core-shim/host_vmalloc.c
SPP_DIAG_TRACE_CORE_HOST_LIB := $(SPP_DIAG_TRACE_CORE_HOST_SHA) $(SPP_DIAG_TRACE_CORE_HOST_VMALLOC)
SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB := $(SPP_DIAG_TRACE_CORE_HOST_LIB) test/spp-diag-trace-core-shim/host_bootstrap.c test/spp-diag-trace-core-shim/host_kmod.c test/spp-diag-trace-core-shim/host_ima.c test/spp-diag-trace-core-shim/host_securityfs.c
SPP_DIAG_TRACE_CORE_EXTRACT := conf_proc_spp_diag_trace_core_extract_constants.py
SPP_DIAG_TRACE_CORE_MANIFEST_PY := conf_proc_spp_diag_trace_core_manifest.py
SPP_DIAG_TRACE_CORE_MATERIALIZE := conf_proc_spp_diag_trace_core_materialize.py
SPP_DIAG_TRACE_CORE_REASONS := conf_proc_spp_diag_trace_core_materialize_reasons.py
SPP_DIAG_TRACE_CORE_HANDOFF := conf_proc_spp_diag_trace_core_handoff.py
SPP_DIAG_TRACE_CORE_TEST := test/conf-proc-spp-diag-trace-core-selftest.c
SPP_DIAG_TRACE_CORE_CAPS_TEST := test/conf-proc-spp-diag-trace-core-caps-selftest.c
SPP_DIAG_TRACE_CORE_RACE_TEST := test/conf-proc-spp-diag-trace-core-race-selftest.c
SPP_DIAG_TRACE_CORE_ORACLE_HARNESS := test/conf-proc-spp-diag-trace-core-oracle-harness.c
SPP_DIAG_TRACE_CORE_ORACLE := test/conf-proc-spp-diag-trace-core-oracle-selftest.py
SPP_DIAG_TRACE_CORE_FIELD_CLASSIFIER := test/conf-proc-spp-diag-trace-core-field-classifier.c
SPP_DIAG_TRACE_CORE_FIELD_ORACLE := test/conf-proc-spp-diag-trace-core-field-oracle.py
SPP_DIAG_TRACE_CORE_EXTRACT_TEST := test/conf-proc-spp-diag-trace-core-extract-selftest.py
SPP_DIAG_TRACE_CORE_MATERIALIZE_TEST := test/conf-proc-spp-diag-trace-core-materialize-selftest.py
SPP_DIAG_TRACE_CORE_HANDOFF_TEST := test/conf-proc-spp-diag-trace-core-handoff-selftest.py
SPP_DIAG_TRACE_CORE_SOURCE_WALK := test/conf-proc-spp-diag-trace-core-source-walk-selftest.py
SPP_DIAG_TRACE_CORE_CONTEXT_TEST := test/conf-proc-spp-diag-trace-core-context-selftest.c
SPP_DIAG_TRACE_CORE_CONTEXT_SOURCE := test/conf-proc-spp-diag-trace-core-context-source-selftest.py
SPP_DIAG_TRACE_CORE_CALLGRAPH := test/conf-proc-spp-diag-trace-core-callgraph-selftest.py
SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG := test/conf-proc-spp-diag-trace-core-callgraph-negative-fixtures.c
SPP_DIAG_TRACE_CORE_BOOTSTRAP_TEST := test/conf-proc-spp-diag-trace-core-bootstrap-selftest.c
SPP_DIAG_TRACE_CORE_BOOTSTRAP_KUNIT_TEST := test/conf-proc-spp-diag-trace-core-bootstrap-kunit-selftest.c
SPP_DIAG_TRACE_CORE_BOOTSTRAP_FIXTURE := test/conf-proc-spp-diag-trace-core-bootstrap-fixture.c
SPP_DIAG_TRACE_CORE_BOOTSTRAP_ORACLE := test/conf-proc-spp-diag-trace-core-bootstrap-oracle-selftest.py
SPP_DIAG_TRACE_CORE_RUNTIME_SRC := $(SPP_DIAG_TRACE_CORE_DIR)/runtime_state.c $(SPP_DIAG_TRACE_CORE_DIR)/runtime_fs.c
SPP_DIAG_TRACE_CORE_ADAPTER_SRC := $(SPP_DIAG_TRACE_CORE_DIR)/adapter.c
SPP_DIAG_TRACE_CORE_RUNTIME_TEST := test/conf-proc-spp-diag-trace-core-runtime-selftest.c
SPP_DIAG_TRACE_CORE_RUNTIME_LIFECYCLE_TEST := test/conf-proc-spp-diag-trace-core-runtime-lifecycle-selftest.c
SPP_DIAG_TRACE_CORE_RUNTIME_FS_TEST := test/conf-proc-spp-diag-trace-core-runtime-fs-selftest.c
SPP_DIAG_TRACE_CORE_RUNTIME_CAPS_TEST := test/conf-proc-spp-diag-trace-core-runtime-caps-selftest.c
SPP_DIAG_TRACE_CORE_RUNTIME_FAMILIES_FIXTURE := test/conf-proc-spp-diag-trace-core-runtime-families-fixture.c
SPP_DIAG_TRACE_CORE_RUNTIME_FAMILIES_ORACLE := test/conf-proc-spp-diag-trace-core-runtime-families-oracle-selftest.py
SPP_DIAG_TRACE_CORE_RUNTIME_AC2_FIXTURE := test/conf-proc-spp-diag-trace-core-runtime-ac2-fixture.c
SPP_DIAG_TRACE_CORE_RUNTIME_AC2_ORACLE := test/conf-proc-spp-diag-trace-core-runtime-ac2-oracle-selftest.py
SPP_DIAG_TRACE_CORE_RUNTIME_AC2_APPRAISER := test/conf-proc-spp-diag-trace-core-runtime-ac2-appraiser-check.py
SPP_DIAG_TRACE_CORE_RUNTIME_KUNIT_TEST := test/conf-proc-spp-diag-trace-core-runtime-kunit-selftest.c
SPP_DIAG_TRACE_CORE_RUNTIME_ADAPTER_OFF_FIXTURE := test/conf-proc-spp-diag-trace-core-runtime-adapter-off-fixture.c
SPP_DIAG_TRACE_CORE_RUNTIME_EXEC_LIFECYCLE_FIXTURE := test/conf-proc-spp-diag-trace-core-runtime-exec-lifecycle-fixture.c
SPP_DIAG_TRACE_CORE_RUNTIME_EXEC_LIFECYCLE_ORACLE := test/conf-proc-spp-diag-trace-core-runtime-exec-lifecycle-oracle-selftest.py
SPP_DIAG_TRACE_CORE_RUNTIME_INTERVAL_BOUNDARY_FIXTURE := test/conf-proc-spp-diag-trace-core-runtime-interval-boundary-fixture.c
SPP_DIAG_TRACE_CORE_RUNTIME_INTERVAL_BOUNDARY_ORACLE := test/conf-proc-spp-diag-trace-core-runtime-interval-boundary-oracle-selftest.py
SPP_DIAG_TRACE_CORE_RUNTIME_FILE_MAPPING_FIXTURE := test/conf-proc-spp-diag-trace-core-runtime-file-mapping-fixture.c
SPP_DIAG_TRACE_CORE_RUNTIME_FILE_MAPPING_ORACLE := test/conf-proc-spp-diag-trace-core-runtime-file-mapping-oracle-selftest.py
SPP_DIAG_TRACE_CORE_RUNTIME_NETWORK_FIXTURE := test/conf-proc-spp-diag-trace-core-runtime-network-fixture.c
SPP_DIAG_TRACE_CORE_RUNTIME_NETWORK_ORACLE := test/conf-proc-spp-diag-trace-core-runtime-network-oracle-selftest.py
SPP_DIAG_TRACE_CORE_RUNTIME_INTEGRATION_FIXTURE := test/conf-proc-spp-diag-trace-core-runtime-integration-fixture.c
SPP_DIAG_TRACE_CORE_RUNTIME_INTEGRATION_ORACLE := test/conf-proc-spp-diag-trace-core-runtime-integration-oracle-selftest.py
SPP_DIAG_TRACE_CORE_RUNTIME_MANIFEST_CI := test/conf-proc-spp-diag-trace-core-runtime-manifest-ci-selftest.py
SPP_DIAG_TRACE_CORE_ADAPTER_HOST_CFLAGS := $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 -DSPP_DIAG_TRACE_CORE_HOST_TEST=1 $(SPP_DIAG_TRACE_CORE_HOST_INC)
SPP_DIAG_TRACE_CORE_ADAPTER_HOST_LIB := $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_ADAPTER_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB)

.PHONY: install check test ci clean ratls-contract test-spp-diag-trace test-spp-diag-trace-oracle test-spp-diag-trace-chain test-spp-diag-trace-checkpoints test-spp-diag-trace-semantics test-spp-diag-trace-sanitized test-spp-diag-ima-replay test-spp-diag-attest-fixture test-spp-diag-attest test-spp-diag-pcr test-spp-diagbundle-protocol test-spp-diag-failure-terminal test-spp-diag-input-closure-manifest test-spp-diag-closure-audit test-spp-diag-runtime-build test-spp-diag-handoff test-spp-diag-controller test-spp-diag-gpu-evidence test-spp-diag-cuda-driver test-spp-diag-apparmor test-spp-diag-quote test-spp-diag-export test-spp-diag-trace-core test-spp-diag-trace-core-oracle test-spp-diag-trace-core-race test-spp-diag-trace-core-sanitized test-spp-diag-trace-core-materialize test-spp-diag-trace-core-handoff test-spp-diag-trace-core-source-walk test-spp-diag-trace-core-context test-spp-diag-trace-core-callgraph test-spp-diag-trace-core-bootstrap test-spp-diag-trace-core-bootstrap-sanitized test-spp-diag-trace-core-bootstrap-source-walk test-spp-diag-trace-core-bootstrap-kunit test-spp-diag-trace-core-bootstrap-callgraph test-spp-diag-trace-core-runtime test-spp-diag-trace-core-runtime-caps test-spp-diag-trace-core-runtime-sanitized test-spp-diag-trace-core-runtime-source-walk test-spp-diag-trace-core-runtime-kunit test-spp-diag-trace-core-runtime-callgraph test-spp-diag-trace-core-runtime-exact-sites test-spp-diag-trace-core-runtime-exec-lifecycle test-spp-diag-trace-core-runtime-interval-boundary test-spp-diag-trace-core-runtime-file-mapping test-spp-diag-trace-core-runtime-network test-spp-diag-trace-core-runtime-integration test-spp-diag-trace-core-runtime-manifest-ci

install:
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements.txt

check:
	$(PYTHON) -m compileall -q verifier.py ratls_contract.py ratls_collector.py ratls_gateway.py spp_health.py asr_shim.py strict_wav.py conf_proc_reasons.py conf_proc_json.py conf_proc_acl.py conf_proc_module_sig.py conf_proc_lock.py conf_proc_policy.py conf_proc_guard.py conf_proc_geometry.py conf_proc_build_images.py conf_proc_inspect_images.py conf_proc_tree_rules.py conf_proc_build_tree.py conf_proc_manifest.py conf_proc_build_manifest.py conf_proc_inspect_manifest.py conf_proc_sbom.py conf_proc_build_sbom.py conf_proc_inspect_sbom.py conf_proc_inspect_provenance.py conf_proc_inspect_provenance_cli.py conf_proc_provenance_v2.py conf_proc_provenance_render.py conf_proc_provenance_v2_spdx.py conf_proc_provenance_v2_build_spdx.py conf_proc_provenance_v2_manifest.py conf_proc_provenance_v2_build_manifest.py conf_proc_provenance_v2_assemble.py conf_proc_module_authority.py conf_proc_build_modules.py conf_proc_elf.py conf_proc_unit_parser.py conf_proc_build_graph.py conf_proc_inspect_graph.py conf_proc_graph_compare.py conf_proc_guard_setup.py conf_proc_promote.py conf_proc_build.py conf_proc_inspect.py conf_proc_prohibited.py conf_proc_spp_boot_payload.py conf_proc_spp_boot_payload_inspect.py test/conf_proc_spp_boot_payload_fixture.py test/python-verifier-selftest.py test/fake-ratls-collector.py test/ratls-gateway-selftest.py test/spp-health-selftest.py test/asr-shim-selftest.py test/conf-proc-format-selftest.py test/conf-proc-guard-selftest.py test/conf-proc-image-selftest.py test/conf-proc-tree-selftest.py test/conf-proc-manifest-selftest.py test/conf-proc-sbom-selftest.py test/conf-proc-provenance-oracle-selftest.py test/conf-proc-provenance-v2-selftest.py test/conf-proc-provenance-render-selftest.py test/conf-proc-provenance-native-kat-selftest.py test/conf-proc-provenance-independence-selftest.py test/conf-proc-provenance-v2-spdx-selftest.py test/conf-proc-provenance-v2-manifest-selftest.py test/conf-proc-provenance-v2-producer-kat-selftest.py test/conf-proc-provenance-v2-assemble-e2e-selftest.py test/conf-proc-provenance-v2-assemble-inputs-selftest.py test/conf-proc-provenance-v2-assemble-native-selftest.py test/conf-proc-provenance-v2-assemble-tree-selftest.py test/conf-proc-provenance-v2-assemble-graph-selftest.py test/conf-proc-provenance-v2-assemble-modules-selftest.py test/conf-proc-provenance-v2-assemble-documents-selftest.py test/conf-proc-provenance-v2-assemble-exposure-selftest.py test/conf-proc-module-selftest.py test/conf-proc-graph-selftest.py test/conf-proc-e2e-selftest.py test/conf-proc-prohibited-selftest.py conf_proc_provenance_v2_inspect.py conf_proc_provenance_v2_inspect_documents.py conf_proc_provenance_v2_inspect_surface.py test/conf_proc_provenance_v2_inspect_fixture.py test/conf-proc-provenance-v2-inspect-e2e-selftest.py test/conf-proc-provenance-v2-inspect-inputs-selftest.py test/conf-proc-provenance-v2-inspect-bundle-native-selftest.py test/conf-proc-provenance-v2-inspect-images-tree-selftest.py test/conf-proc-provenance-v2-inspect-surface-graph-selftest.py test/conf-proc-provenance-v2-inspect-documents-sealed-selftest.py test/conf-proc-provenance-v2-inspect-faults-selftest.py conf_proc_spp_boot.py test/conf-proc-spp-boot-selftest.py test/conf-proc-spp-boot-v2-selftest.py test/conf-proc-spp-boot-v2-oracle-selftest.py test/conf-proc-spp-boot-payload-selftest.py test/conf-proc-spp-boot-payload-independent-selftest.py conf_proc_spp_reasons_v3.py conf_proc_spp_init.py conf_proc_spp_boot_v3_tables.py conf_proc_spp_boot_v3_wire.py conf_proc_spp_boot_v3_resource.py conf_proc_spp_boot_v3.py conf_proc_spp_boot_dispatch_v3.py conf_proc_spp_boot_payload_v3.py conf_proc_spp_boot_payload_v3_inspect.py test/conf_proc_spp_boot_payload_v3_fixture.py test/conf-proc-spp-boot-v3-wire-selftest.py test/conf-proc-spp-boot-v3-resource-selftest.py test/conf-proc-spp-boot-v3-selftest.py test/conf-proc-spp-boot-v3-oracle-selftest.py test/conf-proc-spp-boot-v3-executable-graph-oracle-selftest.py test/conf-proc-spp-boot-payload-v3-selftest.py test/conf-proc-spp-boot-payload-v3-independent-selftest.py conf_proc_spp_boot_v3_semantics.py test/conf_proc_spp_boot_v3_fixture.py test/conf-proc-spp-boot-v3-launch-selftest.py test/conf_proc_spp_boot_v3_readiness_oracle.py test/conf-proc-spp-boot-v3-readiness-selftest.py test/conf_proc_spp_boot_v3_resume_oracle.py test/conf-proc-spp-boot-v3-resume-selftest.py test/conf-proc-spp-boot-v3-controller-selftest.py test/conf-proc-spp-boot-v3-controller-source-oracle-selftest.py test/conf-proc-spp-boot-v3-predicate5-selftest.py test/conf-proc-spp-boot-v3-binding-integrity-selftest.py conf_proc_spp_diagbundle_reasons.py conf_proc_spp_diagbundle_stream.py conf_proc_spp_diagbundle_pe.py conf_proc_spp_diagbundle.py conf_proc_spp_diagbundle_cli.py test/conf_proc_spp_diagbundle_oracle.py test/conf-proc-spp-diagbundle-stream-selftest.py test/conf-proc-spp-diagbundle-pe-selftest.py test/conf-proc-spp-diagbundle-oracle-selftest.py test/conf-proc-spp-diagbundle-selftest.py $(SPP_DIAG_TRACE_ORACLE) $(SPP_DIAG_TRACE_CHAIN_SRC) $(SPP_DIAG_TRACE_CHAIN_VECTORS) $(SPP_DIAG_TRACE_CHAIN_ORACLE) $(SPP_DIAG_TRACE_CHAIN_TEST) $(SPP_DIAG_TRACE_CHECKPOINT_SRC) $(SPP_DIAG_TRACE_CHECKPOINT_VECTORS) $(SPP_DIAG_TRACE_CHECKPOINT_ORACLE) $(SPP_DIAG_TRACE_CHECKPOINT_TEST) $(SPP_DIAG_TRACE_SEMANTIC_REASONS) $(SPP_DIAG_TRACE_SEMANTICS_SRC) $(SPP_DIAG_TRACE_SEMANTICS_FIXTURE) $(SPP_DIAG_TRACE_SEMANTICS_ORACLE_SRC) $(SPP_DIAG_TRACE_SEMANTICS_ORACLE) $(SPP_DIAG_TRACE_SEMANTICS_TEST) $(SPP_DIAG_IMA_REASONS) $(SPP_DIAG_IMA_SRC) $(SPP_DIAG_IMA_FIXTURE) $(SPP_DIAG_IMA_ORACLE) $(SPP_DIAG_IMA_TEST) $(SPP_DIAG_ATTEST_FIXTURE) $(SPP_DIAG_ATTEST_FIXTURE_TEST) $(SPP_DIAG_ATTEST_REASONS) $(SPP_DIAG_ATTEST_SRC) $(SPP_DIAG_ATTEST_ORACLE) $(SPP_DIAG_ATTEST_TEST) conf_proc_spp_diag_pcr.py conf_proc_spp_diagbundle_protocol.py test/conf-proc-spp-diag-pcr-selftest.py test/conf-proc-spp-diagbundle-protocol-selftest.py conf_proc_spp_diag_failure_terminal_reasons.py test/conf-proc-spp-diag-failure-terminal-selftest.py conf_proc_spp_diag_input_closure_manifest_reasons.py conf_proc_spp_diag_input_closure_manifest.py test/conf-proc-spp-diag-input-closure-manifest-selftest.py conf_proc_spp_diag_closure_audit_reasons.py conf_proc_spp_diag_closure_audit.py test/conf-proc-spp-diag-closure-audit-selftest.py conf_proc_spp_diag_runtime_build_reasons.py conf_proc_spp_diag_runtime_build.py test/conf-proc-spp-diag-runtime-build-selftest.py test/conf-proc-spp-diag-handoff-oracle-selftest.py conf_proc_spp_diag_controller.py test/conf-proc-spp-diag-controller-selftest.py conf_proc_spp_diag_gpu_evidence.py test/conf-proc-spp-diag-gpu-evidence-selftest.py test/conf-proc-spp-diag-cuda-driver-oracle-selftest.py test/conf-proc-spp-diag-apparmor-selftest.py conf_proc_spp_diag_quote.py test/conf-proc-spp-diag-quote-selftest.py conf_proc_spp_diag_export_reasons.py conf_proc_spp_diag_export.py test/conf-proc-spp-diag-export-selftest.py $(SPP_DIAG_TRACE_CORE_EXTRACT) $(SPP_DIAG_TRACE_CORE_MANIFEST_PY) $(SPP_DIAG_TRACE_CORE_MATERIALIZE) $(SPP_DIAG_TRACE_CORE_REASONS) $(SPP_DIAG_TRACE_CORE_HANDOFF) $(SPP_DIAG_TRACE_CORE_EXTRACT_TEST) $(SPP_DIAG_TRACE_CORE_ORACLE) $(SPP_DIAG_TRACE_CORE_FIELD_ORACLE) $(SPP_DIAG_TRACE_CORE_CONTEXT_SOURCE) $(SPP_DIAG_TRACE_CORE_CALLGRAPH) $(SPP_DIAG_TRACE_CORE_MATERIALIZE_TEST) $(SPP_DIAG_TRACE_CORE_HANDOFF_TEST) $(SPP_DIAG_TRACE_CORE_SOURCE_WALK) $(SPP_DIAG_TRACE_CORE_RUNTIME_FAMILIES_ORACLE) $(SPP_DIAG_TRACE_CORE_RUNTIME_AC2_ORACLE) $(SPP_DIAG_TRACE_CORE_RUNTIME_AC2_APPRAISER)
	$(PYTHON) ratls_contract.py check
	bash -n run-collector.sh

test:
	$(PYTHON) test/python-verifier-selftest.py
	$(PYTHON) test/ratls-gateway-selftest.py
	$(PYTHON) test/spp-health-selftest.py
	$(PYTHON) test/asr-shim-selftest.py
	$(PYTHON) test/conf-proc-format-selftest.py
	$(PYTHON) test/conf-proc-guard-selftest.py
	$(PYTHON) test/conf-proc-image-selftest.py
	$(PYTHON) test/conf-proc-tree-selftest.py
	$(PYTHON) test/conf-proc-manifest-selftest.py
	$(PYTHON) test/conf-proc-sbom-selftest.py
	$(PYTHON) test/conf-proc-provenance-oracle-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-selftest.py
	$(PYTHON) test/conf-proc-provenance-render-selftest.py
	$(PYTHON) test/conf-proc-provenance-native-kat-selftest.py
	$(PYTHON) test/conf-proc-provenance-independence-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-spdx-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-manifest-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-producer-kat-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-assemble-e2e-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-assemble-inputs-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-assemble-native-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-assemble-tree-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-assemble-graph-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-assemble-modules-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-assemble-documents-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-assemble-exposure-selftest.py
	$(PYTHON) test/conf-proc-module-selftest.py
	$(PYTHON) test/conf-proc-graph-selftest.py
	$(PYTHON) test/conf-proc-e2e-selftest.py
	$(PYTHON) test/conf-proc-prohibited-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-inspect-e2e-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-inspect-inputs-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-inspect-bundle-native-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-inspect-images-tree-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-inspect-surface-graph-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-inspect-documents-sealed-selftest.py
	$(PYTHON) test/conf-proc-provenance-v2-inspect-faults-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v2-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v2-oracle-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-payload-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-payload-independent-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-wire-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-resource-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-launch-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-readiness-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-resume-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-controller-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-controller-source-oracle-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-predicate5-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-binding-integrity-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-oracle-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-v3-executable-graph-oracle-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-payload-v3-selftest.py
	$(PYTHON) test/conf-proc-spp-boot-payload-v3-independent-selftest.py
	$(PYTHON) test/conf-proc-spp-diagbundle-oracle-selftest.py
	$(PYTHON) test/conf-proc-spp-diagbundle-stream-selftest.py
	$(PYTHON) test/conf-proc-spp-diagbundle-pe-selftest.py
	$(PYTHON) test/conf-proc-spp-diagbundle-selftest.py
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-pcr-selftest.py
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diagbundle-protocol-selftest.py
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-failure-terminal-selftest.py
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-input-closure-manifest-selftest.py
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-closure-audit-selftest.py
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-runtime-build-selftest.py
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-controller-selftest.py
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-gpu-evidence-selftest.py
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-quote-selftest.py
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-export-selftest.py

test-spp-diag-trace-chain:
	$(PYTHON) $(SPP_DIAG_TRACE_CHAIN_ORACLE)
	PYTHONPATH=. $(PYTHON) $(SPP_DIAG_TRACE_CHAIN_TEST)

test-spp-diag-trace-checkpoints:
	PYTHONPATH=.:test $(PYTHON) $(SPP_DIAG_TRACE_CHECKPOINT_ORACLE)
	PYTHONPATH=.:test $(PYTHON) $(SPP_DIAG_TRACE_CHECKPOINT_TEST)

test-spp-diag-trace-semantics:
	PYTHONPATH=.:test $(PYTHON) $(SPP_DIAG_TRACE_SEMANTICS_ORACLE)
	PYTHONPATH=.:test $(PYTHON) $(SPP_DIAG_TRACE_SEMANTICS_TEST)

test-spp-diag-ima-replay:
	PYTHONPATH=.:test $(PYTHON) $(SPP_DIAG_IMA_ORACLE)
	PYTHONPATH=.:test $(PYTHON) $(SPP_DIAG_IMA_TEST)

test-spp-diag-attest-fixture:
	PYTHONPATH=.:test $(PYTHON) $(SPP_DIAG_ATTEST_FIXTURE_TEST)

test-spp-diag-attest:
	PYTHONPATH=.:test $(PYTHON) $(SPP_DIAG_ATTEST_FIXTURE_TEST)
	PYTHONPATH=.:test $(PYTHON) $(SPP_DIAG_ATTEST_ORACLE)
	PYTHONPATH=.:test $(PYTHON) $(SPP_DIAG_ATTEST_TEST)

test-spp-diag-pcr:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-pcr-selftest.py

test-spp-diagbundle-protocol:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diagbundle-protocol-selftest.py

test-spp-diag-failure-terminal:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-failure-terminal-selftest.py

test-spp-diag-input-closure-manifest:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-input-closure-manifest-selftest.py

test-spp-diag-closure-audit:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-closure-audit-selftest.py

test-spp-diag-runtime-build:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-runtime-build-selftest.py

test-spp-diag-handoff:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-handoff-oracle-selftest.py

test-spp-diag-controller:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-controller-selftest.py

test-spp-diag-gpu-evidence:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-gpu-evidence-selftest.py

test-spp-diag-cuda-driver:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-cuda-driver-oracle-selftest.py

test-spp-diag-apparmor:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-apparmor-selftest.py

test-spp-diag-quote:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-quote-selftest.py

test-spp-diag-export:
	PYTHONPATH=. $(PYTHON) test/conf-proc-spp-diag-export-selftest.py

test-spp-diag-trace:
	mkdir -p build
	$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_TEST) $(SPP_DIAG_TRACE_FRAME_TEST) $(SPP_DIAG_TRACE_STREAM_TEST) -o build/spp-diag-trace-selftest
	./build/spp-diag-trace-selftest
	$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_PROVENANCE_TEST) -o build/spp-diag-trace-provenance-selftest
	./build/spp-diag-trace-provenance-selftest
	rm -f build/spp-diag-trace-selftest build/spp-diag-trace-provenance-selftest
	$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_FILE_POLICY_TEST) -o build/spp-diag-trace-file-policy-decision-selftest
	./build/spp-diag-trace-file-policy-decision-selftest
	rm -f build/spp-diag-trace-file-policy-decision-selftest
	$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_EXEC_MAPPING_TEST) -o build/spp-diag-trace-exec-mapping-policy-decision-selftest
	./build/spp-diag-trace-exec-mapping-policy-decision-selftest
	rm -f build/spp-diag-trace-exec-mapping-policy-decision-selftest
	$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_NETWORK_POLICY_TEST) -o build/spp-diag-trace-network-policy-decision-selftest
	./build/spp-diag-trace-network-policy-decision-selftest
	rm -f build/spp-diag-trace-network-policy-decision-selftest
	$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_OPERATION_RETURN_TEST) -o build/spp-diag-trace-operation-return-selftest
	./build/spp-diag-trace-operation-return-selftest
	rm -f build/spp-diag-trace-operation-return-selftest
	$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_TASK_EXIT_TEST) -o build/spp-diag-trace-task-exit-selftest
	./build/spp-diag-trace-task-exit-selftest
	rm -f build/spp-diag-trace-task-exit-selftest
	$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_POLICY2_TEST) -o build/spp-diag-trace-policy2-selftest
	./build/spp-diag-trace-policy2-selftest
	rm -f build/spp-diag-trace-policy2-selftest

test-spp-diag-trace-oracle:
	mkdir -p build
	$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_ORACLE_HARNESS) -o build/spp-diag-trace-oracle-harness
	$(PYTHON) $(SPP_DIAG_TRACE_ORACLE) build/spp-diag-trace-oracle-harness
	rm -f build/spp-diag-trace-oracle-harness

test-spp-diag-trace-sanitized:
	mkdir -p build
	$(CC) $(C11FLAGS) -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_TEST) $(SPP_DIAG_TRACE_FRAME_TEST) $(SPP_DIAG_TRACE_STREAM_TEST) -o build/spp-diag-trace-selftest-sanitized
	./build/spp-diag-trace-selftest-sanitized
	$(CC) $(C11FLAGS) -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_PROVENANCE_TEST) -o build/spp-diag-trace-provenance-selftest-sanitized
	./build/spp-diag-trace-provenance-selftest-sanitized
	rm -f build/spp-diag-trace-selftest-sanitized build/spp-diag-trace-provenance-selftest-sanitized
	$(CC) $(C11FLAGS) -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_FILE_POLICY_TEST) -o build/spp-diag-trace-file-policy-decision-selftest-sanitized
	./build/spp-diag-trace-file-policy-decision-selftest-sanitized
	rm -f build/spp-diag-trace-file-policy-decision-selftest-sanitized
	$(CC) $(C11FLAGS) -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_EXEC_MAPPING_TEST) -o build/spp-diag-trace-exec-mapping-policy-decision-selftest-sanitized
	./build/spp-diag-trace-exec-mapping-policy-decision-selftest-sanitized
	rm -f build/spp-diag-trace-exec-mapping-policy-decision-selftest-sanitized
	$(CC) $(C11FLAGS) -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_NETWORK_POLICY_TEST) -o build/spp-diag-trace-network-policy-decision-selftest-sanitized
	./build/spp-diag-trace-network-policy-decision-selftest-sanitized
	rm -f build/spp-diag-trace-network-policy-decision-selftest-sanitized
	$(CC) $(C11FLAGS) -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_OPERATION_RETURN_TEST) -o build/spp-diag-trace-operation-return-selftest-sanitized
	./build/spp-diag-trace-operation-return-selftest-sanitized
	rm -f build/spp-diag-trace-operation-return-selftest-sanitized
	$(CC) $(C11FLAGS) -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_TASK_EXIT_TEST) -o build/spp-diag-trace-task-exit-selftest-sanitized
	./build/spp-diag-trace-task-exit-selftest-sanitized
	rm -f build/spp-diag-trace-task-exit-selftest-sanitized
	$(CC) $(C11FLAGS) -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_POLICY2_TEST) -o build/spp-diag-trace-policy2-selftest-sanitized
	./build/spp-diag-trace-policy2-selftest-sanitized
	rm -f build/spp-diag-trace-policy2-selftest-sanitized

test-spp-diag-trace-core:
	mkdir -p build
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_EXTRACT) build/protocol_constants.h.regen
	cmp $(SPP_DIAG_TRACE_CORE_CONSTANTS) build/protocol_constants.h.regen
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_EXTRACT_TEST)
	$(CC) $(CORE_CFLAGS) $(SPP_DIAG_TRACE_CORE_HOST_INC) -c $(SPP_DIAG_TRACE_CORE_SRC) -o build/spp-diag-trace-core.o
	if nm build/spp-diag-trace-core.o | grep -Ei 'reset|inject_fault|inject_init_fault|pre_lock_barrier|set_op_caps|snapshot|test_checked_add_u64'; then echo "KUnit seam present in non-KUnit object"; exit 1; fi
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_HOST_LIB) $(SPP_DIAG_TRACE_CORE_TEST) -o build/spp-diag-trace-core-selftest
	./build/spp-diag-trace-core-selftest
	rm -f build/spp-diag-trace-core-selftest
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_HOST_LIB) $(SPP_DIAG_TRACE_CORE_CAPS_TEST) -o build/spp-diag-trace-core-caps-selftest
	./build/spp-diag-trace-core-caps-selftest
	rm -f build/spp-diag-trace-core-caps-selftest

test-spp-diag-trace-core-oracle:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_HOST_LIB) $(SPP_DIAG_TRACE_CORE_ORACLE_HARNESS) -o build/spp-diag-trace-core-oracle-harness
	$(CC) $(C11FLAGS) $(SPP_DIAG_TRACE_SRC) $(SPP_DIAG_TRACE_CORE_FIELD_CLASSIFIER) -o build/spp-diag-trace-core-field-classifier
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_ORACLE) build/spp-diag-trace-core-oracle-harness
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_FIELD_ORACLE) build/spp-diag-trace-core-field-classifier build/spp-diag-trace-core-oracle-harness
	rm -f build/spp-diag-trace-core-oracle-harness build/spp-diag-trace-core-field-classifier

test-spp-diag-trace-core-race:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RACE_TEST) -o build/spp-diag-trace-core-race-selftest
	./build/spp-diag-trace-core-race-selftest
	rm -f build/spp-diag-trace-core-race-selftest
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DSPP_DIAG_TRACE_CORE_NOP_LOCK=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RACE_TEST) -o build/spp-diag-trace-core-race-selftest-neg
	./build/spp-diag-trace-core-race-selftest-neg
	rm -f build/spp-diag-trace-core-race-selftest-neg

test-spp-diag-trace-core-sanitized:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_HOST_LIB) $(SPP_DIAG_TRACE_CORE_TEST) -o build/spp-diag-trace-core-selftest-sanitized
	./build/spp-diag-trace-core-selftest-sanitized
	rm -f build/spp-diag-trace-core-selftest-sanitized
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_HOST_LIB) $(SPP_DIAG_TRACE_CORE_CAPS_TEST) -o build/spp-diag-trace-core-caps-selftest-sanitized
	./build/spp-diag-trace-core-caps-selftest-sanitized
	rm -f build/spp-diag-trace-core-caps-selftest-sanitized
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_HOST_LIB) $(SPP_DIAG_TRACE_CORE_ORACLE_HARNESS) -o build/spp-diag-trace-core-oracle-harness-sanitized
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_ORACLE) build/spp-diag-trace-core-oracle-harness-sanitized
	rm -f build/spp-diag-trace-core-oracle-harness-sanitized
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RACE_TEST) -o build/spp-diag-trace-core-race-selftest-sanitized
	./build/spp-diag-trace-core-race-selftest-sanitized
	rm -f build/spp-diag-trace-core-race-selftest-sanitized

test-spp-diag-trace-core-materialize:
	PYTHONPATH=. $(PYTHON) $(SPP_DIAG_TRACE_CORE_MATERIALIZE_TEST)

test-spp-diag-trace-core-handoff:
	PYTHONPATH=. $(PYTHON) $(SPP_DIAG_TRACE_CORE_HANDOFF_TEST)

test-spp-diag-trace-core-source-walk:
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_SOURCE_WALK)

test-spp-diag-trace-core-context:
	mkdir -p build
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_CONTEXT_SOURCE)
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_HOST_LIB) $(SPP_DIAG_TRACE_CORE_CONTEXT_TEST) -o build/spp-diag-trace-core-context-selftest
	./build/spp-diag-trace-core-context-selftest
	rm -f build/spp-diag-trace-core-context-selftest

test-spp-diag-trace-core-bootstrap:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_TEST) -o build/spp-diag-trace-core-bootstrap-selftest
	./build/spp-diag-trace-core-bootstrap-selftest
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_FIXTURE) -o build/spp-diag-trace-core-bootstrap-fixture
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_ORACLE) build/spp-diag-trace-core-bootstrap-fixture
	rm -f build/spp-diag-trace-core-bootstrap-selftest build/spp-diag-trace-core-bootstrap-fixture

test-spp-diag-trace-core-bootstrap-sanitized:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_TEST) -o build/spp-diag-trace-core-bootstrap-selftest-sanitized
	./build/spp-diag-trace-core-bootstrap-selftest-sanitized
	rm -f build/spp-diag-trace-core-bootstrap-selftest-sanitized

test-spp-diag-trace-core-bootstrap-source-walk:
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_SOURCE_WALK)

test-spp-diag-trace-core-bootstrap-kunit:
	mkdir -p build
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_SOURCE_WALK)
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DSPP_DIAG_TRACE_CORE_HOST_TEST=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_KUNIT_TEST) -o build/spp-diag-trace-core-bootstrap-kunit-selftest
	./build/spp-diag-trace-core-bootstrap-kunit-selftest
	rm -f build/spp-diag-trace-core-bootstrap-kunit-selftest

test-spp-diag-trace-core-bootstrap-callgraph:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -O0 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) -r $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) -o build/spp-diag-trace-core-bootstrap-callgraph.o
	$(CC) $(CORE_CFLAGS) -O0 $(SPP_DIAG_TRACE_CORE_HOST_INC) -c $(SPP_DIAG_TRACE_CORE_SRC) -o build/spp-diag-trace-core-callgraph.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_VMALLOC $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-vmalloc.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_SLEEP $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-sleep.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_MUTEX $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-mutex.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_ALT_LOCK $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-alt-lock.o
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_CALLGRAPH) build/spp-diag-trace-core-callgraph.o build/spp-diag-trace-core-callgraph-neg-vmalloc.o build/spp-diag-trace-core-callgraph-neg-sleep.o build/spp-diag-trace-core-callgraph-neg-mutex.o build/spp-diag-trace-core-callgraph-neg-alt-lock.o build/spp-diag-trace-core-bootstrap-callgraph.o
	rm -f build/spp-diag-trace-core-bootstrap-callgraph.o build/spp-diag-trace-core-callgraph.o build/spp-diag-trace-core-callgraph-neg-vmalloc.o build/spp-diag-trace-core-callgraph-neg-sleep.o build/spp-diag-trace-core-callgraph-neg-mutex.o build/spp-diag-trace-core-callgraph-neg-alt-lock.o

test-spp-diag-trace-core-callgraph:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -O0 $(SPP_DIAG_TRACE_CORE_HOST_INC) -c $(SPP_DIAG_TRACE_CORE_SRC) -o build/spp-diag-trace-core-callgraph.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_VMALLOC $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-vmalloc.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_SLEEP $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-sleep.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_MUTEX $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-mutex.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_ALT_LOCK $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-alt-lock.o
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_CALLGRAPH) build/spp-diag-trace-core-callgraph.o build/spp-diag-trace-core-callgraph-neg-vmalloc.o build/spp-diag-trace-core-callgraph-neg-sleep.o build/spp-diag-trace-core-callgraph-neg-mutex.o build/spp-diag-trace-core-callgraph-neg-alt-lock.o
	rm -f build/spp-diag-trace-core-callgraph.o build/spp-diag-trace-core-callgraph-neg-vmalloc.o build/spp-diag-trace-core-callgraph-neg-sleep.o build/spp-diag-trace-core-callgraph-neg-mutex.o build/spp-diag-trace-core-callgraph-neg-alt-lock.o

test-spp-diag-trace-core-runtime:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) -c $(SPP_DIAG_TRACE_CORE_SRC) -o build/spp-diag-trace-core-k3off.o
	nm build/spp-diag-trace-core-k3off.o | grep -q ' spp_diag_trace_core_append$$'
	! nm build/spp-diag-trace-core-k3off.o | grep -q ' spp_diag_trace_core_append_gated$$'
	$(CC) $(CORE_CFLAGS) -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) -c $(SPP_DIAG_TRACE_CORE_SRC) -o build/spp-diag-trace-core-k3on.o
	! nm build/spp-diag-trace-core-k3on.o | grep -Eq ' spp_diag_trace_core_append(_gated)?$$'
	! nm build/spp-diag-trace-core-k3on.o | grep -Eq ' spp_diag_trace_core_runtime_(open|close)_operation$$'
	if nm build/spp-diag-trace-core-k3on.o | grep -Ei 'reset|inject_fault|inject_init_fault|pre_lock_barrier|set_op_caps|snapshot|test_checked_add_u64|test_get_task_record|test_get_op_record|set_read_copy_hook'; then echo "KUnit seam present in non-KUnit object"; exit 1; fi
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_TEST) -o build/spp-diag-trace-core-runtime-selftest
	./build/spp-diag-trace-core-runtime-selftest
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_LIFECYCLE_TEST) -o build/spp-diag-trace-core-runtime-lifecycle-selftest
	./build/spp-diag-trace-core-runtime-lifecycle-selftest
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_FS_TEST) -o build/spp-diag-trace-core-runtime-fs-selftest
	./build/spp-diag-trace-core-runtime-fs-selftest
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 -DSPP_DIAG_TRACE_CORE_OP_MAX_FRAMES=131072 -DSPP_DIAG_TRACE_CORE_OP_MAX_STREAM_BYTES=16777216 -DSPP_DIAG_TRACE_RUNTIME_OP_MAX_TASKS=4096 -DSPP_DIAG_TRACE_RUNTIME_OP_MAX_OPERATIONS=32768 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_CAPS_TEST) -o build/spp-diag-trace-core-runtime-caps-selftest
	./build/spp-diag-trace-core-runtime-caps-selftest
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_FAMILIES_FIXTURE) -o build/spp-diag-trace-core-runtime-families-fixture
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_RUNTIME_FAMILIES_ORACLE) build/spp-diag-trace-core-runtime-families-fixture
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_AC2_FIXTURE) -o build/spp-diag-trace-core-runtime-ac2-fixture
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_RUNTIME_AC2_ORACLE) build/spp-diag-trace-core-runtime-ac2-fixture
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_RUNTIME_AC2_APPRAISER) build/spp-diag-trace-core-runtime-ac2-fixture
	rm -f build/spp-diag-trace-core-k3off.o build/spp-diag-trace-core-k3on.o build/spp-diag-trace-core-runtime-selftest build/spp-diag-trace-core-runtime-lifecycle-selftest build/spp-diag-trace-core-runtime-fs-selftest build/spp-diag-trace-core-runtime-caps-selftest build/spp-diag-trace-core-runtime-families-fixture build/spp-diag-trace-core-runtime-ac2-fixture

test-spp-diag-trace-core-runtime-caps:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 -DSPP_DIAG_TRACE_CORE_OP_MAX_FRAMES=131072 -DSPP_DIAG_TRACE_CORE_OP_MAX_STREAM_BYTES=16777216 -DSPP_DIAG_TRACE_RUNTIME_OP_MAX_TASKS=4096 -DSPP_DIAG_TRACE_RUNTIME_OP_MAX_OPERATIONS=32768 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_CAPS_TEST) -o build/spp-diag-trace-core-runtime-caps-selftest
	./build/spp-diag-trace-core-runtime-caps-selftest
	rm -f build/spp-diag-trace-core-runtime-caps-selftest

test-spp-diag-trace-core-runtime-sanitized:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_TEST) -o build/spp-diag-trace-core-runtime-selftest-sanitized
	./build/spp-diag-trace-core-runtime-selftest-sanitized
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_LIFECYCLE_TEST) -o build/spp-diag-trace-core-runtime-lifecycle-selftest-sanitized
	./build/spp-diag-trace-core-runtime-lifecycle-selftest-sanitized
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 -fsanitize=address,undefined -g -fno-sanitize-recover=undefined $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_FS_TEST) -o build/spp-diag-trace-core-runtime-fs-selftest-sanitized
	./build/spp-diag-trace-core-runtime-fs-selftest-sanitized
	rm -f build/spp-diag-trace-core-runtime-selftest-sanitized build/spp-diag-trace-core-runtime-lifecycle-selftest-sanitized build/spp-diag-trace-core-runtime-fs-selftest-sanitized

test-spp-diag-trace-core-runtime-source-walk:
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_SOURCE_WALK)

test-spp-diag-trace-core-runtime-kunit:
	mkdir -p build
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_SOURCE_WALK)
	$(CC) $(CORE_CFLAGS) -pthread -DCONFIG_KUNIT=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 -DSPP_DIAG_TRACE_CORE_HOST_TEST=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_KUNIT_TEST) -o build/spp-diag-trace-core-runtime-kunit-selftest
	./build/spp-diag-trace-core-runtime-kunit-selftest
	rm -f build/spp-diag-trace-core-runtime-kunit-selftest

test-spp-diag-trace-core-runtime-callgraph:
	mkdir -p build
	$(CC) $(CORE_CFLAGS) -O0 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) -r $(SPP_DIAG_TRACE_CORE_BOOTSTRAP_SRC) -o build/spp-diag-trace-core-bootstrap-callgraph.o
	$(CC) $(CORE_CFLAGS) -O0 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) -r $(SPP_DIAG_TRACE_CORE_SRC) $(SPP_DIAG_TRACE_CORE_RUNTIME_SRC) -o build/spp-diag-trace-core-runtime-callgraph.o
	$(CC) $(CORE_CFLAGS) -O0 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_RUNTIME=1 -DSPP_DIAG_TRACE_CORE_HOST_TEST=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) -c $(SPP_DIAG_TRACE_CORE_ADAPTER_SRC) -o build/spp-diag-trace-core-adapter-callgraph.o
	$(CC) $(CORE_CFLAGS) -O0 $(SPP_DIAG_TRACE_CORE_HOST_INC) -c $(SPP_DIAG_TRACE_CORE_SRC) -o build/spp-diag-trace-core-callgraph.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_VMALLOC $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-vmalloc.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_SLEEP $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-sleep.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_MUTEX $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-mutex.o
	$(CC) $(CORE_CFLAGS) -O0 -c -DHIDE_ALT_LOCK $(SPP_DIAG_TRACE_CORE_CALLGRAPH_NEG) -o build/spp-diag-trace-core-callgraph-neg-alt-lock.o
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_CALLGRAPH) build/spp-diag-trace-core-callgraph.o build/spp-diag-trace-core-callgraph-neg-vmalloc.o build/spp-diag-trace-core-callgraph-neg-sleep.o build/spp-diag-trace-core-callgraph-neg-mutex.o build/spp-diag-trace-core-callgraph-neg-alt-lock.o build/spp-diag-trace-core-bootstrap-callgraph.o build/spp-diag-trace-core-runtime-callgraph.o build/spp-diag-trace-core-adapter-callgraph.o
	rm -f build/spp-diag-trace-core-bootstrap-callgraph.o build/spp-diag-trace-core-runtime-callgraph.o build/spp-diag-trace-core-adapter-callgraph.o build/spp-diag-trace-core-callgraph.o build/spp-diag-trace-core-callgraph-neg-vmalloc.o build/spp-diag-trace-core-callgraph-neg-sleep.o build/spp-diag-trace-core-callgraph-neg-mutex.o build/spp-diag-trace-core-callgraph-neg-alt-lock.o

test-spp-diag-trace-core-runtime-exact-sites:
	mkdir -p build
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_SOURCE_WALK)
	$(CC) $(CORE_CFLAGS) -DCONFIG_SECURITY_SPP_DIAG_TRACE_CORE_BOOTSTRAP=1 $(SPP_DIAG_TRACE_CORE_HOST_INC) -c $(SPP_DIAG_TRACE_CORE_RUNTIME_ADAPTER_OFF_FIXTURE) -o build/spp-diag-trace-core-runtime-adapter-off.o
	! nm -u build/spp-diag-trace-core-runtime-adapter-off.o | grep -q 'spp_diag_trace_adapter_'
	rm -f build/spp-diag-trace-core-runtime-adapter-off.o

test-spp-diag-trace-core-runtime-exec-lifecycle:
	mkdir -p build
	$(CC) $(SPP_DIAG_TRACE_CORE_ADAPTER_HOST_CFLAGS) $(SPP_DIAG_TRACE_CORE_ADAPTER_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_EXEC_LIFECYCLE_FIXTURE) -o build/spp-diag-trace-core-runtime-exec-lifecycle-fixture
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_RUNTIME_EXEC_LIFECYCLE_ORACLE) build/spp-diag-trace-core-runtime-exec-lifecycle-fixture
	rm -f build/spp-diag-trace-core-runtime-exec-lifecycle-fixture

test-spp-diag-trace-core-runtime-interval-boundary:
	mkdir -p build
	$(CC) $(SPP_DIAG_TRACE_CORE_ADAPTER_HOST_CFLAGS) $(SPP_DIAG_TRACE_CORE_ADAPTER_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_INTERVAL_BOUNDARY_FIXTURE) -o build/spp-diag-trace-core-runtime-interval-boundary-fixture
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_RUNTIME_INTERVAL_BOUNDARY_ORACLE) build/spp-diag-trace-core-runtime-interval-boundary-fixture
	rm -f build/spp-diag-trace-core-runtime-interval-boundary-fixture

test-spp-diag-trace-core-runtime-file-mapping:
	mkdir -p build
	$(CC) $(SPP_DIAG_TRACE_CORE_ADAPTER_HOST_CFLAGS) $(SPP_DIAG_TRACE_CORE_ADAPTER_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_FILE_MAPPING_FIXTURE) -o build/spp-diag-trace-core-runtime-file-mapping-fixture
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_RUNTIME_FILE_MAPPING_ORACLE) build/spp-diag-trace-core-runtime-file-mapping-fixture
	rm -f build/spp-diag-trace-core-runtime-file-mapping-fixture

test-spp-diag-trace-core-runtime-network:
	mkdir -p build
	$(CC) $(SPP_DIAG_TRACE_CORE_ADAPTER_HOST_CFLAGS) $(SPP_DIAG_TRACE_CORE_ADAPTER_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_NETWORK_FIXTURE) -o build/spp-diag-trace-core-runtime-network-fixture
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_RUNTIME_NETWORK_ORACLE) build/spp-diag-trace-core-runtime-network-fixture
	rm -f build/spp-diag-trace-core-runtime-network-fixture

test-spp-diag-trace-core-runtime-integration:
	mkdir -p build
	$(CC) $(SPP_DIAG_TRACE_CORE_ADAPTER_HOST_CFLAGS) $(SPP_DIAG_TRACE_CORE_ADAPTER_HOST_LIB) $(SPP_DIAG_TRACE_CORE_RUNTIME_INTEGRATION_FIXTURE) -o build/spp-diag-trace-core-runtime-integration-fixture
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_RUNTIME_INTEGRATION_ORACLE) build/spp-diag-trace-core-runtime-integration-fixture
	rm -f build/spp-diag-trace-core-runtime-integration-fixture

test-spp-diag-trace-core-runtime-manifest-ci:
	$(PYTHON) $(SPP_DIAG_TRACE_CORE_RUNTIME_MANIFEST_CI)

ci: check test test-spp-diag-trace test-spp-diag-trace-oracle test-spp-diag-trace-chain test-spp-diag-trace-checkpoints test-spp-diag-trace-semantics test-spp-diag-ima-replay test-spp-diag-attest test-spp-diag-pcr test-spp-diagbundle-protocol test-spp-diag-failure-terminal test-spp-diag-input-closure-manifest test-spp-diag-closure-audit test-spp-diag-runtime-build test-spp-diag-handoff test-spp-diag-controller test-spp-diag-gpu-evidence test-spp-diag-cuda-driver test-spp-diag-apparmor test-spp-diag-quote test-spp-diag-export test-spp-diag-trace-sanitized test-spp-diag-trace-core test-spp-diag-trace-core-oracle test-spp-diag-trace-core-race test-spp-diag-trace-core-materialize test-spp-diag-trace-core-handoff test-spp-diag-trace-core-source-walk test-spp-diag-trace-core-sanitized test-spp-diag-trace-core-context test-spp-diag-trace-core-callgraph test-spp-diag-trace-core-bootstrap test-spp-diag-trace-core-bootstrap-sanitized test-spp-diag-trace-core-bootstrap-source-walk test-spp-diag-trace-core-bootstrap-kunit test-spp-diag-trace-core-bootstrap-callgraph test-spp-diag-trace-core-runtime test-spp-diag-trace-core-runtime-caps test-spp-diag-trace-core-runtime-sanitized test-spp-diag-trace-core-runtime-source-walk test-spp-diag-trace-core-runtime-kunit test-spp-diag-trace-core-runtime-callgraph test-spp-diag-trace-core-runtime-exact-sites test-spp-diag-trace-core-runtime-exec-lifecycle test-spp-diag-trace-core-runtime-interval-boundary test-spp-diag-trace-core-runtime-file-mapping test-spp-diag-trace-core-runtime-network test-spp-diag-trace-core-runtime-integration test-spp-diag-trace-core-runtime-manifest-ci
	rm -rf build

ratls-contract:
	$(PYTHON) ratls_contract.py generate

clean:
	rm -rf __pycache__ test/__pycache__ .pytest_cache build
