PYTHON ?= python3
CC ?= cc
C11FLAGS := -std=c11 -Wall -Wextra -Werror -pedantic
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

.PHONY: install check test ci clean ratls-contract test-spp-diag-trace test-spp-diag-trace-oracle test-spp-diag-trace-chain test-spp-diag-trace-checkpoints test-spp-diag-trace-semantics test-spp-diag-trace-sanitized test-spp-diag-ima-replay

install:
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements.txt

check:
	$(PYTHON) -m compileall -q verifier.py ratls_contract.py ratls_collector.py ratls_gateway.py spp_health.py asr_shim.py strict_wav.py conf_proc_reasons.py conf_proc_json.py conf_proc_acl.py conf_proc_module_sig.py conf_proc_lock.py conf_proc_policy.py conf_proc_guard.py conf_proc_geometry.py conf_proc_build_images.py conf_proc_inspect_images.py conf_proc_tree_rules.py conf_proc_build_tree.py conf_proc_manifest.py conf_proc_build_manifest.py conf_proc_inspect_manifest.py conf_proc_sbom.py conf_proc_build_sbom.py conf_proc_inspect_sbom.py conf_proc_inspect_provenance.py conf_proc_inspect_provenance_cli.py conf_proc_provenance_v2.py conf_proc_provenance_render.py conf_proc_provenance_v2_spdx.py conf_proc_provenance_v2_build_spdx.py conf_proc_provenance_v2_manifest.py conf_proc_provenance_v2_build_manifest.py conf_proc_provenance_v2_assemble.py conf_proc_module_authority.py conf_proc_build_modules.py conf_proc_elf.py conf_proc_unit_parser.py conf_proc_build_graph.py conf_proc_inspect_graph.py conf_proc_graph_compare.py conf_proc_guard_setup.py conf_proc_promote.py conf_proc_build.py conf_proc_inspect.py conf_proc_prohibited.py conf_proc_spp_boot_payload.py conf_proc_spp_boot_payload_inspect.py test/conf_proc_spp_boot_payload_fixture.py test/python-verifier-selftest.py test/fake-ratls-collector.py test/ratls-gateway-selftest.py test/spp-health-selftest.py test/asr-shim-selftest.py test/conf-proc-format-selftest.py test/conf-proc-guard-selftest.py test/conf-proc-image-selftest.py test/conf-proc-tree-selftest.py test/conf-proc-manifest-selftest.py test/conf-proc-sbom-selftest.py test/conf-proc-provenance-oracle-selftest.py test/conf-proc-provenance-v2-selftest.py test/conf-proc-provenance-render-selftest.py test/conf-proc-provenance-native-kat-selftest.py test/conf-proc-provenance-independence-selftest.py test/conf-proc-provenance-v2-spdx-selftest.py test/conf-proc-provenance-v2-manifest-selftest.py test/conf-proc-provenance-v2-producer-kat-selftest.py test/conf-proc-provenance-v2-assemble-e2e-selftest.py test/conf-proc-provenance-v2-assemble-inputs-selftest.py test/conf-proc-provenance-v2-assemble-native-selftest.py test/conf-proc-provenance-v2-assemble-tree-selftest.py test/conf-proc-provenance-v2-assemble-graph-selftest.py test/conf-proc-provenance-v2-assemble-modules-selftest.py test/conf-proc-provenance-v2-assemble-documents-selftest.py test/conf-proc-provenance-v2-assemble-exposure-selftest.py test/conf-proc-module-selftest.py test/conf-proc-graph-selftest.py test/conf-proc-e2e-selftest.py test/conf-proc-prohibited-selftest.py conf_proc_provenance_v2_inspect.py conf_proc_provenance_v2_inspect_documents.py conf_proc_provenance_v2_inspect_surface.py test/conf_proc_provenance_v2_inspect_fixture.py test/conf-proc-provenance-v2-inspect-e2e-selftest.py test/conf-proc-provenance-v2-inspect-inputs-selftest.py test/conf-proc-provenance-v2-inspect-bundle-native-selftest.py test/conf-proc-provenance-v2-inspect-images-tree-selftest.py test/conf-proc-provenance-v2-inspect-surface-graph-selftest.py test/conf-proc-provenance-v2-inspect-documents-sealed-selftest.py test/conf-proc-provenance-v2-inspect-faults-selftest.py conf_proc_spp_boot.py test/conf-proc-spp-boot-selftest.py test/conf-proc-spp-boot-v2-selftest.py test/conf-proc-spp-boot-v2-oracle-selftest.py test/conf-proc-spp-boot-payload-selftest.py test/conf-proc-spp-boot-payload-independent-selftest.py conf_proc_spp_reasons_v3.py conf_proc_spp_init.py conf_proc_spp_boot_v3_tables.py conf_proc_spp_boot_v3_wire.py conf_proc_spp_boot_v3_resource.py conf_proc_spp_boot_v3.py conf_proc_spp_boot_dispatch_v3.py conf_proc_spp_boot_payload_v3.py conf_proc_spp_boot_payload_v3_inspect.py test/conf_proc_spp_boot_payload_v3_fixture.py test/conf-proc-spp-boot-v3-wire-selftest.py test/conf-proc-spp-boot-v3-resource-selftest.py test/conf-proc-spp-boot-v3-selftest.py test/conf-proc-spp-boot-v3-oracle-selftest.py test/conf-proc-spp-boot-v3-executable-graph-oracle-selftest.py test/conf-proc-spp-boot-payload-v3-selftest.py test/conf-proc-spp-boot-payload-v3-independent-selftest.py conf_proc_spp_boot_v3_semantics.py test/conf_proc_spp_boot_v3_fixture.py test/conf-proc-spp-boot-v3-launch-selftest.py test/conf_proc_spp_boot_v3_readiness_oracle.py test/conf-proc-spp-boot-v3-readiness-selftest.py test/conf_proc_spp_boot_v3_resume_oracle.py test/conf-proc-spp-boot-v3-resume-selftest.py test/conf-proc-spp-boot-v3-controller-selftest.py test/conf-proc-spp-boot-v3-controller-source-oracle-selftest.py test/conf-proc-spp-boot-v3-predicate5-selftest.py test/conf-proc-spp-boot-v3-binding-integrity-selftest.py conf_proc_spp_diagbundle_reasons.py conf_proc_spp_diagbundle_stream.py conf_proc_spp_diagbundle_pe.py conf_proc_spp_diagbundle.py conf_proc_spp_diagbundle_cli.py test/conf_proc_spp_diagbundle_oracle.py test/conf-proc-spp-diagbundle-stream-selftest.py test/conf-proc-spp-diagbundle-pe-selftest.py test/conf-proc-spp-diagbundle-oracle-selftest.py test/conf-proc-spp-diagbundle-selftest.py $(SPP_DIAG_TRACE_ORACLE) $(SPP_DIAG_TRACE_CHAIN_SRC) $(SPP_DIAG_TRACE_CHAIN_VECTORS) $(SPP_DIAG_TRACE_CHAIN_ORACLE) $(SPP_DIAG_TRACE_CHAIN_TEST) $(SPP_DIAG_TRACE_CHECKPOINT_SRC) $(SPP_DIAG_TRACE_CHECKPOINT_VECTORS) $(SPP_DIAG_TRACE_CHECKPOINT_ORACLE) $(SPP_DIAG_TRACE_CHECKPOINT_TEST) $(SPP_DIAG_TRACE_SEMANTIC_REASONS) $(SPP_DIAG_TRACE_SEMANTICS_SRC) $(SPP_DIAG_TRACE_SEMANTICS_FIXTURE) $(SPP_DIAG_TRACE_SEMANTICS_ORACLE_SRC) $(SPP_DIAG_TRACE_SEMANTICS_ORACLE) $(SPP_DIAG_TRACE_SEMANTICS_TEST) $(SPP_DIAG_IMA_REASONS) $(SPP_DIAG_IMA_SRC) $(SPP_DIAG_IMA_FIXTURE) $(SPP_DIAG_IMA_ORACLE) $(SPP_DIAG_IMA_TEST)
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

ci: check test test-spp-diag-trace test-spp-diag-trace-oracle test-spp-diag-trace-chain test-spp-diag-trace-checkpoints test-spp-diag-trace-semantics test-spp-diag-ima-replay test-spp-diag-trace-sanitized
	rm -rf build

ratls-contract:
	$(PYTHON) ratls_contract.py generate

clean:
	rm -rf __pycache__ test/__pycache__ .pytest_cache build
