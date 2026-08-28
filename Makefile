PYTHON ?= python3

.PHONY: install check test ci clean ratls-contract

install:
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements.txt

check:
	$(PYTHON) -m compileall -q verifier.py ratls_contract.py ratls_collector.py ratls_gateway.py spp_health.py asr_shim.py strict_wav.py conf_proc_reasons.py conf_proc_json.py conf_proc_acl.py conf_proc_module_sig.py conf_proc_lock.py conf_proc_policy.py conf_proc_guard.py conf_proc_geometry.py conf_proc_build_images.py conf_proc_inspect_images.py conf_proc_tree_rules.py conf_proc_build_tree.py conf_proc_inspect_tree.py conf_proc_manifest.py conf_proc_build_manifest.py conf_proc_inspect_manifest.py conf_proc_sbom.py conf_proc_build_sbom.py conf_proc_inspect_sbom.py conf_proc_inspect_provenance.py conf_proc_inspect_provenance_cli.py conf_proc_provenance_v2.py conf_proc_provenance_render.py conf_proc_provenance_v2_spdx.py conf_proc_provenance_v2_build_spdx.py conf_proc_provenance_v2_manifest.py conf_proc_provenance_v2_build_manifest.py conf_proc_provenance_v2_assemble.py conf_proc_module_authority.py conf_proc_build_modules.py conf_proc_inspect_modules.py conf_proc_elf.py conf_proc_unit_parser.py conf_proc_build_graph.py conf_proc_inspect_graph.py conf_proc_graph_compare.py conf_proc_guard_setup.py conf_proc_promote.py conf_proc_build.py conf_proc_inspect.py conf_proc_prohibited.py test/python-verifier-selftest.py test/fake-ratls-collector.py test/ratls-gateway-selftest.py test/spp-health-selftest.py test/asr-shim-selftest.py test/conf-proc-format-selftest.py test/conf-proc-guard-selftest.py test/conf-proc-image-selftest.py test/conf-proc-tree-selftest.py test/conf-proc-manifest-selftest.py test/conf-proc-sbom-selftest.py test/conf-proc-provenance-oracle-selftest.py test/conf-proc-provenance-v2-selftest.py test/conf-proc-provenance-render-selftest.py test/conf-proc-provenance-native-kat-selftest.py test/conf-proc-provenance-independence-selftest.py test/conf-proc-provenance-v2-spdx-selftest.py test/conf-proc-provenance-v2-manifest-selftest.py test/conf-proc-provenance-v2-producer-kat-selftest.py test/conf-proc-provenance-v2-assemble-e2e-selftest.py test/conf-proc-provenance-v2-assemble-inputs-selftest.py test/conf-proc-provenance-v2-assemble-native-selftest.py test/conf-proc-provenance-v2-assemble-tree-selftest.py test/conf-proc-provenance-v2-assemble-graph-selftest.py test/conf-proc-provenance-v2-assemble-modules-selftest.py test/conf-proc-provenance-v2-assemble-documents-selftest.py test/conf-proc-provenance-v2-assemble-exposure-selftest.py test/conf-proc-module-selftest.py test/conf-proc-graph-selftest.py test/conf-proc-e2e-selftest.py test/conf-proc-prohibited-selftest.py conf_proc_provenance_v2_inspect.py conf_proc_provenance_v2_inspect_documents.py conf_proc_provenance_v2_inspect_surface.py test/conf_proc_provenance_v2_inspect_fixture.py test/conf-proc-provenance-v2-inspect-e2e-selftest.py test/conf-proc-provenance-v2-inspect-inputs-selftest.py test/conf-proc-provenance-v2-inspect-bundle-native-selftest.py test/conf-proc-provenance-v2-inspect-images-tree-selftest.py test/conf-proc-provenance-v2-inspect-surface-graph-selftest.py test/conf-proc-provenance-v2-inspect-documents-sealed-selftest.py test/conf-proc-provenance-v2-inspect-faults-selftest.py
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

ci: check test

ratls-contract:
	$(PYTHON) ratls_contract.py generate

clean:
	rm -rf __pycache__ test/__pycache__ .pytest_cache
