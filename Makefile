PYTHON ?= python3

.PHONY: install check test ci clean ratls-contract

install:
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements.txt

check:
	$(PYTHON) -m compileall -q verifier.py ratls_contract.py ratls_collector.py ratls_gateway.py spp_health.py asr_shim.py strict_wav.py conf_proc_reasons.py conf_proc_json.py conf_proc_acl.py conf_proc_module_sig.py conf_proc_lock.py conf_proc_policy.py conf_proc_guard.py conf_proc_geometry.py conf_proc_build_images.py conf_proc_inspect_images.py conf_proc_tree_rules.py conf_proc_build_tree.py conf_proc_inspect_tree.py conf_proc_manifest.py conf_proc_build_manifest.py conf_proc_inspect_manifest.py conf_proc_sbom.py conf_proc_build_sbom.py conf_proc_inspect_sbom.py conf_proc_module_authority.py conf_proc_build_modules.py conf_proc_inspect_modules.py conf_proc_elf.py conf_proc_unit_parser.py conf_proc_build_graph.py conf_proc_inspect_graph.py conf_proc_graph_compare.py conf_proc_guard_setup.py conf_proc_promote.py conf_proc_build.py conf_proc_inspect.py conf_proc_prohibited.py test/python-verifier-selftest.py test/fake-ratls-collector.py test/ratls-gateway-selftest.py test/spp-health-selftest.py test/asr-shim-selftest.py test/conf-proc-format-selftest.py test/conf-proc-guard-selftest.py test/conf-proc-image-selftest.py test/conf-proc-tree-selftest.py test/conf-proc-manifest-selftest.py test/conf-proc-sbom-selftest.py test/conf-proc-module-selftest.py test/conf-proc-graph-selftest.py test/conf-proc-e2e-selftest.py test/conf-proc-prohibited-selftest.py
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
	$(PYTHON) test/conf-proc-module-selftest.py
	$(PYTHON) test/conf-proc-graph-selftest.py
	$(PYTHON) test/conf-proc-e2e-selftest.py
	$(PYTHON) test/conf-proc-prohibited-selftest.py

ci: check test

ratls-contract:
	$(PYTHON) ratls_contract.py generate

clean:
	rm -rf __pycache__ test/__pycache__ .pytest_cache
