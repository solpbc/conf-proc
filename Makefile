PYTHON ?= python3

.PHONY: install check test ci clean ratls-contract

install:
	python3 -m venv .venv
	.venv/bin/python -m pip install -r requirements.txt

check:
	$(PYTHON) -m compileall -q verifier.py ratls_contract.py ratls_collector.py ratls_gateway.py spp_health.py asr_shim.py strict_wav.py conf_proc_reasons.py conf_proc_json.py conf_proc_acl.py conf_proc_module_sig.py conf_proc_lock.py conf_proc_policy.py conf_proc_guard.py conf_proc_geometry.py conf_proc_build_images.py conf_proc_inspect_images.py test/python-verifier-selftest.py test/fake-ratls-collector.py test/ratls-gateway-selftest.py test/spp-health-selftest.py test/asr-shim-selftest.py test/conf-proc-format-selftest.py test/conf-proc-guard-selftest.py test/conf-proc-image-selftest.py
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

ci: check test

ratls-contract:
	$(PYTHON) ratls_contract.py generate

clean:
	rm -rf __pycache__ test/__pycache__ .pytest_cache
