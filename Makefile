PYTHON ?= python3

.PHONY: install check test ci clean

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	./test/build-check.sh selftest

check:
	$(PYTHON) -m compileall -q verifier.py test/python-verifier-selftest.py

ci: check test

clean:
	rm -rf __pycache__ test/__pycache__ .pytest_cache
