SHELL := /bin/bash

DEPENDENCIES := venv/dependencies.timestamp
PACKAGE := check_soa_serials
VENV := venv/venv.timestamp
VERSION := $(shell python3 -c 'import check_soa_serials; print(check_soa_serials.__version__)')
BUILD_DIR := dist_$(VERSION)
BUILD := $(BUILD_DIR)/.build.timestamp

all: static-analysis test

$(VENV):
	python3 -m venv venv
	. venv/bin/activate
	touch $(VENV)

$(DEPENDENCIES): $(VENV) requirements-make.txt requirements.txt
	# Install Python dependencies, runtime *and* test/build
	./venv/bin/python3 -m pip install --requirement requirements-make.txt
	./venv/bin/python3 -m pip install --requirement requirements.txt
	touch $(DEPENDENCIES)

.PHONY: static-analysis
static-analysis: $(DEPENDENCIES)
	# Lint
	pylint check_soa_serials/ tests/
	# Check typing
	mypy check_soa_serials/ tests/
	# Check style
	black --check check_soa_serials/ tests/
	# Hooray all good

.PHONY: test
test: $(DEPENDENCIES)
	pytest tests/

.PHONY: test-verbose
test-verbose: $(DEPENDENCIES)
	pytest  -rP -o log_cli=true --log-cli-level=10 tests/

.PHONY: fix
fix: $(DEPENDENCIES)
	# Enforce style with Black
	black check_soa_serials/
	black tests/

.PHONY: package
package: $(BUILD) static-analysis test

$(BUILD): $(DEPENDENCIES)
	# Build the package
	@if grep --extended-regexp "^ *(Documentation|Bug Tracker|Source|url) = *$$" "setup.cfg"; then \
		echo 'FAILURE: Please fully fill out the values for `Documentation`, `Bug Tracker`, `Source`, and `url` in `setup.cfg` before packaging' && \
		exit 1; \
		fi
	mkdir --parents $(BUILD_DIR)
	./venv/bin/python3 -m build --outdir $(BUILD_DIR)
	touch $(BUILD)

.PHONY: publish
publish: package
	@test $${TWINE_PASSWORD?Please set environment variable TWINE_PASSWORD in order to publish}
	./venv/bin/python3 -m twine upload --username __token__ $(BUILD_DIR)/*

.PHONY: publish-test
publish-test: package
	@test $${TWINE_PASSWORD?Please set environment variable TWINE_PASSWORD in order to publish}
	./venv/bin/python3 -m twine upload --repository testpypi --username __token__ $(BUILD_DIR)/*
