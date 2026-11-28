XU ?= xu
XU_STDLIB_ROOT ?= $(if $(wildcard ../xu/src/runtime/core),../xu/src,$(HOME)/.xu/src)
OUT ?= build/fatext-server

.PHONY: build build-linux-x64 preview test test-all clean

build:
	@mkdir -p build
	XU_STDLIB_ROOT=$(XU_STDLIB_ROOT) $(XU) build server -o $(OUT)
	@if [ "$$(uname -s)" = "Darwin" ]; then codesign -fs - $(OUT); fi

build-linux-x64:
	@mkdir -p build
	XU_STDLIB_ROOT=$(XU_STDLIB_ROOT) $(XU) build server --target linux-x64 -o build/fatext-server-linux-x64

preview:
	python3 scripts/build_preview.py

test: build preview
	python3 scripts/test_server_phase1.py
	python3 scripts/test_admin_and_stats.py
	python3 scripts/test_acme.py
	python3 scripts/test_security.py --without-cli
	python3 scripts/test_public_moderation.py
	python3 scripts/test_ctl_pair.py
	python3 scripts/stress_test.py --light

test-all: test
	python3 scripts/test_security.py
	python3 scripts/test_ctl_chain.py
	python3 scripts/test_docs_and_name.py
	python3 scripts/test_logging.py
	python3 scripts/test_rooms.py
	python3 scripts/test_server_phase2.py
	python3 scripts/test_full_e2e.py
	python3 scripts/test_perf_and_resilience.py

clean:
	rm -rf build/
