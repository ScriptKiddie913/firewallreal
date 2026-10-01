# SentinelGate & SentinelFW 3.0 Master Makefile
# Unified build, test, and lab automation

.PHONY: all build-gate build-cli build-bpf test test-python test-go lint lab-up lab-down lab-verify clean

SHELL := /bin/bash
BIN_DIR := bin
GO_SRC := $(shell find cmd pkg -name '*.go' 2>/dev/null)
BPF_SRC := $(wildcard bpf/*.c)

all: build-gate build-cli test

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# --- Go Binary Targets ---
build-gate: $(BIN_DIR)
	@echo "==> Building sentinelgated (Go Management Daemon)..."
	go build -trimpath -ldflags="-s -w -X main.Version=3.0.0-dev" -o $(BIN_DIR)/sentinelgated ./cmd/sentinelgated

build-cli: $(BIN_DIR)
	@echo "==> Building sfw (Unified CLI / TUI)..."
	go build -trimpath -ldflags="-s -w -X main.Version=3.0.0-dev" -o $(BIN_DIR)/sfw ./cmd/sfw

build-nftcompile: $(BIN_DIR)
	@echo "==> Building sfw-nftcompile (Declarative Ruleset Compiler)..."
	go build -trimpath -ldflags="-s -w -X main.Version=3.0.0-dev" -o $(BIN_DIR)/sfw-nftcompile ./cmd/sfw-nftcompile

# --- eBPF Targets ---
build-bpf:
	@echo "==> Compiling eBPF / XDP bytecode with Clang..."
	@which clang >/dev/null 2>&1 || (echo "Warning: clang not installed, skipping eBPF compilation." && exit 0)
	clang -O2 -g -Wall -target bpf -c bpf/xdp_prefilter.c -o $(BIN_DIR)/xdp_prefilter.o
	clang -O2 -g -Wall -target bpf -c bpf/sock_filter.c -o $(BIN_DIR)/sock_filter.o

# --- Testing Targets ---
test: test-python test-go

test-python:
	@echo "==> Running SentinelFW Python unit test suites (pytest)..."
	pytest tests/ -v

test-go:
	@echo "==> Running Go unit tests..."
	@which go >/dev/null 2>&1 || (echo "Notice: Go environment not configured on this host, skipping Go unit tests." && exit 0)
	go test -v -race -cover ./pkg/... ./cmd/...

lint:
	@echo "==> Running code linter checks..."
	@which go >/dev/null 2>&1 && go vet ./pkg/... ./cmd/...
	python scripts/check_release_hygiene.py

# --- Virtual Lab Automation Targets ---
lab-up:
	@echo "==> Deploying network namespaces virtual lab..."
	bash lab/setup_netns_lab.sh up

lab-down:
	@echo "==> Tearing down network namespaces virtual lab..."
	bash lab/setup_netns_lab.sh down

lab-verify:
	@echo "==> Executing automated lab verification..."
	python lab/verify_p0.py

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
