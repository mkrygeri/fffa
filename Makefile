# Enhanced Makefile for FFFA with remote eBPF development support

# Go build settings
GO_CMD=go
GO_BUILD=$(GO_CMD) build
GO_CLEAN=$(GO_CMD) clean
GO_TEST=$(GO_CMD) test
GO_GET=$(GO_CMD) get
BINARY_NAME=fffa
BINARY_UNIX=$(BINARY_NAME)_unix

# eBPF build settings
CLANG=clang
CFLAGS=-O2 -g -Wall -Werror
BPF_CFLAGS=$(CFLAGS) -target bpf -D__TARGET_ARCH_x86

.PHONY: all build clean test deps build-bpf setup-aws sync-remote

all: test build

build:
	$(GO_BUILD) -o $(BINARY_NAME) -v ./...

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO_BUILD) -o $(BINARY_UNIX) -v ./...

build-bpf:
	@echo "Building eBPF programs..."
	@if [ ! -f /usr/include/linux/bpf.h ]; then \
		echo "Error: Linux kernel headers not found. This must be run on a Linux system."; \
		echo "Use 'make setup-aws' to create a remote development environment."; \
		exit 1; \
	fi
	$(CLANG) $(BPF_CFLAGS) -c bpf/flow_monitor.c -o bpf/flow_monitor.o
	@echo "eBPF object file created: bpf/flow_monitor.o"

test:
	$(GO_TEST) -v ./...

clean:
	$(GO_CLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -f bpf/*.o

deps:
	$(GO_GET) github.com/cilium/ebpf@v0.19.0

# AWS remote development helpers
setup-aws:
	@echo "Setting up AWS EC2 development environment..."
	@chmod +x scripts/setup-aws-dev.sh
	@scripts/setup-aws-dev.sh

sync-remote:
	@if [ -z "$(REMOTE)" ]; then 
		echo "Usage: make sync-remote REMOTE=ec2-user@<instance-ip>"; 
		exit 1; 
	fi
	@chmod +x scripts/sync-to-remote.sh
	@scripts/sync-to-remote.sh $(REMOTE)

# Development workflow
dev-setup: deps
	@echo "Development environment ready"
	@echo "For eBPF development, run: make setup-aws"

# Install (requires sudo for eBPF capabilities)
install: build-bpf build-linux
	sudo cp $(BINARY_UNIX) /usr/local/bin/$(BINARY_NAME)
	sudo setcap cap_sys_admin,cap_net_admin,cap_bpf+ep /usr/local/bin/$(BINARY_NAME)

# Help target
help:
	@echo "Available targets:"
	@echo "  build        - Build Go binary for current platform"
	@echo "  build-linux  - Build Go binary for Linux"
	@echo "  build-bpf    - Build eBPF programs (Linux only)"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  deps         - Install Go dependencies"
	@echo "  setup-aws    - Setup AWS EC2 development environment"
	@echo "  sync-remote  - Sync project to remote instance"
	@echo "  install      - Install binary with capabilities (Linux only)"
	@echo "  help         - Show this help"