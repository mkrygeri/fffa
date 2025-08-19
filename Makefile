# Makefile for building eBPF program and Go userspace program

BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86_64 \
	-I$(KERNEL_HEADERS)/include \
	-I$(KERNEL_HEADERS)/arch/x86/include \
	-I$(KERNEL_HEADERS)/include/uapi \
	-I$(KERNEL_HEADERS)/arch/x86/include/uapi \
	-I$(KERNEL_HEADERS)/include/generated/uapi

GO ?= go
GO_FLAGS := build -o flowmonitor

BPF_OBJ := fffa.bpf.o
BPF_SRC := bpf/flow_monitor.c
GO_MAIN := main.go

KERNEL_HEADERS ?= /lib/modules/$(shell uname -r)/build

all: $(BPF_OBJ) flowmonitor

$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

flowmonitor: $(GO_MAIN)
	$(GO) $(GO_FLAGS)

clean:
	rm -f $(BPF_OBJ) flowmonitor

.PHONY: all clean