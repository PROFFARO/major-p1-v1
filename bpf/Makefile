# Makefile — Compile eBPF probes into BPF bytecode object files.
# Requires: clang >= 15, llvm, bpftool (for vmlinux.h generation)

CLANG      ?= clang
LLC        ?= llc
BPFTOOL    ?= bpftool
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_BTF := /sys/kernel/btf/vmlinux

BPF_CFLAGS := -g -O2 \
              -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -I include/ \
              -Wall \
              -Wno-missing-declarations \
              -Werror

PROBES_SRC := $(wildcard probes/*.bpf.c)
PROBES_OBJ := $(PROBES_SRC:.bpf.c=.bpf.o)

.PHONY: all clean vmlinux

all: vmlinux $(PROBES_OBJ)
	@echo ""
	@echo "══════════════════════════════════════════════"
	@echo "  eBPF probes compiled successfully!"
	@echo "  Objects: $(PROBES_OBJ)"
	@echo "══════════════════════════════════════════════"

# Generate vmlinux.h from running kernel's BTF data
vmlinux: include/vmlinux.h

include/vmlinux.h:
	@echo "[*] Generating vmlinux.h from kernel BTF..."
	$(BPFTOOL) btf dump file $(KERNEL_BTF) format c > $@

# Compile each BPF probe
probes/%.bpf.o: probes/%.bpf.c include/vmlinux.h include/common.h
	@echo "[*] Compiling $< -> $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f probes/*.bpf.o
	@echo "[*] Cleaned BPF object files."
