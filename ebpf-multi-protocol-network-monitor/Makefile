# DNS eBPF prototype Makefile

CLANG ?= /opt/homebrew/opt/llvm/bin/clang
GOOS ?= linux
GOARCH ?= $(shell go env GOARCH 2>/dev/null || echo amd64)

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/armv.*/arm/')
MULTIARCH ?= $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null)

KERNEL_INCLUDE := -I/usr/include
ifneq ($(MULTIARCH),)
KERNEL_INCLUDE += -I/usr/include/$(MULTIARCH)
endif

BPF_CFLAGS := -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types -mcpu=v3
BPF_EXTRA_WARN := -Wno-unused-function
BPF_INCLUDE := -I bpf
CFLAGS := -g -O2 -Wall

DIST := dist
BPF_HEADERS := $(wildcard bpf/*.h)

DNS_OBJ := $(DIST)/dns_ingress.o

all: bpf go

bpf: $(DNS_OBJ)

go: dnsd dnsbench

dnsd: | $(DIST)/
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -trimpath -ldflags="-s -w" -o $(DIST)/dnsd ./services/dns/cmd/dnsd

dnsbench: | $(DIST)/
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -trimpath -ldflags="-s -w" -o $(DIST)/dnsbench ./services/dns/cmd/dnsbench

lab-veth: bpf go
	bash scripts/lab/dns-veth-netns.sh

bpftool-smoke: bpf go
	bash scripts/lab/bpftool-smoke.sh

$(DIST)/:
	mkdir -p $(DIST)

$(DNS_OBJ): bpf/dns_ingress.c $(BPF_HEADERS) | $(DIST)/
	$(CLANG) $(BPF_CFLAGS) $(CFLAGS) $(BPF_EXTRA_WARN) $(BPF_INCLUDE) $(KERNEL_INCLUDE) -target bpf -c $< -o $@

clean:
	rm -rf $(DIST)

.PHONY: all bpf go dnsd dnsbench lab-veth bpftool-smoke clean
