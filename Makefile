.PHONY: proto bpf apid agent test-go test-updater release

export PATH := $(shell go env GOPATH)/bin:$(PATH)
export GOTOOLCHAIN ?= local

proto:
	mkdir -p internal/gen
	protoc -I proto --go_out=internal/gen --go_opt=module=defendsec/internal/gen \
		--go-grpc_out=internal/gen --go-grpc_opt=module=defendsec/internal/gen \
		proto/defendsec/v1/agent.proto

# The BPF object for the eBPF sensor (roadmap 3.1).
#
# Committed to the repository, so building the agent needs no clang, no kernel
# headers and no libbpf — only this target does. Run it after editing the C,
# and commit the resulting object with it.
#
#   apt install clang llvm libbpf-dev   # Debian/Ubuntu
#   dnf install clang llvm libbpf-devel # Fedora/RHEL
#
# The object is arch-independent for the tracepoints it uses; the one CO-RE
# relocation is resolved against the running kernel's BTF at load time, which
# is what lets a single object work across kernel versions.
BPF_CFLAGS := -target bpf -O2 -g -Wall -Werror -I/usr/include/$(shell uname -m)-linux-gnu

bpf:
	clang $(BPF_CFLAGS) -c internal/sensor/bpf/exec.bpf.c -o internal/sensor/bpf/exec_bpfel.o
	llvm-strip -g internal/sensor/bpf/exec_bpfel.o

apid:
	go build -o bin/defendsec-apid ./cmd/defendsec-apid

agent:
	go build -o bin/defendsec-agentd ./cmd/defendsec-agentd

test-go:
	go test ./cmd/... ./internal/...

test-updater:
	./scripts/test-server-update.sh

release:
	./scripts/build-release.sh
