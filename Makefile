.PHONY: proto apid agent test-go release

export PATH := $(shell go env GOPATH)/bin:$(PATH)
export GOTOOLCHAIN ?= local

proto:
	mkdir -p internal/gen
	protoc -I proto --go_out=internal/gen --go_opt=module=defendsec/internal/gen \
		--go-grpc_out=internal/gen --go-grpc_opt=module=defendsec/internal/gen \
		proto/defendsec/v1/agent.proto

apid:
	go build -o bin/defendsec-apid ./cmd/defendsec-apid

agent:
	go build -o bin/defendsec-agentd ./cmd/defendsec-agentd

test-go:
	go test ./cmd/... ./internal/...

release:
	./scripts/build-release.sh
