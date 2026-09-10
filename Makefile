.PHONY: proto apid agent test-go

export PATH := $(shell go env GOPATH)/bin:$(PATH)

proto:
	mkdir -p internal/gen
	protoc -I proto --go_out=internal/gen --go_opt=module=keel/internal/gen \
		--go-grpc_out=internal/gen --go-grpc_opt=module=keel/internal/gen \
		proto/keel/v1/agent.proto

apid:
	go build -o bin/keel-apid ./cmd/keel-apid

agent:
	go build -o bin/keel-agentd ./cmd/keel-agentd

test-go:
	go test ./cmd/... ./internal/...
