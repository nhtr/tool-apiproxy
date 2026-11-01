VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Falls back to "dev" whenever git isn't usable at all, which also covers
# "no commits/tags yet" since `git describe` fails the same way in that case.
ifeq ($(strip $(VERSION)),)
VERSION := dev
endif

LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help build windows test vet fmt check clean

help:
	@echo "apiproxy make targets:"
	@echo "  build    build the host binary into bin/"
	@echo "  windows  cross-compile bin/apiproxy.exe for Windows amd64"
	@echo "  test     go test ./... -race"
	@echo "  vet      go vet ./..."
	@echo "  fmt      gofmt -w ."
	@echo "  check    fmt check + vet + test"
	@echo "  clean    remove bin/"

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/apiproxy ./cmd/apiproxy

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/apiproxy.exe ./cmd/apiproxy

test:
	go test ./... -race

vet:
	go vet ./...

fmt:
	gofmt -w .

check:
	@echo "checking gofmt..."
	@test -z "$$(gofmt -l .)" || (echo "not gofmt-clean, run 'make fmt':"; gofmt -l .; exit 1)
	$(MAKE) vet
	$(MAKE) test

clean:
	rm -rf bin
