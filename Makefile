.PHONY: all build test vet fmt lint check clean bench fuzz demo

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS = -ldflags "-X main.version=$(VERSION)"

all: check build

build:
	go build $(LDFLAGS) -o bin/trace ./cmd/trace

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (echo "gofmt check failed:" && gofmt -l . && exit 1)

lint: vet fmt

check: lint test

clean:
	rm -rf bin/ dist/ build/ coverage.html

bench:
	go test -bench=. -benchmem -run=^$$ ./... | tee bench/results.txt

fuzz:
	@echo "Running 30s fuzz per target..."
	go test -fuzz=FuzzPcapOpen -fuzztime=30s ./internal/pcap/
	go test -fuzz=FuzzLinkDecode -fuzztime=30s ./internal/netdec/
	go test -fuzz=FuzzIPDecode -fuzztime=30s ./internal/netdec/

validate:
	go test -race -count=1 -v ./... > docs/test-output.txt 2>&1 || true
	go run ./cmd/trace version >> docs/VALIDATION.md

demo:
	@echo "Running TRACE demo..."
	@for f in demo/*.pcap demo/*.pcapng; do \
		[ -f "$$f" ] && echo "=== $$f ===" && go run ./cmd/trace analyze "$$f" || true; \
	done
