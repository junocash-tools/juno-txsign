.PHONY: build rust-build rust-test test test-unit test-integration test-e2e fmt tidy clean

TESTFLAGS ?=

ifneq ($(JUNO_TEST_LOG),)
TESTFLAGS += -v
endif

BIN_DIR := bin
BIN := $(BIN_DIR)/juno-txsign
GO_CACHE ?= $(CURDIR)/tmp/go-build
GO_ENV := GOWORK=off GOCACHE=$(GO_CACHE)

RUST_MANIFEST_TX := rust/juno-tx/Cargo.toml
RUST_MANIFEST_WITNESS := rust/witness/Cargo.toml

build: rust-build
	@mkdir -p $(BIN_DIR)
	$(GO_ENV) go build -o $(BIN) ./cmd/juno-txsign

rust-build:
	cargo build --release --manifest-path $(RUST_MANIFEST_TX)
	cargo build --release --manifest-path $(RUST_MANIFEST_WITNESS)

rust-test:
	cargo test --manifest-path $(RUST_MANIFEST_TX)
	cargo test --manifest-path $(RUST_MANIFEST_WITNESS)

test-unit:
	$(MAKE) rust-build
	$(MAKE) rust-test
	$(GO_ENV) go test $(TESTFLAGS) ./...

test-integration:
	$(MAKE) rust-build
	$(GO_ENV) go test $(TESTFLAGS) -tags=integration ./...

test-e2e:
	$(MAKE) build
	$(GO_ENV) go test $(TESTFLAGS) -tags=e2e ./...

test: test-unit test-integration test-e2e

fmt:
	gofmt -w .

tidy:
	$(GO_ENV) go mod tidy

clean:
	rm -rf $(BIN_DIR)
	rm -rf rust/juno-tx/target
	rm -rf rust/witness/target
