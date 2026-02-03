.PHONY: build rust-build rust-test test test-unit test-integration test-e2e fmt tidy clean

TESTFLAGS ?=

ifneq ($(JUNO_TEST_LOG),)
TESTFLAGS += -v
endif

BIN_DIR := bin
BIN := $(BIN_DIR)/juno-txsign

RUST_MANIFEST_TX := rust/juno-tx/Cargo.toml
RUST_MANIFEST_WITNESS := rust/witness/Cargo.toml

build: rust-build
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN) ./cmd/juno-txsign

rust-build:
	cargo build --release --manifest-path $(RUST_MANIFEST_TX)
	cargo build --release --manifest-path $(RUST_MANIFEST_WITNESS)

rust-test:
	cargo test --manifest-path $(RUST_MANIFEST_TX)
	cargo test --manifest-path $(RUST_MANIFEST_WITNESS)

test-unit:
	CGO_ENABLED=0 go test $(TESTFLAGS) ./internal/plan ./internal/cliout

test-integration:
	$(MAKE) rust-build
	go test $(TESTFLAGS) -tags=integration ./...

test-e2e:
	$(MAKE) build
	go test $(TESTFLAGS) -tags=e2e ./...

test: test-unit test-integration test-e2e

fmt:
	gofmt -w .

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR)
	rm -rf rust/juno-tx/target
	rm -rf rust/witness/target
