.PHONY: test test-unit test-integration test-e2e fmt tidy

TESTFLAGS ?=

ifneq ($(JUNO_TEST_LOG),)
TESTFLAGS += -v
endif

test-unit:
	go test $(TESTFLAGS) ./...

test-integration:
	go test $(TESTFLAGS) -tags=integration ./...

test-e2e:
	go test $(TESTFLAGS) -tags=e2e ./...

test: test-unit test-integration test-e2e

fmt:
	gofmt -w .

tidy:
	go mod tidy

