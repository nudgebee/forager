BINARY_NAME=forager
BUILD_DIR=bin
CMD_DIR=cmd

.PHONY: all build run test fmt lint validate clean

all: validate build

build:
	@echo "Building $(BINARY_NAME)..."
	CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

run:
	go run ./$(CMD_DIR)

test:
	go test -race -cover ./...

fmt:
	gofmt -w .

lint:
	golangci-lint run --timeout 10m

validate: fmt lint test

clean:
	rm -rf $(BUILD_DIR)

deps:
	go mod download
	go mod tidy
