BINARY_NAME=forager
BUILD_DIR=bin
CMD_DIR=cmd

.PHONY: all build build-all run test fmt lint validate clean

all: validate build

build:
	@echo "Building $(BINARY_NAME)..."
	CGO_ENABLED=0 go build -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

build-all:
	@echo "Building all platforms..."
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o $(BUILD_DIR)/nudgebee-forager-linux-amd64 ./$(CMD_DIR)
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o $(BUILD_DIR)/nudgebee-forager-linux-arm64 ./$(CMD_DIR)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -o $(BUILD_DIR)/nudgebee-forager-darwin-amd64 ./$(CMD_DIR)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o $(BUILD_DIR)/nudgebee-forager-darwin-arm64 ./$(CMD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/nudgebee-forager-windows-amd64.exe ./$(CMD_DIR)

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
