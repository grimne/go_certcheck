# Binary name
BINARY_NAME=certcheck

# Build variables
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Directories
BUILD_DIR=build
CMD_DIR=cmd/certcheck

# Platforms for cross-compilation
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build clean test coverage deps install release build-all help

all: test build

## build: Build the binary for current platform
build:
	@echo "Building ${BINARY_NAME}..."
	@mkdir -p ${BUILD_DIR}
	$(GOBUILD) ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME} ./${CMD_DIR}

## release: Build optimized binary
release:
	@echo "Building release version..."
	@mkdir -p ${BUILD_DIR}
	$(GOBUILD) ${LDFLAGS} -trimpath -o ${BUILD_DIR}/${BINARY_NAME} ./${CMD_DIR}
	@echo "Built: ${BUILD_DIR}/${BINARY_NAME}"

## build-all: Cross-compile for all platforms
build-all:
	@echo "Cross-compiling for all platforms..."
	@$(foreach PLATFORM,$(PLATFORMS), \
		GOOS=$(word 1,$(subst /, ,$(PLATFORM))) \
		GOARCH=$(word 2,$(subst /, ,$(PLATFORM))) \
		$(GOBUILD) ${LDFLAGS} -trimpath \
		-o ${BUILD_DIR}/${BINARY_NAME}-$(subst /,-,$(PLATFORM))$(if $(findstring windows,$(PLATFORM)),.exe) \
		./${CMD_DIR} && echo "✓ Built for $(PLATFORM)" || exit 1; \
	)

## test: Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race ./...

## coverage: Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## install: Install binary to $GOPATH/bin
install: build
	@echo "Installing ${BINARY_NAME}..."
	@cp ${BUILD_DIR}/${BINARY_NAME} ${GOPATH}/bin/
	@echo "Installed to ${GOPATH}/bin/${BINARY_NAME}"

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -rf ${BUILD_DIR}
	@rm -f coverage.out coverage.html

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

## lint: Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run ./...

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

.DEFAULT_GOAL := build
