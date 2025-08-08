# Terminal-Link Makefile
# Provides easy commands for building, testing, and development

.PHONY: all build test clean dist install lint help

# Default target
all: build

# Build for current platform
build:
	@echo "Building Terminal-Link for current platform..."
	go build -ldflags="-s -w" -o terminal-link main.go
	@echo "✓ Built terminal-link"

# Build optimized binary
build-optimized:
	@echo "Building optimized binary..."
	go build -ldflags="-s -w -X main.Version=$(shell git describe --tags --always --dirty)" -o terminal-link main.go
	@echo "✓ Built optimized terminal-link"

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...
	@echo "✓ Tests completed"

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

# Run linter
lint:
	@echo "Running linter..."
	@if command -v golint >/dev/null 2>&1; then \
		golint -set_exit_status ./...; \
	else \
		echo "Installing golint..."; \
		go install golang.org/x/lint/golint@latest; \
		golint -set_exit_status ./...; \
	fi
	@echo "✓ Linting completed"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f terminal-link
	rm -f terminal-link.exe
	rm -rf dist/
	rm -f coverage.out coverage.html
	@echo "✓ Cleaned"

# Build for all platforms
dist: clean
	@echo "Building for all platforms..."
	@if [ "$(OS)" = "Windows_NT" ]; then \
		./build.bat; \
	else \
		chmod +x build.sh && ./build.sh; \
	fi
	@echo "✓ Distribution builds completed"

# Install locally
install: build
	@echo "Installing Terminal-Link..."
	@if [ "$(OS)" = "Windows_NT" ]; then \
		cp terminal-link.exe $(GOPATH)/bin/terminal-link.exe; \
	else \
		cp terminal-link $(GOPATH)/bin/terminal-link; \
	fi
	@echo "✓ Installed to $(GOPATH)/bin/"

# Development mode (build and run tests)
dev: build test lint

# Quick test of the application
quick-test:
	@echo "Running quick application test..."
	@echo "Starting discovery mode (will timeout in 5 seconds)..."
	@timeout 5s go run main.go --discover || true
	@echo "✓ Quick test completed"

# Show help
help:
	@echo "Terminal-Link Makefile Commands:"
	@echo ""
	@echo "  build          - Build for current platform"
	@echo "  build-optimized- Build with version info"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  lint           - Run linter"
	@echo "  clean          - Clean build artifacts"
	@echo "  dist           - Build for all platforms"
	@echo "  install        - Install locally"
	@echo "  dev            - Build, test, and lint"
	@echo "  quick-test     - Quick application test"
	@echo "  help           - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make build     # Build for current platform"
	@echo "  make dist      # Build all platforms"
	@echo "  make dev       # Development workflow" 