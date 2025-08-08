#!/bin/bash
# Terminal-Link Cross-Compilation Build Script
# Builds binaries for Linux, macOS, Windows, and Android

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Build directory
BUILD_DIR="dist"
mkdir -p $BUILD_DIR

echo -e "${GREEN}Building Terminal-Link for all platforms...${NC}"

# Function to build for a specific platform
build_platform() {
    local os=$1
    local arch=$2
    local output_name=$3
    local env_vars=$4
    
    echo -e "${YELLOW}Building for $os/$arch...${NC}"
    
    # Set environment variables for cross-compilation
    eval $env_vars
    
    # Build the binary
    GOOS=$os GOARCH=$arch go build -ldflags="-s -w" -o "$BUILD_DIR/$output_name" main.go
    
    # Show file size
    if command -v stat >/dev/null 2>&1; then
        size=$(stat -c%s "$BUILD_DIR/$output_name" 2>/dev/null || stat -f%z "$BUILD_DIR/$output_name" 2>/dev/null)
        echo -e "${GREEN}✓ Built $output_name ($size bytes)${NC}"
    else
        echo -e "${GREEN}✓ Built $output_name${NC}"
    fi
}

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf $BUILD_DIR/*

# Linux builds
build_platform "linux" "amd64" "terminal-link-linux-amd64" ""
build_platform "linux" "arm64" "terminal-link-linux-arm64" ""

# macOS builds
build_platform "darwin" "amd64" "terminal-link-darwin-amd64" "CGO_ENABLED=0"
build_platform "darwin" "arm64" "terminal-link-darwin-arm64" "CGO_ENABLED=0"

# Windows builds
build_platform "windows" "amd64" "terminal-link-windows-amd64.exe" ""
build_platform "windows" "arm64" "terminal-link-windows-arm64.exe" ""

# Android builds (for Termux)
build_platform "linux" "arm64" "terminal-link-android-arm64" "CGO_ENABLED=0"

echo -e "${GREEN}Build complete! Binaries in $BUILD_DIR/:${NC}"
ls -la $BUILD_DIR/

# Create checksums
echo "Creating checksums..."
cd $BUILD_DIR
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum * > checksums.txt
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 * > checksums.txt
else
    echo "Warning: No checksum tool found"
fi
cd ..

echo -e "${GREEN}✓ All builds completed successfully!${NC}" 