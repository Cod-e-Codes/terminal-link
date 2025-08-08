#!/bin/bash
# Terminal-Link Packaging Script
# Creates release packages with proper naming and structure

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
VERSION=${1:-"0.1.0"}
RELEASE_DIR="release"
BUILD_DIR="dist"

echo -e "${GREEN}Packaging Terminal-Link v${VERSION}...${NC}"

# Clean previous releases
rm -rf $RELEASE_DIR
mkdir -p $RELEASE_DIR

# Build all platforms
echo -e "${YELLOW}Building for all platforms...${NC}"
./build.sh

# Create platform-specific packages
echo -e "${YELLOW}Creating release packages...${NC}"

# Linux packages
if [ -f "$BUILD_DIR/terminal-link-linux-amd64" ]; then
    mkdir -p "$RELEASE_DIR/linux-amd64"
    cp "$BUILD_DIR/terminal-link-linux-amd64" "$RELEASE_DIR/linux-amd64/terminal-link"
    cp README.md "$RELEASE_DIR/linux-amd64/"
    cp LICENSE "$RELEASE_DIR/linux-amd64/"
    cd "$RELEASE_DIR/linux-amd64"
    tar -czf "../terminal-link-v${VERSION}-linux-amd64.tar.gz" *
    cd ../..
    echo -e "${GREEN}✓ Created linux-amd64 package${NC}"
fi

if [ -f "$BUILD_DIR/terminal-link-linux-arm64" ]; then
    mkdir -p "$RELEASE_DIR/linux-arm64"
    cp "$BUILD_DIR/terminal-link-linux-arm64" "$RELEASE_DIR/linux-arm64/terminal-link"
    cp README.md "$RELEASE_DIR/linux-arm64/"
    cp LICENSE "$RELEASE_DIR/linux-arm64/"
    cd "$RELEASE_DIR/linux-arm64"
    tar -czf "../terminal-link-v${VERSION}-linux-arm64.tar.gz" *
    cd ../..
    echo -e "${GREEN}✓ Created linux-arm64 package${NC}"
fi

# macOS packages
if [ -f "$BUILD_DIR/terminal-link-darwin-amd64" ]; then
    mkdir -p "$RELEASE_DIR/darwin-amd64"
    cp "$BUILD_DIR/terminal-link-darwin-amd64" "$RELEASE_DIR/darwin-amd64/terminal-link"
    cp README.md "$RELEASE_DIR/darwin-amd64/"
    cp LICENSE "$RELEASE_DIR/darwin-amd64/"
    cd "$RELEASE_DIR/darwin-amd64"
    tar -czf "../terminal-link-v${VERSION}-darwin-amd64.tar.gz" *
    cd ../..
    echo -e "${GREEN}✓ Created darwin-amd64 package${NC}"
fi

if [ -f "$BUILD_DIR/terminal-link-darwin-arm64" ]; then
    mkdir -p "$RELEASE_DIR/darwin-arm64"
    cp "$BUILD_DIR/terminal-link-darwin-arm64" "$RELEASE_DIR/darwin-arm64/terminal-link"
    cp README.md "$RELEASE_DIR/darwin-arm64/"
    cp LICENSE "$RELEASE_DIR/darwin-arm64/"
    cd "$RELEASE_DIR/darwin-arm64"
    tar -czf "../terminal-link-v${VERSION}-darwin-arm64.tar.gz" *
    cd ../..
    echo -e "${GREEN}✓ Created darwin-arm64 package${NC}"
fi

# Windows packages
if [ -f "$BUILD_DIR/terminal-link-windows-amd64.exe" ]; then
    mkdir -p "$RELEASE_DIR/windows-amd64"
    cp "$BUILD_DIR/terminal-link-windows-amd64.exe" "$RELEASE_DIR/windows-amd64/terminal-link.exe"
    cp README.md "$RELEASE_DIR/windows-amd64/"
    cp LICENSE "$RELEASE_DIR/windows-amd64/"
    cd "$RELEASE_DIR/windows-amd64"
    zip -r "../terminal-link-v${VERSION}-windows-amd64.zip" *
    cd ../..
    echo -e "${GREEN}✓ Created windows-amd64 package${NC}"
fi

if [ -f "$BUILD_DIR/terminal-link-windows-arm64.exe" ]; then
    mkdir -p "$RELEASE_DIR/windows-arm64"
    cp "$BUILD_DIR/terminal-link-windows-arm64.exe" "$RELEASE_DIR/windows-arm64/terminal-link.exe"
    cp README.md "$RELEASE_DIR/windows-arm64/"
    cp LICENSE "$RELEASE_DIR/windows-arm64/"
    cd "$RELEASE_DIR/windows-arm64"
    zip -r "../terminal-link-v${VERSION}-windows-arm64.zip" *
    cd ../..
    echo -e "${GREEN}✓ Created windows-arm64 package${NC}"
fi

# Android package
if [ -f "$BUILD_DIR/terminal-link-android-arm64" ]; then
    mkdir -p "$RELEASE_DIR/android-arm64"
    cp "$BUILD_DIR/terminal-link-android-arm64" "$RELEASE_DIR/android-arm64/terminal-link"
    cp README.md "$RELEASE_DIR/android-arm64/"
    cp LICENSE "$RELEASE_DIR/android-arm64/"
    cd "$RELEASE_DIR/android-arm64"
    tar -czf "../terminal-link-v${VERSION}-android-arm64.tar.gz" *
    cd ../..
    echo -e "${GREEN}✓ Created android-arm64 package${NC}"
fi

# Create checksums
echo -e "${YELLOW}Creating checksums...${NC}"
cd $RELEASE_DIR
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum *.tar.gz *.zip > checksums.txt
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 *.tar.gz *.zip > checksums.txt
else
    echo "Warning: No checksum tool found"
fi
cd ..

# Show results
echo -e "${GREEN}Packaging complete! Release files in $RELEASE_DIR/:${NC}"
ls -la $RELEASE_DIR/

echo -e "${GREEN}✓ All packages created successfully!${NC}" 