# Terminal-Link Build System

This document describes the build system, CI/CD pipeline, and deployment process for Terminal-Link.

## Build Scripts

### Cross-Platform Build Scripts

**Linux/macOS (`build.sh`):**
```bash
./build.sh
```
- Builds for all target platforms
- Creates optimized binaries with size reporting
- Generates SHA256 checksums
- Outputs to `dist/` directory

**Windows (`build.bat`):**
```cmd
build.bat
```
- Windows-compatible build script
- Same functionality as Linux version
- Uses Windows-native commands

### Makefile Commands

```bash
make build          # Build for current platform
make dist           # Build for all platforms
make test           # Run tests
make lint           # Run linter
make clean          # Clean build artifacts
make dev            # Build, test, and lint
make help           # Show all commands
```

## CI/CD Pipeline

### GitHub Actions Workflow (`.github/workflows/ci.yml`)

**Jobs:**
1. **Test**: Runs unit tests and linting
2. **Build**: Cross-compiles for all platforms
3. **Release**: Creates GitHub releases with binaries
4. **Size Check**: Validates binary sizes (< 15MB)

**Triggers:**
- Push to main/master branches
- Pull requests
- Release creation

### Supported Platforms

| Platform | Architecture | Binary Name |
|----------|--------------|-------------|
| Linux | amd64 | `terminal-link-linux-amd64` |
| Linux | arm64 | `terminal-link-linux-arm64` |
| macOS | amd64 | `terminal-link-darwin-amd64` |
| macOS | arm64 | `terminal-link-darwin-arm64` |
| Windows | amd64 | `terminal-link-windows-amd64.exe` |
| Windows | arm64 | `terminal-link-windows-arm64.exe` |
| Android | arm64 | `terminal-link-android-arm64` |

## Build Configuration

### Optimization Flags
```bash
go build -ldflags="-s -w" -o binary main.go
```
- `-s`: Strip debug information
- `-w`: Strip DWARF symbol table

### Cross-Compilation Environment Variables
```bash
GOOS=linux GOARCH=amd64 go build
GOOS=darwin GOARCH=arm64 go build
GOOS=windows GOARCH=amd64 go build
```

### Android Build (Termux)
```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build
```

## Release Process

### Automatic Release
1. Create a GitHub release
2. CI automatically builds all platforms
3. Binaries attached to release
4. Checksums generated for verification

### Manual Release
```bash
# Build all platforms and create release packages
make release

# Or build and package separately
make dist
./package.sh 0.1.0
```

### Release Process for v0.1.0

1. **Update version in main.go**:
   ```go
   const Version = "0.1.0"
   ```

2. **Build and package**:
   ```bash
   make release
   ```

3. **Create GitHub release**:
   - Upload all files from `release/` directory
   - Include `checksums.txt` for verification
   - Add release notes describing features and fixes

4. **Verify release**:
   - Test binaries on target platforms
   - Verify checksums match
   - Confirm all platforms are included

## Binary Size Targets

- **Target**: < 15MB per binary
- **Current**: ~8-12MB (varies by platform)
- **Optimization**: Stripped debug info, minimal dependencies

## Development Workflow

### Local Development
```bash
# Quick development cycle
make dev

# Test specific functionality
go test -v ./...

# Build and test application
go build && ./terminal-link --discover
```

### CI/CD Integration
- Automatic testing on every commit
- Cross-platform builds on every PR
- Release automation on tag creation
- Size validation to prevent bloat

## Troubleshooting

### Build Issues
1. **Dependencies**: Run `go mod tidy`
2. **Cross-compilation**: Ensure Go 1.21+
3. **Size limits**: Check for unnecessary dependencies

### CI/CD Issues
1. **Test failures**: Check test output in Actions
2. **Build failures**: Verify platform-specific issues
3. **Size violations**: Review dependencies and optimization

## Future Enhancements

- [ ] Docker-based builds for consistency
- [ ] Automated performance benchmarking
- [ ] Code signing for releases
- [ ] Automated dependency updates
- [ ] Multi-stage builds for smaller binaries 