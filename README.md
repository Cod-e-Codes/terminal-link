# Terminal-Link MVP

A LAN-only, secure, terminal-native messaging and file transfer application with end-to-end encryption.

**Current Release: v0.1.0** - Initial MVP with comprehensive test suite, cross-platform builds, and secure file transfer capabilities.

## Features

- **LAN-only operation**: Uses mDNS discovery with manual IP fallback
- **End-to-end encryption**: Noise_XX protocol with X25519 + ChaCha20-Poly1305
- **Simple pairing**: 6-digit verification codes for secure pairing
- **Real-time messaging**: Bidirectional text messaging with timestamps
- **Secure file transfer**: Chunked file transfer with SHA256 verification and resume capability
- **Cross-platform**: Single binary for Linux, macOS, Windows, and Android

## Quick Start

### Prerequisites

- Go 1.21 or later
- Network connectivity between devices

### Build

```bash
# Clone and build
git clone <repository>
cd terminal-link
go mod tidy

# Build for current platform
go build -o terminal-link main.go

# Or use the Makefile for easier builds
make build

# Build for all platforms
make dist
```

### Usage

#### Discovery Mode (Server)

Start the discovery service to accept incoming connections:

```bash
# Start discovery on default port 8080
go run main.go --discover

# Or specify a custom port
go run main.go --discover --port 9000
```

#### Connect Mode (Client)

Connect to a discovered peer:

```bash
# Connect to a specific IP and port
go run main.go --connect 192.168.1.100:8080

# Connect and immediately send a file
go run main.go --connect 192.168.1.100:8080 --send-file /path/to/file.txt
```

### Pairing Process

1. Start discovery mode on one device
2. Start discovery mode on another device (or connect directly)
3. When devices connect, both will display a 6-digit pairing code
4. Verify the codes match on both devices
5. Begin messaging!

## Protocol Details

### Discovery
- Uses mDNS service `_tlnk._tcp` on port 8080 (default)
- Automatically discovers peers on the same LAN
- Manual connection via IP:port as fallback

### Security
- **Noise_XX handshake**: Ephemeral X25519 key exchange
- **Encryption**: ChaCha20-Poly1305 for message encryption
- **Authentication**: Built into Noise protocol
- **Pairing verification**: 6-digit codes prevent MITM attacks

### Message Format

**Text Messages:**
```json
{
  "type": "text",
  "content": "Hello, World!",
  "timestamp": 1640995200,
  "id": "a1b2c3d4e5f67890"
}
```

**File Transfer:**
```json
// File metadata
{
  "type": "file_meta",
  "filename": "document.pdf",
  "size": 1048576,
  "sha256": "a1b2c3d4e5f67890...",
  "chunk_size": 65536,
  "id": "file123"
}

// File chunk
{
  "type": "file_chunk",
  "file_id": "file123",
  "chunk_id": 0,
  "data": "base64_encoded_chunk_data",
  "checksum": "chunk_checksum"
}
```

## Testing

Run the unit tests:

```bash
go test
```

### Manual Testing

1. **Two-terminal test**:
   ```bash
   # Terminal 1
   go run main.go --discover
   
   # Terminal 2  
   go run main.go --connect 127.0.0.1:8080
   ```

2. **File transfer test**:
   ```bash
   # Terminal 1 - Start discovery
   go run main.go --discover
   
   # Terminal 2 - Connect and send file
   go run main.go --connect 127.0.0.1:8080 --send-file test.txt
   
   # Or use interactive mode
   go run main.go --connect 127.0.0.1:8080
   # Then type: /send test.txt
   ```

3. **Cross-device test**:
   - Start discovery on device A
   - Find device A's IP address
   - Connect from device B using `--connect <device-a-ip>:8080`

## Architecture

```
Peer A (Desktop) ←→ LAN ←→ Peer B (Phone)
     ↑                              ↑
  Discovery                    Discovery
     ↓                              ↓
  Noise_XX Handshake ←→ Noise_XX Handshake
     ↓                              ↓
  Encrypted Channel ←→ Encrypted Channel
     ↓                              ↓
  Messaging ←→ Messaging
```

## Security Considerations

- **No cloud components**: All communication is peer-to-peer
- **Persistent encrypted keys**: Keys stored encrypted with user password
- **Verification codes**: Manual verification prevents impersonation
- **Secure key storage**: AES-GCM encryption for keyfile with salt and nonce

## Troubleshooting

### Common Issues

1. **Discovery not working**:
   - Check firewall settings
   - Try manual connection with `--connect <ip>:<port>`
   - Ensure both devices are on the same LAN

2. **Connection refused**:
   - Verify the target device is running in discovery mode
   - Check port number (default: 8080)
   - Ensure no firewall blocking

3. **Handshake fails**:
   - Check network connectivity
   - Verify pairing codes match
   - Restart both applications

### Debug Mode

For troubleshooting, check the console output for:
- Discovery messages showing found peers
- Handshake progress and pairing codes
- Connection status and errors

## Development

### Dependencies

- `github.com/flynn/noise`: Noise protocol implementation
- `github.com/grandcat/zeroconf`: mDNS discovery
- `github.com/charmbracelet/bubbletea`: TUI framework (future)

### Build System

The project includes a comprehensive build system:

```bash
# Development workflow
make dev          # Build, test, and lint

# Build options
make build        # Build for current platform
make dist         # Build for all platforms
make test         # Run tests
make lint         # Run linter
make clean        # Clean build artifacts

# Cross-compilation scripts
./build.sh        # Linux/macOS build script
./build.bat       # Windows build script
```

### CI/CD Pipeline

GitHub Actions automatically:
- Runs tests and linting on every push/PR
- Builds binaries for all target platforms
- Creates releases with attached binaries
- Validates binary sizes (< 15MB limit)

**Supported Platforms:**
- Linux (amd64, arm64) ✅
- Windows (amd64, arm64) ✅
- Android (arm64 via Termux) ✅
- macOS (amd64, arm64) - requires native macOS environment

### Manual Cross-Compilation

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o terminal-link-linux-amd64

# macOS
GOOS=darwin GOARCH=amd64 go build -o terminal-link-darwin-amd64

# Windows
GOOS=windows GOARCH=amd64 go build -o terminal-link-windows-amd64.exe

# Android (for Termux)
GOOS=linux GOARCH=arm64 go build -o terminal-link-android-arm64
```

## Roadmap

- [x] File transfer with chunking and SHA256 verification
- [x] Cross-compilation CI/CD with GitHub Actions
- [x] Encrypted keyfile storage for persistent keys
- [x] Comprehensive packaging and release system
- [ ] Resume functionality for interrupted transfers
- [ ] TUI interface with message history
- [ ] Android Termux compatibility
- [ ] Notification forwarding

## License

MIT License - see LICENSE file for details.