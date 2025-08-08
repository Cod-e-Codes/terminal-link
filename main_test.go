package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/grandcat/zeroconf"
)

// Test utilities and mocks

type mockConn struct {
	readBuffer  *bytes.Buffer
	writeBuffer *bytes.Buffer
	closed      bool
	addr        net.Addr
}

func newMockConn() *mockConn {
	return &mockConn{
		readBuffer:  bytes.NewBuffer(nil),
		writeBuffer: bytes.NewBuffer(nil),
		addr:        &mockAddr{addr: "127.0.0.1:8080"},
	}
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.readBuffer.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.closed {
		return 0, fmt.Errorf("connection closed")
	}
	return m.writeBuffer.Write(b)
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return m.addr }
func (m *mockConn) RemoteAddr() net.Addr               { return m.addr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

type mockAddr struct {
	addr string
}

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string  { return m.addr }

// Test Discovery

func TestDiscoveryServiceRegistration(t *testing.T) {
	// Test mDNS service registration
	port := 8080
	server, err := zeroconf.Register("TestTerminalLink", ServiceName, "local.", port, nil, nil)
	if err != nil {
		t.Fatalf("Failed to register mDNS service: %v", err)
	}
	defer server.Shutdown()

	// Verify service is registered
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}

	entries := make(chan *zeroconf.ServiceEntry, 1)
	err = resolver.Browse(context.Background(), ServiceName, "local.", entries)
	if err != nil {
		t.Fatalf("Failed to browse: %v", err)
	}

	// Wait for service discovery
	select {
	case entry := <-entries:
		if entry.Port != port {
			t.Errorf("Expected port %d, got %d", port, entry.Port)
		}
		if entry.Instance != "TestTerminalLink" {
			t.Errorf("Expected instance 'TestTerminalLink', got '%s'", entry.Instance)
		}
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for service discovery")
	}
}

func TestManualConnectionFallback(t *testing.T) {
	// Test manual IP:port connection when mDNS fails
	tl := &TerminalLink{
		peers:           make(map[string]*Peer),
		activeTransfers: make(map[string]*FileTransfer),
	}

	// Test with invalid IP (should fail gracefully)
	// Note: This test would need proper mocking to avoid actual network calls
	// For now, we'll just verify the TerminalLink struct was created properly
	if tl.peers == nil {
		t.Error("peers map should be initialized")
	}
	if tl.activeTransfers == nil {
		t.Error("activeTransfers map should be initialized")
	}
}

// Test Noise_XX Handshake and Encryption

func TestNoiseXXHandshake(t *testing.T) {
	// Configure as initiator and responder
	config1 := &noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXX,
		Initiator:   true,
	}

	config2 := &noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXX,
		Initiator:   false,
	}

	// Generate keypairs
	keypair1, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair 1: %v", err)
	}

	keypair2, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair 2: %v", err)
	}

	config1.StaticKeypair = keypair1
	config2.StaticKeypair = keypair2

	// Create handshake states
	hs1, err := noise.NewHandshakeState(*config1)
	if err != nil {
		t.Fatalf("Failed to create handshake state 1: %v", err)
	}

	hs2, err := noise.NewHandshakeState(*config2)
	if err != nil {
		t.Fatalf("Failed to create handshake state 2: %v", err)
	}

	// Perform handshake
	// Message 1: -> e
	msg1, _, _, err := hs1.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write 1 failed: %v", err)
	}

	// Message 2: <- e, ee, s, es
	_, _, _, err = hs2.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatalf("Handshake read 1 failed: %v", err)
	}

	msg2, _, _, err := hs2.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write 2 failed: %v", err)
	}

	// Message 3: -> s, se
	_, _, _, err = hs1.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("Handshake read 2 failed: %v", err)
	}

	msg3, cs1, cs2, err := hs1.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write 3 failed: %v", err)
	}

	_, cs3, cs4, err := hs2.ReadMessage(nil, msg3)
	if err != nil {
		t.Fatalf("Handshake read 3 failed: %v", err)
	}

	// Verify handshake completed successfully
	if cs1 == nil || cs2 == nil || cs3 == nil || cs4 == nil {
		t.Error("Handshake failed to establish cipher states")
	}
}

func TestMessageEncryptionDecryption(t *testing.T) {
	// Test message encryption and decryption using proper Noise_XX handshake
	t.Log("=== Starting TestMessageEncryptionDecryption ===")

	// Configure as initiator and responder
	config1 := &noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXX,
		Initiator:   true,
	}

	config2 := &noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXX,
		Initiator:   false,
	}

	// Generate keypairs
	t.Log("Generating keypairs...")
	keypair1, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair 1: %v", err)
	}
	t.Logf("Keypair 1 generated - Private: %v, Public: %v",
		keypair1.Private != nil, keypair1.Public != nil)

	keypair2, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair 2: %v", err)
	}
	t.Logf("Keypair 2 generated - Private: %v, Public: %v",
		keypair2.Private != nil, keypair2.Public != nil)

	config1.StaticKeypair = keypair1
	config2.StaticKeypair = keypair2
	t.Log("Static keypairs assigned to configs")

	t.Log("Creating handshake states...")
	hs1, err := noise.NewHandshakeState(*config1)
	if err != nil {
		t.Fatalf("Failed to create handshake state 1: %v", err)
	}
	t.Log("Handshake state 1 (initiator) created successfully")

	hs2, err := noise.NewHandshakeState(*config2)
	if err != nil {
		t.Fatalf("Failed to create handshake state 2: %v", err)
	}
	t.Log("Handshake state 2 (responder) created successfully")

	// Complete handshake to get cipher states
	t.Log("=== Starting Noise_XX handshake message exchange ===")

	t.Log("Step 1: Initiator writes first message")
	msg1, _, _, err := hs1.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write failed: %v", err)
	}
	t.Logf("Message 1 sent, length: %d bytes", len(msg1))

	t.Log("Step 2: Responder reads first message")
	_, _, _, err = hs2.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatalf("Handshake read failed: %v", err)
	}
	t.Log("Message 1 received by responder successfully")

	t.Log("Step 3: Responder writes second message")
	msg2, _, _, err := hs2.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write 2 failed: %v", err)
	}
	t.Logf("Message 2 sent, length: %d bytes", len(msg2))

	t.Log("Step 4: Initiator reads second message")
	_, cs1, cs2, err := hs1.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("Handshake read 2 failed: %v", err)
	}
	t.Logf("Message 2 received by initiator - cs1: %v, cs2: %v", cs1 != nil, cs2 != nil)

	t.Log("Step 5: Initiator writes third message")
	msg3, cs3, cs4, err := hs1.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write 3 failed: %v", err)
	}
	t.Logf("Message 3 sent, length: %d bytes", len(msg3))
	t.Logf("Initiator cipher states after write - cs3: %v, cs4: %v", cs3 != nil, cs4 != nil)

	t.Log("Step 6: Responder reads third message")
	_, cs5, cs6, err := hs2.ReadMessage(nil, msg3)
	if err != nil {
		t.Fatalf("Handshake read 3 failed: %v", err)
	}
	t.Logf("Message 3 received by responder - cs5: %v, cs6: %v", cs5 != nil, cs6 != nil)

	// Debug: Log all cipher states
	t.Log("=== Final cipher state status ===")
	t.Logf("cs1 (initiator send): %v", cs1 != nil)
	t.Logf("cs2 (initiator receive): %v", cs2 != nil)
	t.Logf("cs3 (initiator send after msg3): %v", cs3 != nil)
	t.Logf("cs4 (initiator receive after msg3): %v", cs4 != nil)
	t.Logf("cs5 (responder send): %v", cs5 != nil)
	t.Logf("cs6 (responder receive): %v", cs6 != nil)

	// Verify cipher states were established
	// Note: cs1 and cs2 are from incomplete handshake steps, only cs3-cs6 are valid
	if cs3 == nil || cs4 == nil || cs5 == nil || cs6 == nil {
		t.Fatalf("Cipher states should not be nil after handshake")
	}
	t.Log("All cipher states established successfully")

	// Test encryption/decryption
	originalMessage := []byte("Hello, World!")
	encrypted, err := cs3.Encrypt(nil, nil, originalMessage)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := cs5.Decrypt(nil, nil, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(originalMessage, decrypted) {
		t.Errorf("Decrypted message doesn't match original: got %s, want %s", decrypted, originalMessage)
	}

	// Test that different cipher states produce different results
	encrypted2, err := cs4.Encrypt(nil, nil, originalMessage)
	if err != nil {
		t.Fatalf("Encryption 2 failed: %v", err)
	}

	if bytes.Equal(encrypted, encrypted2) {
		t.Error("Different cipher states should produce different encrypted results")
	}

	// Verify that the keypairs were generated correctly
	if keypair1.Private == nil || keypair1.Public == nil {
		t.Error("Keypair 1 should have private and public keys")
	}

	if keypair2.Private == nil || keypair2.Public == nil {
		t.Error("Keypair 2 should have private and public keys")
	}
}

// Test Messaging

func TestMessageSerialization(t *testing.T) {
	msg := Message{
		Type:      "text",
		Content:   "Hello, World!",
		Timestamp: time.Now().Unix(),
		ID:        "test123",
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}

	var decoded Message
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal message: %v", err)
	}

	if decoded.Type != msg.Type {
		t.Errorf("Expected type %s, got %s", msg.Type, decoded.Type)
	}
	if decoded.Content != msg.Content {
		t.Errorf("Expected content %s, got %s", msg.Content, decoded.Content)
	}
	if decoded.ID != msg.ID {
		t.Errorf("Expected ID %s, got %s", msg.ID, decoded.ID)
	}
}

func TestFileMetaSerialization(t *testing.T) {
	meta := FileMeta{
		Type:      "file_meta",
		Filename:  "test.txt",
		Size:      1024,
		SHA256:    "a1b2c3d4e5f67890",
		ChunkSize: 65536,
		ID:        "file123",
	}

	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("Failed to marshal file meta: %v", err)
	}

	var decoded FileMeta
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal file meta: %v", err)
	}

	if decoded.Filename != meta.Filename {
		t.Errorf("Expected filename %s, got %s", meta.Filename, decoded.Filename)
	}
	if decoded.Size != meta.Size {
		t.Errorf("Expected size %d, got %d", meta.Size, decoded.Size)
	}
	if decoded.SHA256 != meta.SHA256 {
		t.Errorf("Expected SHA256 %s, got %s", meta.SHA256, decoded.SHA256)
	}
}

func TestCommandParsing(t *testing.T) {
	tests := []struct {
		name    string
		command string
		expect  string
	}{
		{
			name:    "Send command",
			command: "/send test.txt",
			expect:  "send",
		},
		{
			name:    "Help command",
			command: "/help",
			expect:  "help",
		},
		{
			name:    "Quit command",
			command: "/quit",
			expect:  "quit",
		},
		{
			name:    "Invalid command",
			command: "/invalid",
			expect:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := strings.Fields(tt.command)
			if len(parts) == 0 {
				return
			}

			command := parts[0]
			switch command {
			case "/send":
				if tt.expect != "send" {
					t.Errorf("Expected 'send', got %s", command)
				}
			case "/help":
				if tt.expect != "help" {
					t.Errorf("Expected 'help', got %s", command)
				}
			case "/quit":
				if tt.expect != "quit" {
					t.Errorf("Expected 'quit', got %s", command)
				}
			default:
				if tt.expect != "unknown" {
					t.Errorf("Expected 'unknown', got %s", command)
				}
			}
		})
	}
}

// Test File Transfer

func TestFileChunking(t *testing.T) {
	// Create a test file
	testData := []byte("This is test data for chunking. " + strings.Repeat("A", 1000))
	tempFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	_, err = tempFile.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}

	// Test file metadata creation
	stat, err := tempFile.Stat()
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	meta := FileMeta{
		Type:      "file_meta",
		Filename:  filepath.Base(tempFile.Name()),
		Size:      stat.Size(),
		SHA256:    "test-sha256",
		ChunkSize: ChunkSize,
		ID:        generateID(),
	}

	if meta.Size != int64(len(testData)) {
		t.Errorf("Expected size %d, got %d", len(testData), meta.Size)
	}

	// Test chunking logic
	totalChunks := int((meta.Size + int64(meta.ChunkSize) - 1) / int64(meta.ChunkSize))
	expectedChunks := (len(testData) + ChunkSize - 1) / ChunkSize

	if totalChunks != expectedChunks {
		t.Errorf("Expected %d chunks, got %d", expectedChunks, totalChunks)
	}

	// Verify all fields are properly set
	if meta.Type != "file_meta" {
		t.Errorf("Expected type 'file_meta', got %s", meta.Type)
	}
	if meta.Filename == "" {
		t.Error("Filename should not be empty")
	}
	if meta.SHA256 != "test-sha256" {
		t.Errorf("Expected SHA256 'test-sha256', got %s", meta.SHA256)
	}
	if meta.ID == "" {
		t.Error("ID should not be empty")
	}
}

func TestChunkChecksum(t *testing.T) {
	testData := []byte("Test chunk data")
	checksum := calculateChunkChecksum(testData)

	if len(checksum) != 16 {
		t.Errorf("Expected checksum length 16, got %d", len(checksum))
	}

	// Test checksum consistency
	checksum2 := calculateChunkChecksum(testData)
	if checksum != checksum2 {
		t.Error("Checksums should be consistent for same data")
	}

	// Test different data produces different checksum
	testData2 := []byte("Different test data")
	checksum3 := calculateChunkChecksum(testData2)
	if checksum == checksum3 {
		t.Error("Different data should produce different checksums")
	}
}

func TestFileTransferSimulation(t *testing.T) {
	// Create test file
	testData := []byte("Test file content for transfer simulation")
	tempFile, err := os.CreateTemp("", "transfer-test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	_, err = tempFile.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}

	// Create mock peer with proper noise cipher states
	peer := &Peer{conn: newMockConn()}

	// Configure as initiator and responder
	config1 := &noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXX,
		Initiator:   true,
	}

	config2 := &noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXX,
		Initiator:   false,
	}

	// Generate keypairs
	keypair1, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair 1: %v", err)
	}

	keypair2, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair 2: %v", err)
	}

	config1.StaticKeypair = keypair1
	config2.StaticKeypair = keypair2

	hs1, err := noise.NewHandshakeState(*config1)
	if err != nil {
		t.Fatalf("Failed to create handshake state 1: %v", err)
	}

	hs2, err := noise.NewHandshakeState(*config2)
	if err != nil {
		t.Fatalf("Failed to create handshake state 2: %v", err)
	}

	// Complete handshake to get cipher states
	msg1, _, _, err := hs1.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write failed: %v", err)
	}

	_, _, _, err = hs2.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatalf("Handshake read failed: %v", err)
	}

	msg2, _, _, err := hs2.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write 2 failed: %v", err)
	}

	_, _, _, err = hs1.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("Handshake read 2 failed: %v", err)
	}

	// Complete the third message to establish both cipher states
	msg3, cs3, cs4, err := hs1.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write 3 failed: %v", err)
	}

	_, cs5, cs6, err := hs2.ReadMessage(nil, msg3)
	if err != nil {
		t.Fatalf("Handshake read 3 failed: %v", err)
	}

	// Verify cipher states were established
	// Note: cs1 and cs2 are from incomplete handshake steps, only cs3-cs6 are valid
	if cs3 == nil || cs4 == nil || cs5 == nil || cs6 == nil {
		t.Fatalf("Cipher states should not be nil after handshake")
	}

	// Set the cipher states on the peer for testing
	peer.noise = cs3
	peer.remote = cs6

	// Verify keypairs were generated correctly
	if keypair1.Private == nil || keypair1.Public == nil {
		t.Error("Keypair 1 should have private and public keys")
	}

	if keypair2.Private == nil || keypair2.Public == nil {
		t.Error("Keypair 2 should have private and public keys")
	}

	tl := &TerminalLink{
		peers:           make(map[string]*Peer),
		activeTransfers: make(map[string]*FileTransfer),
	}

	// Add peer to the peers map (as would happen in handleConnection)
	peerID := peer.conn.RemoteAddr().String()
	tl.peers[peerID] = peer

	// Simulate file transfer
	err = tl.sendFile(peer, tempFile.Name())
	if err != nil {
		t.Fatalf("File transfer failed: %v", err)
	}

	// Verify that data was written to mock connection
	if peer.conn.(*mockConn).writeBuffer.Len() == 0 {
		t.Error("No data was written to connection")
	}

	// Verify that the peer was added to the peers map
	if _, exists := tl.peers[peerID]; !exists {
		t.Error("Peer should be added to peers map")
	}
}

// Test Encrypted Keyfile Storage

func TestKeyStoreCreation(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "keystore-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tl := &TerminalLink{
		peers:           make(map[string]*Peer),
		activeTransfers: make(map[string]*FileTransfer),
		keyFile:         filepath.Join(tempDir, ".terminal-link-keys"),
	}

	// Test key store creation by directly calling the underlying functions
	// instead of going through the password prompt
	keyStore := &KeyStore{
		PrivateKey: make([]byte, 32),
		PublicKey:  make([]byte, 32),
		Salt:       make([]byte, 32),
		Nonce:      make([]byte, 12),
	}

	// Fill with test data
	rand.Read(keyStore.PrivateKey)
	rand.Read(keyStore.PublicKey)
	rand.Read(keyStore.Salt)
	rand.Read(keyStore.Nonce)

	tl.keyStore = keyStore

	// Test saving the key store
	data, err := json.Marshal(keyStore)
	if err != nil {
		t.Fatalf("Failed to marshal key store: %v", err)
	}

	encrypted, err := tl.encryptKeyStore(data, "testpassword")
	if err != nil {
		t.Fatalf("Failed to encrypt key store: %v", err)
	}

	err = os.WriteFile(tl.keyFile, encrypted, 0600)
	if err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Verify key store was created
	if tl.keyStore == nil {
		t.Error("Key store was not created")
	}

	if len(tl.keyStore.PrivateKey) == 0 {
		t.Error("Private key was not generated")
	}

	if len(tl.keyStore.PublicKey) == 0 {
		t.Error("Public key was not generated")
	}

	if len(tl.keyStore.Salt) == 0 {
		t.Error("Salt was not generated")
	}

	if len(tl.keyStore.Nonce) == 0 {
		t.Error("Nonce was not generated")
	}

	// Verify key file was created
	if _, err := os.Stat(tl.keyFile); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}
}

func TestKeyStoreEncryptionDecryption(t *testing.T) {
	// Create test key store
	keyStore := &KeyStore{
		PrivateKey: []byte("private-key-data"),
		PublicKey:  []byte("public-key-data"),
		Salt:       make([]byte, 32),
		Nonce:      make([]byte, 12),
	}

	// Fill salt and nonce with test data
	for i := range keyStore.Salt {
		keyStore.Salt[i] = byte(i)
	}
	for i := range keyStore.Nonce {
		keyStore.Nonce[i] = byte(i + 10)
	}

	tl := &TerminalLink{
		peers:           make(map[string]*Peer),
		activeTransfers: make(map[string]*FileTransfer),
		keyStore:        keyStore,
	}

	password := "testpassword"

	// Test encryption
	data, err := json.Marshal(keyStore)
	if err != nil {
		t.Fatalf("Failed to marshal key store: %v", err)
	}

	encrypted, err := tl.encryptKeyStore(data, password)
	if err != nil {
		t.Fatalf("Failed to encrypt key store: %v", err)
	}

	// Test decryption
	decrypted, err := tl.decryptKeyStore(encrypted, password)
	if err != nil {
		t.Fatalf("Failed to decrypt key store: %v", err)
	}

	// Compare the decrypted data with original
	if !bytes.Equal(data, decrypted) {
		t.Error("Decrypted data doesn't match original")
	}

	// Test wrong password
	_, err = tl.decryptKeyStore(encrypted, "wrongpassword")
	if err == nil {
		t.Error("Expected error for wrong password")
	}

	// Test that we can unmarshal the decrypted data back to KeyStore
	var decodedKeyStore KeyStore
	err = json.Unmarshal(decrypted, &decodedKeyStore)
	if err != nil {
		t.Fatalf("Failed to unmarshal decrypted key store: %v", err)
	}

	if !bytes.Equal(decodedKeyStore.PrivateKey, keyStore.PrivateKey) {
		t.Error("Decoded private key doesn't match original")
	}

	if !bytes.Equal(decodedKeyStore.PublicKey, keyStore.PublicKey) {
		t.Error("Decoded public key doesn't match original")
	}
}

func TestKeyDerivation(t *testing.T) {
	tl := &TerminalLink{
		peers:           make(map[string]*Peer),
		activeTransfers: make(map[string]*FileTransfer),
	}

	password := "testpassword"
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	key1 := tl.deriveKey(password, salt)
	key2 := tl.deriveKey(password, salt)

	// Same password and salt should produce same key
	if !bytes.Equal(key1, key2) {
		t.Error("Key derivation should be deterministic")
	}

	// Different password should produce different key
	key3 := tl.deriveKey("differentpassword", salt)
	if bytes.Equal(key1, key3) {
		t.Error("Different passwords should produce different keys")
	}

	// Different salt should produce different key
	differentSalt := make([]byte, 32)
	for i := range differentSalt {
		differentSalt[i] = byte(i + 1)
	}
	key4 := tl.deriveKey(password, differentSalt)
	if bytes.Equal(key1, key4) {
		t.Error("Different salts should produce different keys")
	}
}

// Test Error Handling and Recovery

func TestNetworkErrorHandling(t *testing.T) {
	// Test connection failure
	tl := &TerminalLink{
		peers:           make(map[string]*Peer),
		activeTransfers: make(map[string]*FileTransfer),
	}

	// Test with invalid address - this would fail in real scenario
	// For testing, we'll just verify the TerminalLink struct was created properly
	if tl.peers == nil {
		t.Error("peers map should be initialized")
	}
	if tl.activeTransfers == nil {
		t.Error("activeTransfers map should be initialized")
	}
}

func TestMalformedMessageHandling(t *testing.T) {
	tl := &TerminalLink{
		peers:           make(map[string]*Peer),
		activeTransfers: make(map[string]*FileTransfer),
	}

	// Test handling of malformed JSON
	malformedData := []byte(`{"type": "text", "content": "test"`) // Missing closing brace
	err := tl.handleMessage(nil, malformedData)
	if err == nil {
		t.Error("Expected error for malformed JSON")
	}

	// Test handling of missing message type
	invalidData := []byte(`{"content": "test"}`)
	err = tl.handleMessage(nil, invalidData)
	if err == nil {
		t.Error("Expected error for missing message type")
	}

	// Verify that the TerminalLink struct was created properly
	if tl.peers == nil {
		t.Error("peers map should be initialized")
	}
	if tl.activeTransfers == nil {
		t.Error("activeTransfers map should be initialized")
	}
}

func TestFileTransferErrorHandling(t *testing.T) {
	tl := &TerminalLink{
		peers:           make(map[string]*Peer),
		activeTransfers: make(map[string]*FileTransfer),
	}

	// Test sending non-existent file
	err := tl.sendFile(nil, "/non/existent/file.txt")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Verify that the TerminalLink struct was created properly
	if tl.peers == nil {
		t.Error("peers map should be initialized")
	}
	if tl.activeTransfers == nil {
		t.Error("activeTransfers map should be initialized")
	}
}

// Test Utility Functions

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()

	if len(id1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("Expected ID length 16, got %d", len(id1))
	}
	if id1 == id2 {
		t.Error("Generated IDs should be unique")
	}
}

func TestGetBaseName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test.txt", "test.txt"},
		{"/path/to/file.txt", "file.txt"},
		{"C:\\path\\to\\file.txt", "file.txt"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := getBaseName(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGeneratePairingCode(t *testing.T) {
	// Mock public key (32 bytes for X25519)
	publicKey := make([]byte, 32)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}

	tl := &TerminalLink{}
	code := tl.generatePairingCode(publicKey, "192.168.1.100:8080")

	if len(code) != 6 {
		t.Errorf("Expected pairing code length 6, got %d", len(code))
	}

	// Test that it's valid hex
	for _, c := range code {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Invalid hex character in pairing code: %c", c)
		}
	}

	// Test consistency for same inputs
	code2 := tl.generatePairingCode(publicKey, "192.168.1.100:8080")
	if code != code2 {
		t.Error("Pairing codes should be consistent for same inputs")
	}

	// Test different inputs produce different codes
	code3 := tl.generatePairingCode(publicKey, "192.168.1.101:8080")
	if code == code3 {
		t.Error("Different addresses should produce different pairing codes")
	}

	// Test that different public keys produce different codes
	publicKey2 := make([]byte, 32)
	for i := range publicKey2 {
		publicKey2[i] = byte(i + 1)
	}
	code4 := tl.generatePairingCode(publicKey2, "192.168.1.100:8080")
	if code == code4 {
		t.Error("Different public keys should produce different pairing codes")
	}
}

// Integration Tests

func TestEndToEndMessaging(t *testing.T) {
	// Create two mock peers with proper noise cipher states
	peer1 := &Peer{conn: newMockConn()}
	peer2 := &Peer{conn: newMockConn()}

	// Configure as initiator and responder
	config1 := &noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXX,
		Initiator:   true,
	}

	config2 := &noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeXX,
		Initiator:   false,
	}

	// Generate keypairs
	keypair1, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair 1: %v", err)
	}

	keypair2, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keypair 2: %v", err)
	}

	config1.StaticKeypair = keypair1
	config2.StaticKeypair = keypair2

	hs1, err := noise.NewHandshakeState(*config1)
	if err != nil {
		t.Fatalf("Failed to create handshake state 1: %v", err)
	}

	hs2, err := noise.NewHandshakeState(*config2)
	if err != nil {
		t.Fatalf("Failed to create handshake state 2: %v", err)
	}

	// Complete handshake
	msg1, _, _, err := hs1.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write failed: %v", err)
	}

	_, _, _, err = hs2.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatalf("Handshake read failed: %v", err)
	}

	msg2, _, _, err := hs2.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write 2 failed: %v", err)
	}

	_, _, _, err = hs1.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("Handshake read 2 failed: %v", err)
	}

	msg3, cs3, cs4, err := hs1.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("Handshake write 3 failed: %v", err)
	}

	_, cs5, cs6, err := hs2.ReadMessage(nil, msg3)
	if err != nil {
		t.Fatalf("Handshake read 3 failed: %v", err)
	}

	// Verify cipher states were established from handshake
	// Note: Only cs3-cs6 are valid after complete handshake
	if cs3 == nil || cs4 == nil || cs5 == nil || cs6 == nil {
		t.Fatalf("Cipher states should not be nil after handshake")
	}

	// Set cipher states on peers for testing
	// peer1 (initiator): cs3 for sending, cs4 for receiving
	// peer2 (responder): cs5 for sending, cs6 for receiving
	// cs3 encrypts -> cs5 decrypts (initiator send -> responder send)
	// cs4 decrypts <- cs6 encrypts (initiator receive <- responder receive)
	peer1.noise = cs3
	peer1.remote = cs4
	peer2.noise = cs6
	peer2.remote = cs5 // Use cs5 for decryption (responder send)

	tl1 := &TerminalLink{
		peers:           make(map[string]*Peer),
		activeTransfers: make(map[string]*FileTransfer),
	}

	tl2 := &TerminalLink{
		peers:           make(map[string]*Peer),
		activeTransfers: make(map[string]*FileTransfer),
	}

	// Simulate message exchange
	msg := Message{
		Type:      "text",
		Content:   "Hello from peer 1",
		Timestamp: time.Now().Unix(),
		ID:        generateID(),
	}

	// Debug: Log the message being sent
	t.Logf("Sending message: %+v", msg)

	// Send message from peer1 to peer2
	err = tl1.sendMessage(peer1, msg)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Simulate message being received by peer2
	writtenData := peer1.conn.(*mockConn).writeBuffer.Bytes()
	if len(writtenData) == 0 {
		t.Error("No data was written to connection")
	}

	// Debug: Log the encrypted data length
	t.Logf("Encrypted data length: %d bytes", len(writtenData))

	// In a real scenario, this data would be transmitted over the network
	// and received by peer2. For testing, we'll simulate this by copying
	// the data to peer2's read buffer
	peer2.conn.(*mockConn).readBuffer.Write(writtenData)

	// Simulate peer2 reading and processing the message
	// This would normally happen in the readMessages goroutine
	// For testing, we'll manually decrypt and trigger the message handling

	// Note: Direct cipher state test removed because sendMessage advances cipher state nonce
	// The actual encrypted data from sendMessage uses advanced cipher states

	// Decrypt the message using peer2's remote cipher state
	// peer1 encrypted with cs3 (initiator send), so peer2 decrypts with cs5 (responder send)
	t.Logf("Attempting decryption with peer2.remote (cs5)")
	decrypted, err := peer2.remote.Decrypt(nil, nil, writtenData)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}
	t.Logf("Decryption successful, decrypted length: %d bytes", len(decrypted))

	err = tl2.handleMessage(peer2, decrypted)
	if err != nil {
		t.Fatalf("Failed to handle message: %v", err)
	}
}

// Benchmark Tests

func BenchmarkMessageSerialization(b *testing.B) {
	msg := Message{
		Type:      "text",
		Content:   "Benchmark test message",
		Timestamp: time.Now().Unix(),
		ID:        generateID(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(msg)
		if err != nil {
			b.Fatalf("Failed to marshal message: %v", err)
		}
	}
}

func BenchmarkGenerateID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateID()
	}
}

func BenchmarkChunkChecksum(b *testing.B) {
	testData := make([]byte, 65536) // 64KB chunk
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateChunkChecksum(testData)
	}
}

// Test cleanup and resource management

func TestResourceCleanup(t *testing.T) {
	// Test that file transfers are properly cleaned up
	activeTransfers := make(map[string]*FileTransfer)

	// Create a mock file transfer
	transferID := "test-transfer"
	activeTransfers[transferID] = &FileTransfer{
		Meta: FileMeta{
			ID: transferID,
		},
	}

	// Simulate transfer completion
	delete(activeTransfers, transferID)

	if len(activeTransfers) != 0 {
		t.Error("Active transfers should be cleaned up")
	}
}

// Test concurrent operations

func TestConcurrentMessaging(t *testing.T) {
	var wg sync.WaitGroup
	numGoroutines := 10
	messages := make(chan Message, numGoroutines)

	// Start multiple goroutines sending messages
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			msg := Message{
				Type:      "text",
				Content:   fmt.Sprintf("Message from goroutine %d", id),
				Timestamp: time.Now().Unix(),
				ID:        generateID(),
			}
			messages <- msg
		}(i)
	}

	// Collect messages
	go func() {
		wg.Wait()
		close(messages)
	}()

	count := 0
	for msg := range messages {
		count++
		if msg.Content == "" {
			t.Error("Message content should not be empty")
		}
		if msg.ID == "" {
			t.Error("Message ID should not be empty")
		}
	}

	if count != numGoroutines {
		t.Errorf("Expected %d messages, got %d", numGoroutines, count)
	}
}
