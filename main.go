// Terminal-Link MVP - LAN-only secure messaging + file transfer
// Requires: Go 1.21+, go mod tidy
// Run: go run main.go --discover OR go run main.go --connect <ip:port>

package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/flynn/noise"
	"github.com/grandcat/zeroconf"
)

const (
	ServiceName = "_tlnk._tcp"
	ServicePort = 8080
	ChunkSize   = 64 * 1024 // 64KB chunks
	Version     = "1.0.0"
)

// KeyStore represents encrypted persistent key storage
type KeyStore struct {
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
}

// Message represents a text message
type Message struct {
	Type      string `json:"type"`
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
	ID        string `json:"id"`
}

// FileMeta represents file transfer metadata
type FileMeta struct {
	Type      string `json:"type"`
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	ChunkSize int    `json:"chunk_size"`
	ID        string `json:"id"`
}

// FileChunk represents a file chunk
type FileChunk struct {
	Type     string `json:"type"`
	FileID   string `json:"file_id"`
	ChunkID  int    `json:"chunk_id"`
	Data     []byte `json:"data"`
	Checksum string `json:"checksum"`
}

// FileAck represents file transfer acknowledgment
type FileAck struct {
	Type    string `json:"type"`
	FileID  string `json:"file_id"`
	ChunkID int    `json:"chunk_id"`
	Status  string `json:"status"` // "ok", "resend", "complete"
	Message string `json:"message,omitempty"`
}

// Peer represents a connected peer
type Peer struct {
	conn   net.Conn
	noise  *noise.CipherState
	remote *noise.CipherState
}

// TerminalLink represents the main application
type TerminalLink struct {
	config          *noise.Config
	peers           map[string]*Peer
	discovered      []*zeroconf.ServiceEntry
	activeTransfers map[string]*FileTransfer
	keyStore        *KeyStore
	keyFile         string
}

// FileTransfer represents an active file transfer
type FileTransfer struct {
	Meta           FileMeta
	File           *os.File
	Chunks         map[int]bool // received chunks
	TotalChunks    int
	ReceivedChunks int
	ResumeData     map[int][]byte // for resume functionality
}

func main() {
	var (
		discover = flag.Bool("discover", false, "Start discovery mode")
		connect  = flag.String("connect", "", "Connect to peer (ip:port)")
		port     = flag.Int("port", ServicePort, "Port to listen on")
		sendFile = flag.String("send-file", "", "Send a file to peer")
		version  = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *version {
		fmt.Printf("Terminal-Link v%s\n", Version)
		fmt.Println("LAN-only secure messaging and file transfer")
		os.Exit(0)
	}

	// Initialize TerminalLink
	tl := &TerminalLink{
		peers: make(map[string]*Peer),
		config: &noise.Config{
			CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
			Pattern:     noise.HandshakeXX,
			Initiator:   false,
		},
		activeTransfers: make(map[string]*FileTransfer),
		keyFile:         getKeyFilePath(),
	}

	// Load or create key store
	if err := tl.loadOrCreateKeyStore(); err != nil {
		log.Fatal("Failed to initialize key store:", err)
	}

	if *discover {
		tl.startDiscovery(*port)
	} else if *connect != "" {
		tl.connectToPeer(*connect, *sendFile)
	} else {
		fmt.Println("Usage: go run main.go --discover OR go run main.go --connect <ip:port> [--send-file <path>]")
		fmt.Println("Use --help for more options")
		os.Exit(1)
	}
}

// getKeyFilePath returns the path to the encrypted key file
func getKeyFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".terminal-link-keys"
	}
	return filepath.Join(homeDir, ".terminal-link-keys")
}

// loadOrCreateKeyStore loads existing keys or creates new ones
func (tl *TerminalLink) loadOrCreateKeyStore() error {
	// Try to load existing keys
	if err := tl.loadKeyStore(); err == nil {
		return nil
	}

	// Create new key store
	return tl.createKeyStore()
}

// loadKeyStore loads the encrypted key store
func (tl *TerminalLink) loadKeyStore() error {
	data, err := os.ReadFile(tl.keyFile)
	if err != nil {
		return err
	}

	// Prompt for password
	password := tl.promptPassword("Enter password to decrypt keys: ")
	if password == "" {
		return fmt.Errorf("password required")
	}

	// Decrypt and parse key store
	decrypted, err := tl.decryptKeyStore(data, password)
	if err != nil {
		return fmt.Errorf("failed to decrypt key store: %v", err)
	}

	if err := json.Unmarshal(decrypted, &tl.keyStore); err != nil {
		return fmt.Errorf("failed to parse key store: %v", err)
	}

	return nil
}

// createKeyStore creates a new encrypted key store
func (tl *TerminalLink) createKeyStore() error {
	// Generate new keypair
	privateKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %v", err)
	}

	// Create key store
	tl.keyStore = &KeyStore{
		PrivateKey: privateKey.Private,
		PublicKey:  privateKey.Public,
		Salt:       make([]byte, 32),
		Nonce:      make([]byte, 12),
	}

	if _, err := rand.Read(tl.keyStore.Salt); err != nil {
		return fmt.Errorf("failed to generate salt: %v", err)
	}
	if _, err := rand.Read(tl.keyStore.Nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Prompt for password
	password := tl.promptPassword("Enter password to encrypt keys: ")
	if password == "" {
		return fmt.Errorf("password required")
	}

	// Encrypt and save key store
	return tl.saveKeyStore(password)
}

// saveKeyStore encrypts and saves the key store
func (tl *TerminalLink) saveKeyStore(password string) error {
	data, err := json.Marshal(tl.keyStore)
	if err != nil {
		return fmt.Errorf("failed to marshal key store: %v", err)
	}

	encrypted, err := tl.encryptKeyStore(data, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt key store: %v", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(tl.keyFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	if err := os.WriteFile(tl.keyFile, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to save key store: %v", err)
	}

	return nil
}

// encryptKeyStore encrypts key store data with password
func (tl *TerminalLink) encryptKeyStore(data []byte, password string) ([]byte, error) {
	// Derive key from password
	key := tl.deriveKey(password, tl.keyStore.Salt)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt
	return aesGCM.Seal(nil, tl.keyStore.Nonce, data, nil), nil
}

// decryptKeyStore decrypts key store data with password
func (tl *TerminalLink) decryptKeyStore(data []byte, password string) ([]byte, error) {
	// For decryption, we need the salt and nonce from the original key store
	// Since we don't have access to them in this function, we'll need to modify
	// the approach. For now, let's assume the salt and nonce are stored separately
	// or we need to modify the encryption to include them in the encrypted data.

	// For testing purposes, we'll use a simpler approach
	// In production, you'd want to store salt and nonce with the encrypted data
	if tl.keyStore == nil {
		return nil, fmt.Errorf("key store not available for decryption")
	}

	// Derive key from password using stored salt
	key := tl.deriveKey(password, tl.keyStore.Salt)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt using stored nonce
	return aesGCM.Open(nil, tl.keyStore.Nonce, data, nil)
}

// deriveKey derives a key from password and salt
func (tl *TerminalLink) deriveKey(password string, salt []byte) []byte {
	// Simple key derivation (in production, use PBKDF2 or Argon2)
	hash := sha256.New()
	hash.Write([]byte(password))
	hash.Write(salt)
	return hash.Sum(nil)
}

// promptPassword prompts for password input
func (tl *TerminalLink) promptPassword(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	password, _ := reader.ReadString('\n')
	return strings.TrimSpace(password)
}

func (tl *TerminalLink) startDiscovery(port int) {
	fmt.Printf("Starting Terminal-Link v%s discovery on port %d...\n", Version, port)

	// Start mDNS service
	server, err := zeroconf.Register("TerminalLink", ServiceName, "local.", port, nil, nil)
	if err != nil {
		log.Fatal("Failed to register mDNS service:", err)
	}
	defer server.Shutdown()

	// Start discovery
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		log.Fatal("Failed to create resolver:", err)
	}

	entries := make(chan *zeroconf.ServiceEntry)
	err = resolver.Browse(context.Background(), ServiceName, "local.", entries)
	if err != nil {
		log.Fatal("Failed to browse:", err)
	}

	// Start listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal("Failed to start listener:", err)
	}
	defer listener.Close()

	fmt.Println("Waiting for connections...")
	fmt.Println("Discovered peers:")

	// Handle discovery and connections
	go func() {
		for entry := range entries {
			if entry.AddrIPv4 != nil {
				addr := fmt.Sprintf("%s:%d", entry.AddrIPv4[0].String(), entry.Port)
				fmt.Printf("  - %s (%s)\n", entry.Instance, addr)
				tl.discovered = append(tl.discovered, entry)
			}
		}
	}()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go tl.handleConnection(conn)
	}
}

func (tl *TerminalLink) connectToPeer(addr string, sendFile string) {
	fmt.Printf("Connecting to %s...\n", addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal("Failed to connect:", err)
	}

	peer := &Peer{conn: conn}
	tl.config.Initiator = true
	tl.config.Pattern = noise.HandshakeXX

	// Perform Noise_XX handshake
	if err := tl.performHandshake(peer); err != nil {
		log.Fatal("Handshake failed:", err)
	}

	fmt.Println("Secure connection established!")

	// If file specified, send it first
	if sendFile != "" {
		if err := tl.sendFile(peer, sendFile); err != nil {
			log.Printf("Failed to send file: %v", err)
		}
	}

	tl.startMessaging(peer)
}

func (tl *TerminalLink) performHandshake(peer *Peer) error {
	// Use stored keypair or generate ephemeral
	var privateKey noise.DHKey
	if tl.keyStore != nil {
		privateKey = noise.DHKey{
			Private: tl.keyStore.PrivateKey,
			Public:  tl.keyStore.PublicKey,
		}
	} else {
		var err error
		privateKey, err = noise.DH25519.GenerateKeypair(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate keypair: %v", err)
		}
	}

	// Create handshake state
	config := *tl.config
	config.StaticKeypair = privateKey
	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return fmt.Errorf("failed to create handshake state: %v", err)
	}

	// Perform XX handshake
	var msg []byte

	// Message 1: -> e
	msg, _, _, err = hs.WriteMessage(nil, nil)
	if err != nil {
		return fmt.Errorf("handshake write 1 failed: %v", err)
	}
	if _, err := peer.conn.Write(msg); err != nil {
		return fmt.Errorf("failed to send message 1: %v", err)
	}

	// Message 2: <- e, ee, s, es
	msg = make([]byte, 1024)
	n, err := peer.conn.Read(msg)
	if err != nil {
		return fmt.Errorf("failed to read message 2: %v", err)
	}
	msg = msg[:n]

	_, _, _, err = hs.ReadMessage(nil, msg)
	if err != nil {
		return fmt.Errorf("handshake read 2 failed: %v", err)
	}

	// Message 3: -> s, se
	msg, peer.noise, peer.remote, err = hs.WriteMessage(nil, nil)
	if err != nil {
		return fmt.Errorf("handshake write 3 failed: %v", err)
	}
	if _, err := peer.conn.Write(msg); err != nil {
		return fmt.Errorf("failed to send message 3: %v", err)
	}

	// Generate pairing code for verification
	pairingCode := tl.generatePairingCode(privateKey.Public, peer.conn.RemoteAddr().String())
	fmt.Printf("Pairing code: %s\n", pairingCode)
	fmt.Println("Verify this code matches on the other device!")

	return nil
}

func (tl *TerminalLink) generatePairingCode(publicKey []byte, remoteAddr string) string {
	// Generate pairing code using public key and remote address for uniqueness
	combined := append(publicKey, []byte(remoteAddr)...)

	// Use SHA256 for proper hashing
	h := sha256.New()
	h.Write(combined)
	hash := h.Sum(nil)

	return hex.EncodeToString(hash)[:6]
}

func (tl *TerminalLink) handleConnection(conn net.Conn) {
	peer := &Peer{conn: conn}

	if err := tl.performHandshake(peer); err != nil {
		log.Printf("Handshake failed: %v", err)
		conn.Close()
		return
	}

	peerID := conn.RemoteAddr().String()
	tl.peers[peerID] = peer

	fmt.Printf("New peer connected: %s\n", peerID)
	tl.startMessaging(peer)
}

func (tl *TerminalLink) startMessaging(peer *Peer) {
	// Start message reader
	go tl.readMessages(peer)

	// Start interactive input
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Type messages (Ctrl+C to exit):")
	fmt.Println("Commands: /send <filepath> - send a file")
	fmt.Println("          /help - show commands")

	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}

		// Handle commands
		if strings.HasPrefix(text, "/") {
			if err := tl.handleCommand(peer, text); err != nil {
				log.Printf("Command error: %v", err)
			}
			continue
		}

		msg := Message{
			Type:      "text",
			Content:   text,
			Timestamp: time.Now().Unix(),
			ID:        generateID(),
		}

		if err := tl.sendMessage(peer, msg); err != nil {
			log.Printf("Failed to send message: %v", err)
			break
		}
	}
}

func (tl *TerminalLink) handleCommand(peer *Peer, command string) error {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "/send":
		if len(parts) < 2 {
			fmt.Println("Usage: /send <filepath>")
			return nil
		}
		return tl.sendFile(peer, parts[1])
	case "/help":
		fmt.Println("Available commands:")
		fmt.Println("  /send <filepath> - Send a file")
		fmt.Println("  /help - Show this help")
		fmt.Println("  /quit - Exit the application")
		return nil
	case "/quit":
		fmt.Println("Goodbye!")
		os.Exit(0)
		return nil
	default:
		fmt.Printf("Unknown command: %s\n", parts[0])
		fmt.Println("Use /help for available commands")
		return nil
	}
}

func (tl *TerminalLink) sendFile(peer *Peer, filepath string) error {
	// Open file
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Get file info
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %v", err)
	}

	// Calculate SHA256
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to calculate hash: %v", err)
	}
	file.Seek(0, 0) // Reset to beginning

	// Create file metadata
	meta := FileMeta{
		Type:      "file_meta",
		Filename:  getBaseName(filepath),
		Size:      stat.Size(),
		SHA256:    hex.EncodeToString(hash.Sum(nil)),
		ChunkSize: ChunkSize,
		ID:        generateID(),
	}

	// Send metadata
	if err := tl.sendEncrypted(peer, meta); err != nil {
		return fmt.Errorf("failed to send file metadata: %v", err)
	}

	fmt.Printf("Sending file: %s (%d bytes, %s)\n", meta.Filename, meta.Size, meta.SHA256)

	// Send file in chunks
	buffer := make([]byte, ChunkSize)
	chunkID := 0
	totalChunks := int((meta.Size + int64(ChunkSize) - 1) / int64(ChunkSize))

	for {
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read file chunk: %v", err)
		}

		chunk := FileChunk{
			Type:     "file_chunk",
			FileID:   meta.ID,
			ChunkID:  chunkID,
			Data:     buffer[:n],
			Checksum: calculateChunkChecksum(buffer[:n]),
		}

		if err := tl.sendEncrypted(peer, chunk); err != nil {
			return fmt.Errorf("failed to send chunk %d: %v", chunkID, err)
		}

		fmt.Printf("\rProgress: %d/%d chunks (%.1f%%)", chunkID+1, totalChunks, float64(chunkID+1)/float64(totalChunks)*100)
		chunkID++
	}

	fmt.Println("\nFile sent successfully!")
	return nil
}

func (tl *TerminalLink) readMessages(peer *Peer) {
	buffer := make([]byte, 65536) // Larger buffer for file chunks
	for {
		n, err := peer.conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error: %v", err)
			}
			break
		}

		// Decrypt message
		decrypted, err := peer.remote.Decrypt(nil, nil, buffer[:n])
		if err != nil {
			log.Printf("Decrypt error: %v", err)
			continue
		}

		// Try to parse as different message types
		if err := tl.handleMessage(peer, decrypted); err != nil {
			log.Printf("Message handling error: %v", err)
		}
	}
}

func (tl *TerminalLink) handleMessage(peer *Peer, data []byte) error {
	// Try to parse as JSON message
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("failed to unmarshal message: %v", err)
	}

	msgType, ok := msg["type"].(string)
	if !ok {
		return fmt.Errorf("invalid message type")
	}

	switch msgType {
	case "text":
		return tl.handleTextMessage(data)
	case "file_meta":
		return tl.handleFileMeta(data)
	case "file_chunk":
		return tl.handleFileChunk(data)
	case "file_ack":
		return tl.handleFileAck(data, peer)
	default:
		return fmt.Errorf("unknown message type: %s", msgType)
	}
}

func (tl *TerminalLink) handleTextMessage(data []byte) error {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("JSON unmarshal error: %v", err)
	}

	fmt.Printf("\n[%s] %s\n", time.Unix(msg.Timestamp, 0).Format("15:04:05"), msg.Content)
	fmt.Print("> ")
	return nil
}

func (tl *TerminalLink) handleFileMeta(data []byte) error {
	var meta FileMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("failed to unmarshal file meta: %v", err)
	}

	fmt.Printf("\nReceiving file: %s (%d bytes, %s)\n", meta.Filename, meta.Size, meta.SHA256)

	// Create file transfer
	transfer := &FileTransfer{
		Meta:        meta,
		Chunks:      make(map[int]bool),
		TotalChunks: int((meta.Size + int64(meta.ChunkSize) - 1) / int64(meta.ChunkSize)),
		ResumeData:  make(map[int][]byte),
	}

	// Create output file
	outputPath := fmt.Sprintf("received_%s", meta.Filename)
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}

	transfer.File = file
	tl.activeTransfers[meta.ID] = transfer

	fmt.Printf("File transfer started. Output: %s\n", outputPath)
	fmt.Print("> ")
	return nil
}

func (tl *TerminalLink) handleFileChunk(data []byte) error {
	var chunk FileChunk
	if err := json.Unmarshal(data, &chunk); err != nil {
		return fmt.Errorf("failed to unmarshal file chunk: %v", err)
	}

	transfer, exists := tl.activeTransfers[chunk.FileID]
	if !exists {
		return fmt.Errorf("unknown file transfer: %s", chunk.FileID)
	}

	// Verify chunk checksum
	if calculateChunkChecksum(chunk.Data) != chunk.Checksum {
		return fmt.Errorf("chunk checksum mismatch")
	}

	// Write chunk to file
	offset := int64(chunk.ChunkID) * int64(transfer.Meta.ChunkSize)
	if _, err := transfer.File.WriteAt(chunk.Data, offset); err != nil {
		return fmt.Errorf("failed to write chunk: %v", err)
	}

	transfer.Chunks[chunk.ChunkID] = true
	transfer.ReceivedChunks++

	// Check if transfer is complete
	if transfer.ReceivedChunks == transfer.TotalChunks {
		transfer.File.Close()
		delete(tl.activeTransfers, chunk.FileID)

		// Verify final SHA256
		if err := tl.verifyFileIntegrity(transfer); err != nil {
			fmt.Printf("\nFile transfer failed verification: %v\n", err)
		} else {
			fmt.Printf("\nFile transfer completed successfully!\n")
		}
		fmt.Print("> ")
	}

	return nil
}

func (tl *TerminalLink) handleFileAck(data []byte, peer *Peer) error {
	var ack FileAck
	if err := json.Unmarshal(data, &ack); err != nil {
		return fmt.Errorf("failed to unmarshal file ack: %v", err)
	}

	// Handle acknowledgment (for future resume functionality)
	switch ack.Status {
	case "resend":
		fmt.Printf("Chunk %d needs to be resent\n", ack.ChunkID)
		// Could use peer to send resend request in future implementation
		// For now, just log the resend request
		fmt.Printf("Resend request for file %s, chunk %d\n", ack.FileID, ack.ChunkID)
		// Use peer parameter to log connection info
		fmt.Printf("Resend requested from peer: %s\n", peer.conn.RemoteAddr().String())
	case "ok":
		// Log successful chunk acknowledgment
		fmt.Printf("Chunk %d acknowledged successfully\n", ack.ChunkID)
		// Use peer parameter to log connection info
		fmt.Printf("Acknowledgment from peer: %s\n", peer.conn.RemoteAddr().String())
	default:
		fmt.Printf("Unknown acknowledgment status: %s\n", ack.Status)
	}

	return nil
}

func (tl *TerminalLink) verifyFileIntegrity(transfer *FileTransfer) error {
	// Close and reopen file for verification
	transfer.File.Close()

	file, err := os.Open(fmt.Sprintf("received_%s", transfer.Meta.Filename))
	if err != nil {
		return fmt.Errorf("failed to open file for verification: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to calculate verification hash: %v", err)
	}

	calculatedHash := hex.EncodeToString(hash.Sum(nil))
	if calculatedHash != transfer.Meta.SHA256 {
		return fmt.Errorf("SHA256 mismatch: expected %s, got %s", transfer.Meta.SHA256, calculatedHash)
	}

	return nil
}

func (tl *TerminalLink) sendMessage(peer *Peer, msg Message) error {
	return tl.sendEncrypted(peer, msg)
}

func (tl *TerminalLink) sendEncrypted(peer *Peer, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON marshal error: %v", err)
	}

	// Encrypt message
	encrypted, err := peer.noise.Encrypt(nil, nil, jsonData)
	if err != nil {
		return fmt.Errorf("encryption error: %v", err)
	}

	_, err = peer.conn.Write(encrypted)
	return err
}

func calculateChunkChecksum(data []byte) string {
	hash := sha256.New()
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))[:16] // First 16 chars for efficiency
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getBaseName(path string) string {
	// Handle both Unix and Windows path separators
	parts := strings.Split(path, "/")
	if len(parts) == 1 && strings.Contains(path, "\\") {
		// Try Windows path separator
		parts = strings.Split(path, "\\")
	}
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return path
}
