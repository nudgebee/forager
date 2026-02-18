package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// CloudPushStore manages credentials pushed from Nudgebee cloud.
// Credentials are stored encrypted on disk and in memory.
type CloudPushStore struct {
	mu       sync.RWMutex
	creds    map[string]map[string]string // datasourceID → {key: value}
	filePath string
	key      []byte // AES-256 key derived from access_secret
}

// NewCloudPushStore creates a credential store for cloud-pushed credentials.
func NewCloudPushStore(dataDir, accessSecret string) (*CloudPushStore, error) {
	// Derive AES-256 key from access_secret
	hash := sha256.Sum256([]byte(accessSecret))

	store := &CloudPushStore{
		creds:    make(map[string]map[string]string),
		filePath: filepath.Join(dataDir, "credentials.enc"),
		key:      hash[:],
	}

	// Try to load existing credentials from disk
	if err := store.loadFromDisk(); err != nil {
		// Not an error if file doesn't exist yet
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("loading credentials: %w", err)
		}
	}

	return store, nil
}

// Set stores credentials for a datasource (in memory + disk).
func (s *CloudPushStore) Set(datasourceID string, creds map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.creds[datasourceID] = creds
	return s.saveToDisk()
}

// Get retrieves credentials for a datasource.
func (s *CloudPushStore) Get(datasourceID string) (map[string]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	creds, ok := s.creds[datasourceID]
	return creds, ok
}

// Delete removes credentials for a datasource.
func (s *CloudPushStore) Delete(datasourceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.creds, datasourceID)
	return s.saveToDisk()
}

// saveToDisk encrypts and writes all credentials to the file.
func (s *CloudPushStore) saveToDisk() error {
	plaintext, err := json.Marshal(s.creds)
	if err != nil {
		return fmt.Errorf("marshaling credentials: %w", err)
	}

	encrypted, err := encryptAESGCM(s.key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	return os.WriteFile(s.filePath, encrypted, 0600)
}

// loadFromDisk decrypts and loads credentials from the file.
func (s *CloudPushStore) loadFromDisk() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	plaintext, err := decryptAESGCM(s.key, data)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	return json.Unmarshal(plaintext, &s.creds)
}

func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
