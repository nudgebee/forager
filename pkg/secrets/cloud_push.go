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
//
// Each entry remembers the host its credentials were pushed for. A later
// sync that names a different host but carries no credentials must not reuse
// them: that is how a forged sync would point a stored token at another
// server (see Handler.handleConfigSync).
type CloudPushStore struct {
	mu       sync.RWMutex
	entries  map[string]credEntry // datasourceID → entry
	filePath string
	key      []byte // AES-256 key derived from access_secret
}

type credEntry struct {
	Creds map[string]string `json:"creds"`
	// Host is the host the credentials belong to ("" for entries written
	// before host binding existed).
	Host string `json:"host,omitempty"`
}

// diskFormat is what credentials.enc holds once decrypted. Version 1 was a
// bare map of datasource id → credentials; loadFromDisk still reads it.
type diskFormat struct {
	Version int                  `json:"v"`
	Entries map[string]credEntry `json:"entries"`
}

const diskFormatVersion = 2

// NewCloudPushStore creates a credential store for cloud-pushed credentials.
func NewCloudPushStore(dataDir, accessSecret string) (*CloudPushStore, error) {
	// Derive AES-256 key from access_secret
	hash := sha256.Sum256([]byte(accessSecret))

	store := &CloudPushStore{
		entries:  make(map[string]credEntry),
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

// Set stores credentials for a datasource (in memory + disk) with no host binding.
func (s *CloudPushStore) Set(datasourceID string, creds map[string]string) error {
	return s.SetBound(datasourceID, creds, "")
}

// SetBound stores credentials for a datasource and the host they are for.
func (s *CloudPushStore) SetBound(datasourceID string, creds map[string]string, host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[datasourceID] = credEntry{Creds: creds, Host: host}
	return s.saveToDisk()
}

// Get retrieves credentials for a datasource.
func (s *CloudPushStore) Get(datasourceID string) (map[string]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.entries[datasourceID]
	return e.Creds, ok
}

// Host returns the host a datasource's credentials were stored for, or ""
// when unknown (no entry, or one written before host binding).
func (s *CloudPushStore) Host(datasourceID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.entries[datasourceID].Host
}

// IDs lists every datasource with stored credentials, so a sync can delete
// entries for datasources that never registered (a failed configure) as
// well as registered ones.
func (s *CloudPushStore) IDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.entries))
	for id := range s.entries {
		ids = append(ids, id)
	}
	return ids
}

// Delete removes credentials for a datasource.
func (s *CloudPushStore) Delete(datasourceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.entries[datasourceID]; !ok {
		return nil
	}
	delete(s.entries, datasourceID)
	return s.saveToDisk()
}

// saveToDisk encrypts and writes all credentials to the file.
func (s *CloudPushStore) saveToDisk() error {
	plaintext, err := json.Marshal(diskFormat{Version: diskFormatVersion, Entries: s.entries})
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

// loadFromDisk decrypts and loads credentials from the file, accepting both
// the current format and the version-1 bare map.
func (s *CloudPushStore) loadFromDisk() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	plaintext, err := decryptAESGCM(s.key, data)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	var current diskFormat
	if err := json.Unmarshal(plaintext, &current); err == nil && current.Version == diskFormatVersion {
		if current.Entries == nil {
			current.Entries = make(map[string]credEntry)
		}
		s.entries = current.Entries
		return nil
	}

	var legacy map[string]map[string]string
	if err := json.Unmarshal(plaintext, &legacy); err != nil {
		return fmt.Errorf("credentials file is neither the current nor the legacy format: %w", err)
	}
	s.entries = make(map[string]credEntry, len(legacy))
	for id, creds := range legacy {
		s.entries[id] = credEntry{Creds: creds}
	}
	return nil
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
