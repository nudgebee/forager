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
//
// On disk, credentials.enc keeps the format every forager version reads (a
// map of datasource id → credentials), so rolling the agent back never stops
// it from starting. The host bindings live beside it in credential_hosts.enc;
// an older forager ignores that file.
type CloudPushStore struct {
	mu        sync.RWMutex
	creds     map[string]map[string]string // datasourceID → credentials
	hosts     map[string]string            // datasourceID → bound host
	filePath  string
	hostsPath string
	key       []byte // AES-256 key derived from access_secret
}

// NewCloudPushStore creates a credential store for cloud-pushed credentials.
func NewCloudPushStore(dataDir, accessSecret string) (*CloudPushStore, error) {
	// Derive AES-256 key from access_secret
	hash := sha256.Sum256([]byte(accessSecret))

	store := &CloudPushStore{
		creds:     make(map[string]map[string]string),
		hosts:     make(map[string]string),
		filePath:  filepath.Join(dataDir, "credentials.enc"),
		hostsPath: filepath.Join(dataDir, "credential_hosts.enc"),
		key:       hash[:],
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

	s.creds[datasourceID] = creds
	if host != "" {
		s.hosts[datasourceID] = host
	} else {
		delete(s.hosts, datasourceID)
	}
	return s.saveToDisk()
}

// Get retrieves credentials for a datasource.
func (s *CloudPushStore) Get(datasourceID string) (map[string]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	creds, ok := s.creds[datasourceID]
	return creds, ok
}

// Host returns the host a datasource's credentials were stored for, or ""
// when unknown (no entry, or one written before host binding).
func (s *CloudPushStore) Host(datasourceID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.hosts[datasourceID]
}

// IDs lists every datasource with stored credentials, so a sync can delete
// entries for datasources that never registered (a failed configure) as
// well as registered ones.
func (s *CloudPushStore) IDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.creds))
	for id := range s.creds {
		ids = append(ids, id)
	}
	return ids
}

// Delete removes credentials for a datasource.
func (s *CloudPushStore) Delete(datasourceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.creds[datasourceID]; !ok {
		return nil
	}
	delete(s.creds, datasourceID)
	delete(s.hosts, datasourceID)
	return s.saveToDisk()
}

// saveToDisk encrypts and writes all credentials, then their host bindings.
func (s *CloudPushStore) saveToDisk() error {
	if err := os.MkdirAll(filepath.Dir(s.filePath), 0700); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}
	if err := s.writeEncrypted(s.filePath, s.creds); err != nil {
		return err
	}
	return s.writeEncrypted(s.hostsPath, s.hosts)
}

func (s *CloudPushStore) writeEncrypted(path string, v any) error {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", filepath.Base(path), err)
	}
	encrypted, err := encryptAESGCM(s.key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypting %s: %w", filepath.Base(path), err)
	}
	return os.WriteFile(path, encrypted, 0600)
}

func (s *CloudPushStore) readEncrypted(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	plaintext, err := decryptAESGCM(s.key, data)
	if err != nil {
		return fmt.Errorf("decrypting %s: %w", filepath.Base(path), err)
	}
	return json.Unmarshal(plaintext, v)
}

// loadFromDisk decrypts and loads credentials, then their host bindings. A
// missing hosts file (credentials written by a forager before host binding)
// leaves every entry unbound. Bindings for datasources without credentials
// — left behind if an older forager rewrote credentials.enc — are dropped.
func (s *CloudPushStore) loadFromDisk() error {
	if err := s.readEncrypted(s.filePath, &s.creds); err != nil {
		return err
	}
	if s.creds == nil {
		s.creds = make(map[string]map[string]string)
	}

	hosts := map[string]string{}
	if err := s.readEncrypted(s.hostsPath, &hosts); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("loading credential host bindings: %w", err)
	}
	for id, host := range hosts {
		if _, ok := s.creds[id]; ok {
			s.hosts[id] = host
		}
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
