package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCloudPushStore_SetGetDelete(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCloudPushStore(dir, "test-secret-key")
	if err != nil {
		t.Fatalf("NewCloudPushStore: %v", err)
	}

	// Get non-existent
	_, ok := store.Get("ds-1")
	if ok {
		t.Fatal("expected Get to return false for non-existent key")
	}

	// Set
	creds := map[string]string{"username": "admin", "password": "s3cret"}
	if err := store.Set("ds-1", creds); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Get
	got, ok := store.Get("ds-1")
	if !ok {
		t.Fatal("expected Get to return true")
	}
	if got["username"] != "admin" || got["password"] != "s3cret" {
		t.Fatalf("unexpected creds: %v", got)
	}

	// Delete
	if err := store.Delete("ds-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, ok = store.Get("ds-1")
	if ok {
		t.Fatal("expected Get to return false after Delete")
	}
}

func TestCloudPushStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	secret := "my-access-secret"

	// Create store and set creds
	store1, err := NewCloudPushStore(dir, secret)
	if err != nil {
		t.Fatalf("NewCloudPushStore: %v", err)
	}
	if err := store1.Set("ds-persist", map[string]string{"key": "value123"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Verify file exists on disk
	encFile := filepath.Join(dir, "credentials.enc")
	if _, err := os.Stat(encFile); os.IsNotExist(err) {
		t.Fatal("encrypted file should exist on disk")
	}

	// Create new store with same secret — should load from disk
	store2, err := NewCloudPushStore(dir, secret)
	if err != nil {
		t.Fatalf("NewCloudPushStore (reload): %v", err)
	}

	got, ok := store2.Get("ds-persist")
	if !ok {
		t.Fatal("expected to load persisted creds")
	}
	if got["key"] != "value123" {
		t.Fatalf("unexpected value: %v", got)
	}
}

func TestCloudPushStore_WrongKey(t *testing.T) {
	dir := t.TempDir()

	// Write with one key
	store1, err := NewCloudPushStore(dir, "key-1")
	if err != nil {
		t.Fatalf("NewCloudPushStore: %v", err)
	}
	if err := store1.Set("ds-1", map[string]string{"a": "b"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Try to load with different key — should fail
	_, err = NewCloudPushStore(dir, "key-2")
	if err == nil {
		t.Fatal("expected error when loading with wrong key")
	}
}

func TestCloudPushStore_MultipleDatasources(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCloudPushStore(dir, "secret")
	if err != nil {
		t.Fatalf("NewCloudPushStore: %v", err)
	}

	// Set multiple datasources
	if err := store.Set("ds-1", map[string]string{"user": "u1"}); err != nil {
		t.Fatalf("Set ds-1: %v", err)
	}
	if err := store.Set("ds-2", map[string]string{"user": "u2"}); err != nil {
		t.Fatalf("Set ds-2: %v", err)
	}
	if err := store.Set("ds-3", map[string]string{"user": "u3"}); err != nil {
		t.Fatalf("Set ds-3: %v", err)
	}

	// Delete one
	if err := store.Delete("ds-2"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify
	if _, ok := store.Get("ds-1"); !ok {
		t.Fatal("ds-1 should exist")
	}
	if _, ok := store.Get("ds-2"); ok {
		t.Fatal("ds-2 should not exist")
	}
	if _, ok := store.Get("ds-3"); !ok {
		t.Fatal("ds-3 should exist")
	}
}

func TestCloudPushStore_HostBindingPersists(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCloudPushStore(dir, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetBound("ds-1", map[string]string{"bearer_token": "tk"}, "tempo.acme.internal"); err != nil {
		t.Fatalf("SetBound: %v", err)
	}
	if err := store.Set("ds-2", map[string]string{"password": "p"}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	reloaded, err := NewCloudPushStore(dir, "secret")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.Host("ds-1"); got != "tempo.acme.internal" {
		t.Fatalf("ds-1 host %q", got)
	}
	if got := reloaded.Host("ds-2"); got != "" {
		t.Fatalf("ds-2 host %q, want none", got)
	}
	if got := reloaded.Host("missing"); got != "" {
		t.Fatalf("missing host %q, want none", got)
	}
	if creds, ok := reloaded.Get("ds-1"); !ok || creds["bearer_token"] != "tk" {
		t.Fatalf("ds-1 creds %v %v", creds, ok)
	}
}

// A credentials.enc written before host binding (a bare map) still loads,
// with every entry unbound.
func TestCloudPushStore_LoadsLegacyFormat(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCloudPushStore(dir, "secret")
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"ds-old":{"username":"u","password":"p"}}`)
	encrypted, err := encryptAESGCM(store.key, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credentials.enc"), encrypted, 0600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewCloudPushStore(dir, "secret")
	if err != nil {
		t.Fatalf("reload legacy: %v", err)
	}
	creds, ok := reloaded.Get("ds-old")
	if !ok || creds["username"] != "u" {
		t.Fatalf("legacy entry %v %v", creds, ok)
	}
	if reloaded.Host("ds-old") != "" {
		t.Fatal("legacy entry must be unbound")
	}

	// The next write upgrades the file; a further reload reads the new format.
	if err := reloaded.SetBound("ds-new", map[string]string{"a": "b"}, "h"); err != nil {
		t.Fatal(err)
	}
	again, err := NewCloudPushStore(dir, "secret")
	if err != nil {
		t.Fatalf("reload upgraded: %v", err)
	}
	if _, ok := again.Get("ds-old"); !ok {
		t.Fatal("legacy entry lost on upgrade")
	}
	if again.Host("ds-new") != "h" {
		t.Fatal("new entry lost its host on upgrade")
	}
}

func TestCloudPushStore_DeleteMissingIsNoop(t *testing.T) {
	store, err := NewCloudPushStore(t.TempDir(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete("never-set"); err != nil {
		t.Fatalf("Delete of a missing id: %v", err)
	}
}

func TestEncryptDecryptAESGCM(t *testing.T) {
	key := make([]byte, 32) // AES-256
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("hello world, this is a secret")

	encrypted, err := encryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Ciphertext should differ from plaintext
	if string(encrypted) == string(plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := decryptAESGCM(key, encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestDecryptAESGCM_TooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := decryptAESGCM(key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestDecryptAESGCM_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 0xFF

	encrypted, err := encryptAESGCM(key1, []byte("secret data"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = decryptAESGCM(key2, encrypted)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}
