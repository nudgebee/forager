package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEncKeypair_CreateThenReloadKeepsKey(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreateEncKeypair(dir)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, encKeyFile))
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key file mode %v, want 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dir, encKeyFile+".tmp")); !os.IsNotExist(err) {
		t.Fatal("temp key file left behind")
	}

	k2, err := LoadOrCreateEncKeypair(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if k1.PublicKey() != k2.PublicKey() || k1.KeyID() != k2.KeyID() {
		t.Fatal("reloaded keypair differs from the created one")
	}
}

func TestEncKeypair_ShortKeyFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, encKeyFile), []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateEncKeypair(dir); err == nil {
		t.Fatal("a truncated key file must not be silently replaced")
	}
}

func TestEncKeypair_SealOpenRoundTrip(t *testing.T) {
	k, err := LoadOrCreateEncKeypair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	creds := map[string]string{"bearer_token": "tk_123", "username": "nb"}
	blob, keyID, err := SealCredentials(k.PublicKey(), "ds-1", "tempo.acme.internal", creds)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if keyID != k.KeyID() {
		t.Fatalf("seal named key %s, forager has %s", keyID, k.KeyID())
	}

	got, err := k.Open(keyID, blob, "ds-1", "tempo.acme.internal")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got["bearer_token"] != "tk_123" || got["username"] != "nb" {
		t.Fatalf("got %v", got)
	}

	// A push from a server that does not name the key still opens.
	if _, err := k.Open("", blob, "ds-1", "tempo.acme.internal"); err != nil {
		t.Fatalf("open without key id: %v", err)
	}

	// A proxy type with no single host seals and opens with an empty host.
	blob, _, _ = SealCredentials(k.PublicKey(), "ds-2", "", creds)
	if _, err := k.Open("", blob, "ds-2", ""); err != nil {
		t.Fatalf("open with empty host: %v", err)
	}
}

// The sealed box is anonymous — anyone with the public key can produce one —
// so the datasource id and host ride inside it and are checked on open. A
// blob captured from one push cannot be replayed to point the same
// credentials at another datasource or host.
func TestEncKeypair_OpenRefusesReplayToOtherDatasourceOrHost(t *testing.T) {
	k, _ := LoadOrCreateEncKeypair(t.TempDir())
	blob, keyID, err := SealCredentials(k.PublicKey(), "ds-1", "good.internal", map[string]string{"password": "p"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := k.Open(keyID, blob, "ds-1", "evil.example"); !errors.Is(err, ErrSealedForOther) {
		t.Fatalf("other host: want ErrSealedForOther, got %v", err)
	}
	if _, err := k.Open(keyID, blob, "ds-2", "good.internal"); !errors.Is(err, ErrSealedForOther) {
		t.Fatalf("other datasource: want ErrSealedForOther, got %v", err)
	}
	if _, err := k.Open(keyID, blob, "ds-1", ""); !errors.Is(err, ErrSealedForOther) {
		t.Fatalf("host dropped: want ErrSealedForOther, got %v", err)
	}
}

func TestEncKeypair_OpenRefusesOtherKeyAndGarbage(t *testing.T) {
	ours, _ := LoadOrCreateEncKeypair(t.TempDir())
	theirs, _ := LoadOrCreateEncKeypair(t.TempDir())

	blob, theirID, err := SealCredentials(theirs.PublicKey(), "ds-x", "h", map[string]string{"password": "x"})
	if err != nil {
		t.Fatal(err)
	}

	// Named for another key: refused by id, before any decryption.
	_, err = ours.Open(theirID, blob, "ds-x", "h")
	if !errors.Is(err, ErrEncKeyMismatch) {
		t.Fatalf("want ErrEncKeyMismatch, got %v", err)
	}
	// Unnamed but sealed to another key: refused by the box itself.
	if _, err := ours.Open("", blob, "ds-x", "h"); err == nil {
		t.Fatal("blob sealed to another key must not open")
	}
	if _, err := ours.Open("", "not base64!", "ds-x", "h"); err == nil {
		t.Fatal("non-base64 blob must be refused")
	}
	if _, err := ours.Open("", "AAAA", "ds-x", "h"); err == nil {
		t.Fatal("short blob must be refused")
	}
}

func TestSealCredentials_RejectsBadRecipient(t *testing.T) {
	if _, _, err := SealCredentials("short", "ds", "", map[string]string{"a": "b"}); err == nil {
		t.Fatal("expected an error for a bad recipient key")
	}
}
