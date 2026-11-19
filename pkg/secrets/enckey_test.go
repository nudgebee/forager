package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// Replicas of one forager identity share a configured key, so a configured
// key or key file wins over data_dir/enc_key, and generation happens only
// when nothing is configured or stored.
func TestLoadEncKeypair_Precedence(t *testing.T) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(priv[:])
	want, err := keypairFromPrivate(&priv)
	if err != nil {
		t.Fatal(err)
	}

	// A data dir that already holds a different key.
	dataDir := t.TempDir()
	stored, err := LoadOrCreateEncKeypair(dataDir)
	if err != nil {
		t.Fatal(err)
	}

	base64File := filepath.Join(t.TempDir(), "key.b64")
	if err := os.WriteFile(base64File, []byte(b64+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rawFile := filepath.Join(t.TempDir(), "key.raw")
	if err := os.WriteFile(rawFile, priv[:], 0600); err != nil {
		t.Fatal(err)
	}
	otherFile := filepath.Join(t.TempDir(), "other.b64")
	if err := os.WriteFile(otherFile, []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))), 0600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		key, file  string
		dataDir    string
		wantKeyID  string
		wantSource EncKeySource
	}{
		{"configured key beats file and data dir", b64, otherFile, dataDir, want.KeyID(), EncKeyFromConfig},
		{"base64 key file beats data dir", "", base64File, dataDir, want.KeyID(), EncKeyFromFile},
		{"raw key file", "", rawFile, dataDir, want.KeyID(), EncKeyFromFile},
		{"stored key when nothing configured", "", "", dataDir, stored.KeyID(), EncKeyFromDataDir},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, source, err := LoadEncKeypair(tc.key, tc.file, tc.dataDir)
			if err != nil {
				t.Fatal(err)
			}
			if k.KeyID() != tc.wantKeyID || source != tc.wantSource {
				t.Fatalf("got key %s from %s, want %s from %s", k.KeyID(), source, tc.wantKeyID, tc.wantSource)
			}
		})
	}

	// Nothing configured or stored: generated, and kept for the next start.
	empty := t.TempDir()
	k, source, err := LoadEncKeypair("", "", empty)
	if err != nil || source != EncKeyGenerated {
		t.Fatalf("got source %s, err %v; want generated", source, err)
	}
	again, source, err := LoadEncKeypair("", "", empty)
	if err != nil || source != EncKeyFromDataDir || again.KeyID() != k.KeyID() {
		t.Fatalf("second start: source %s, err %v, same key %v", source, err, again.KeyID() == k.KeyID())
	}
}

// A configured key that is malformed stops the start: generating a key
// instead would leave a replica unable to open what its peers can.
func TestLoadEncKeypair_MalformedConfiguredKeyIsAnError(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	badFile := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(badFile, []byte("not base64!"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, key, file string }{
		{"not base64", "not base64!", ""},
		{"wrong length", short, ""},
		{"bad key file", "", badFile},
		{"missing key file", "", filepath.Join(t.TempDir(), "missing")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			if _, _, err := LoadEncKeypair(tc.key, tc.file, dataDir); err == nil {
				t.Fatal("want an error")
			}
			if _, err := os.Stat(filepath.Join(dataDir, encKeyFile)); !os.IsNotExist(err) {
				t.Fatal("a malformed configured key must not fall back to generating one")
			}
		})
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

// A key file other users can read is refused, not used silently.
func TestLoadEncKeypair_RefusesLooseKeyFileMode(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateEncKeypair(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, encKeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateEncKeypair(dir); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("want a mode refusal, got %v", err)
	}
}

// Hosts are compared case-insensitively: a sender that seals for DB.Example.com
// opens for db.example.com.
func TestSealCredentials_HostCaseInsensitive(t *testing.T) {
	k, err := LoadOrCreateEncKeypair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	blob, keyID, err := SealCredentials(k.PublicKey(), "ds", " DB.Example.com ", map[string]string{"password": "p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open(keyID, blob, "ds", "db.example.com"); err != nil {
		t.Fatalf("open: %v", err)
	}
}

// The key file named by enc_private_key_file gets the same mode check.
func TestLoadEncKeypair_RefusesLooseConfiguredKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enc.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadEncKeypair("", path, t.TempDir()); err == nil || !strings.Contains(err.Error(), "defaultMode") {
		t.Fatalf("want a mode refusal, got %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadEncKeypair("", path, t.TempDir()); err != nil {
		t.Fatalf("a 0400 key file should load: %v", err)
	}
}
