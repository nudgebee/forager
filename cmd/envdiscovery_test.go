package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"nudgebee/forager/pkg/config"
)

func TestEnsureSSHKey_GeneratesThenReuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "ssh", "id_ed25519")

	pub, generated, err := ensureSSHKey(path, "nudgebee-forager@lan-test")
	if err != nil {
		t.Fatalf("ensureSSHKey: %v", err)
	}
	if !generated {
		t.Error("generated = false for a missing key")
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") || !strings.HasSuffix(pub, " nudgebee-forager@lan-test") {
		t.Errorf("public key line = %q", pub)
	}

	assertMode(t, filepath.Dir(path), 0o700)
	assertMode(t, path, 0o600)
	assertMode(t, path+".pub", 0o644)

	priv, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(priv)
	if err != nil {
		t.Fatalf("key is not a usable OpenSSH key: %v", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("key type = %s", signer.PublicKey().Type())
	}
	if pubFile, _ := os.ReadFile(path + ".pub"); strings.TrimSpace(string(pubFile)) != pub {
		t.Errorf(".pub = %q, want %q", pubFile, pub)
	}

	// A restart with the volume kept must reuse the key, not replace it.
	again, generated, err := ensureSSHKey(path, "nudgebee-forager@lan-test")
	if err != nil {
		t.Fatalf("second ensureSSHKey: %v", err)
	}
	if generated || again != pub {
		t.Errorf("second call: generated=%v pub=%q, want the existing key", generated, again)
	}
}

func TestEnsureSSHKey_RewritesMissingPub(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	pub, _, err := ensureSSHKey(path, "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + ".pub"); err != nil {
		t.Fatal(err)
	}

	again, generated, err := ensureSSHKey(path, "c")
	if err != nil || generated || again != pub {
		t.Fatalf("got %q generated=%v err=%v, want the existing key", again, generated, err)
	}
	if _, err := os.Stat(path + ".pub"); err != nil {
		t.Errorf(".pub not rewritten: %v", err)
	}
}

func TestEnsureSSHKey_UnreadableKeyIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureSSHKey(path, "c"); err == nil {
		t.Error("garbage key accepted")
	}
	if got, _ := os.ReadFile(path); string(got) != "not a key" {
		t.Error("existing key file was overwritten")
	}
}

// The startup log must carry the public key and the setup hints, and never
// the private key.
func TestProvisionEnvDiscovery_Logs(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("NB_DATA_DIR", dataDir)
	t.Setenv(config.EnvDiscoveryCIDR, "10.0.1.0/24,10.0.0.0/8")
	t.Setenv(config.EnvSSHUser, "ops")
	cfgPath := filepath.Join(t.TempDir(), "forager.yaml")
	if err := os.WriteFile(cfgPath, []byte("access_key: abcd1234ef\naccess_secret: s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	provisionEnvDiscovery(slog.New(slog.NewJSONHandler(&buf, nil)), cfg)

	byLevel := map[string][]map[string]any{}
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		lvl, _ := rec["level"].(string)
		byLevel[lvl] = append(byLevel[lvl], rec)
	}

	if len(byLevel["ERROR"]) != 1 || !strings.Contains(byLevel["ERROR"][0]["err"].(string), "10.0.0.0/8") {
		t.Errorf("want one ERROR for the /8 entry, got %v", byLevel["ERROR"])
	}
	if len(byLevel["WARN"]) != 1 || !strings.Contains(byLevel["WARN"][0]["msg"].(string), "persistent volume") {
		t.Errorf("want one WARN about the persistent volume, got %v", byLevel["WARN"])
	}

	keyPath := filepath.Join(dataDir, "ssh", "id_ed25519")
	var found bool
	for _, rec := range byLevel["INFO"] {
		pub, ok := rec["public_key"].(string)
		if !ok {
			continue
		}
		found = true
		if !strings.HasPrefix(pub, "ssh-ed25519 ") {
			t.Errorf("public_key = %q", pub)
		}
		if want := "ssh-copy-id -f -i " + keyPath + ".pub ops@<vm-ip>"; rec["ssh_copy_id"] != want {
			t.Errorf("ssh_copy_id = %v, want %q", rec["ssh_copy_id"], want)
		}
		if !strings.Contains(rec["msg"].(string), "~ops/.ssh/authorized_keys") {
			t.Errorf("msg lacks the authorized_keys hint: %v", rec["msg"])
		}
	}
	if !found {
		t.Error("public key not logged")
	}
	if strings.Contains(buf.String(), "PRIVATE KEY") {
		t.Error("private key logged")
	}

	// A second start keeps the key and does not warn again.
	buf.Reset()
	provisionEnvDiscovery(slog.New(slog.NewJSONHandler(&buf, nil)), cfg)
	if strings.Contains(buf.String(), "persistent volume") {
		t.Error("warned about a generated key on a restart that reused it")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", path, got, want)
	}
}
