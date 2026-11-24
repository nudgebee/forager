package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"nudgebee/forager/pkg/config"
	"nudgebee/forager/pkg/proxy"
)

// Credentials may name a file instead of inlining key material, so a private
// key can stay out of config entirely — mounted as a Kubernetes Secret, say.
func TestResolveKeyFiles(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	const keyMaterial = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(keyPath, []byte(keyMaterial), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	// The trailing newline is stripped; a real OpenSSH key still parses
	// without it (verified against ssh.ParsePrivateKey).
	wantKey := strings.TrimRight(keyMaterial, "\n")

	got, err := resolveKeyFiles(map[string]string{
		"username":         "nudgebee-ro",
		"private_key_file": keyPath,
	})
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	if got["private_key"] != wantKey {
		t.Errorf("private_key = %q, want %q", got["private_key"], wantKey)
	}
	if _, present := got["private_key_file"]; present {
		t.Error("private_key_file survived resolution; proxies would see an unknown credential")
	}
	if got["username"] != "nudgebee-ro" {
		t.Error("unrelated credentials were not carried through")
	}
}

// The input map comes from parsed config that may be shared; rewriting a
// caller's map in place is a poor trade for saving an allocation.
func TestResolveKeyFiles_DoesNotMutateInput(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte("material"), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	in := map[string]string{"private_key_file": keyPath}
	if _, err := resolveKeyFiles(in); err != nil {
		t.Fatalf("resolving: %v", err)
	}

	if in["private_key_file"] != keyPath || in["private_key"] != "" {
		t.Errorf("input map was mutated: %v", in)
	}
}

// Setting both forms would make the effective credential depend on map
// iteration order, so it is rejected rather than silently resolved one way.
func TestResolveKeyFiles_RejectsBothForms(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte("from-file"), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	_, err := resolveKeyFiles(map[string]string{
		"private_key":      "inline",
		"private_key_file": keyPath,
	})
	if err == nil {
		t.Fatal("accepted both private_key and private_key_file")
	}
	if !strings.Contains(err.Error(), "provide one") {
		t.Errorf("error = %q, want it to say which to provide", err)
	}
}

func TestResolveKeyFiles_Errors(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	cases := map[string]string{
		"missing file": filepath.Join(dir, "nope"),
		// An empty key file means a broken mount or a failed secret
		// injection; passing "" to the proxy would fail far less clearly.
		"empty file": empty,
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveKeyFiles(map[string]string{"private_key_file": path}); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

// `echo secret > file` and most editors append a newline; passing it through
// fails authentication for a reason that looks nothing like a stray byte.
// But whitespace a user actually typed is not ours to remove.
func TestResolveKeyFiles_TrimsTrailingNewlinesOnly(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name     string
		contents string
		want     string
	}{
		{"trailing LF", "s3cret\n", "s3cret"},
		{"trailing CRLF", "s3cret\r\n", "s3cret"},
		{"several trailing newlines", "s3cret\n\n\n", "s3cret"},
		{"no trailing newline", "s3cret", "s3cret"},
		// A password may legitimately begin or end with a space; trimming it
		// swaps one baffling auth failure for another.
		{"significant trailing space", "s3cret \n", "s3cret "},
		{"significant leading space", " s3cret\n", " s3cret"},
		// Key material is multi-line and its internal newlines must survive.
		{"multi-line key", "-----BEGIN-----\nabc\ndef\n-----END-----\n", "-----BEGIN-----\nabc\ndef\n-----END-----"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_"))
			if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
				t.Fatalf("writing: %v", err)
			}
			got, err := resolveKeyFiles(map[string]string{"password_file": path})
			if err != nil {
				t.Fatalf("resolving: %v", err)
			}
			if got["password"] != tc.want {
				t.Errorf("password = %q, want %q", got["password"], tc.want)
			}
		})
	}
}

// Credentials with no *_file entries must pass through untouched, including
// the common case of an inline key.
func TestResolveKeyFiles_PassesThroughUnchanged(t *testing.T) {
	in := map[string]string{"username": "u", "private_key": "inline", "password": "p"}
	got, err := resolveKeyFiles(in)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("credentials = %v, want %v", got, in)
	}
	for k, v := range in {
		if got[k] != v {
			t.Errorf("credentials[%q] = %q, want %q", k, got[k], v)
		}
	}
}

// The install scripts write a discovery datasource into forager.yaml. This is
// that block, field for field (deploy/install.sh write_discovery_config): if
// it stops loading, a fresh install silently gets no discovery.
func TestConfigureDatasource_InstallScriptDiscoveryBlock(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signingPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	yaml := fmt.Sprintf(`relay_url: wss://relay.example/register
access_key: k
access_secret: s
data_dir: %[1]s
signing_public_key: "%[3]s"

datasources:
  - type: discovery
    name: "local-network"
    allowed_hosts:
      - "10.0.1.0/24"
    credential_source: local
    credentials:
      username: "ubuntu"
      private_key_file: "%[2]s"
    discovery:
      pack_dir: "%[1]s/packs"
      known_hosts_file: "%[1]s/known_hosts"
      host_key_policy: accept-new
      ssh_access: true
`, dir, keyPath, base64.StdEncoding.EncodeToString(signingPub))
	cfgPath := filepath.Join(dir, "forager.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	registry := proxy.NewRegistry()
	defer registry.CloseAll()
	logger := slog.New(slog.DiscardHandler)
	for _, ds := range cfg.Datasources {
		configureDatasource(logger, registry, nil, true, ds)
	}

	p, ok := registry.Get("local:local-network")
	if !ok {
		t.Fatalf("discovery datasource not registered; registry = %v", registry.All())
	}
	meta, err := p.(proxy.MetadataCollector).CollectMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	actions, _ := meta["actions"].([]string)
	if !slices.Contains(actions, "discovery_inventory") {
		t.Errorf("actions = %v, want discovery_inventory with ssh credentials and no pack key", actions)
	}
	if _, ok := registry.Get("local:local-network:ssh"); !ok {
		t.Errorf("ssh_access sibling not registered; registry = %v", registry.All())
	}
	if _, err := os.Stat(filepath.Join(dir, "known_hosts")); err != nil {
		t.Errorf("accept-new did not create known_hosts_file: %v", err)
	}
}
