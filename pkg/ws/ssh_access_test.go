package ws

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"nudgebee/forager/pkg/proxy"
	"nudgebee/forager/pkg/secrets"
	"nudgebee/forager/pkg/signing"
)

func discoverySyncMsg(t *testing.T, sshAccess bool, knownHosts string, priv ed25519.PrivateKey) []byte {
	t.Helper()
	return signLikeRelay(t, map[string]any{
		"action":     "datasource_config_sync",
		"account_id": "acc-1",
		"datasources": []any{map[string]any{
			"id":         "ds-disc",
			"type":       "discovery",
			"proxy_type": "discovery-proxy",
			"name":       "segment-a",
			"config": map[string]any{
				"ssh_access":       sshAccess,
				"known_hosts_file": knownHosts,
			},
			"allowed_hosts":     []any{"192.0.2.10/32"},
			"credentials":       map[string]any{"username": "inventory", "password": "x"},
			"credential_source": "cloud_push",
		}},
	}, priv)
}

func signedHandler(t *testing.T) (*Handler, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	logger := slog.New(slog.DiscardHandler)
	verifier, err := signing.NewVerifier(base64.StdEncoding.EncodeToString(pub), logger)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	store, err := secrets.NewCloudPushStore(t.TempDir(), "test-secret")
	if err != nil {
		t.Fatalf("cred store: %v", err)
	}
	return NewHandler(proxy.NewRegistry(), store, secrets.NewManager(logger), verifier, logger), priv
}

// A cloud-pushed discovery datasource with ssh_access registers both the
// discovery proxy and an ssh sibling; turning the flag off removes the sibling.
func TestConfigSync_DiscoverySSHAccessSibling(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h, priv := signedHandler(t)

	if _, err := h.HandleMessage(context.Background(), discoverySyncMsg(t, true, kh, priv)); err != nil {
		t.Fatalf("sync: %v", err)
	}
	entries := h.registry.List()
	if e, ok := entries["ds-disc"]; !ok || e.ProxyType != "discovery-proxy" {
		t.Fatalf("discovery datasource not registered (unknown proxy type?): %+v", entries)
	}
	sib, ok := entries["ds-disc:ssh"]
	if !ok {
		t.Fatalf("ssh sibling not registered: %+v", entries)
	}
	if sib.Type != "ssh" || sib.ProxyType != "ssh-proxy" {
		t.Errorf("sibling type = %s/%s", sib.Type, sib.ProxyType)
	}

	if _, err := h.HandleMessage(context.Background(), discoverySyncMsg(t, false, kh, priv)); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if _, ok := h.registry.List()["ds-disc:ssh"]; ok {
		t.Error("sibling survived ssh_access being turned off")
	}
	if _, ok := h.registry.List()["ds-disc"]; !ok {
		t.Error("discovery datasource removed along with the sibling")
	}
}

// Without signing the sibling must not start, even though the flag is set.
func TestConfigSync_SSHAccessRefusedWhenUnsigned(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h := newTestHandler(t) // verifier disabled
	_, priv, _ := ed25519.GenerateKey(nil)

	if _, err := h.HandleMessage(context.Background(), discoverySyncMsg(t, true, kh, priv)); err != nil {
		t.Fatalf("sync: %v", err)
	}
	entries := h.registry.List()
	if _, ok := entries["ds-disc"]; !ok {
		t.Fatal("discovery datasource should still register")
	}
	if _, ok := entries["ds-disc:ssh"]; ok {
		t.Error("ssh sibling registered without signing")
	}
}

// A push that omits "config" must not panic when allowed_hosts is injected.
func TestConfigSync_MissingConfigWithAllowedHosts(t *testing.T) {
	h := newTestHandler(t)
	for _, pt := range []string{"discovery-proxy", "ssh-proxy"} {
		msg := `{"action":"datasource_config_sync","account_id":"a","datasources":[` +
			`{"id":"ds-1","type":"x","proxy_type":"` + pt + `","name":"n",` +
			`"allowed_hosts":["10.0.0.0/24"],"credential_source":"cloud_push"}]}`
		if _, err := h.HandleMessage(context.Background(), []byte(msg)); err != nil {
			t.Fatalf("%s: %v", pt, err)
		}
	}
}
