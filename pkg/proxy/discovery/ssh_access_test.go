package discovery

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nudgebee/forager/pkg/proxy"
)

func knownHostsFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("writing known_hosts: %v", err)
	}
	return path
}

func TestSSHAccessEnabled(t *testing.T) {
	if SSHAccessEnabled(map[string]any{}) {
		t.Error("enabled with no flag; ssh_access must be opt-in")
	}
	if SSHAccessEnabled(map[string]any{"ssh_access": "true"}) {
		t.Error("string flag accepted; only a real bool opts in")
	}
	if !SSHAccessEnabled(map[string]any{"ssh_access": true}) {
		t.Error("not enabled with ssh_access: true")
	}
}

// Each guard exists because the sibling turns inventory credentials into a
// shell: without them a misconfiguration silently grants more than intended.
func TestSSHAccessConfigRefusesUnsafeScopes(t *testing.T) {
	kh := knownHostsFile(t)
	base := func() map[string]any {
		return map[string]any{
			"allowed_cidrs":    []string{"192.0.2.10/32"},
			"known_hosts_file": kh,
		}
	}

	cases := []struct {
		name    string
		mutate  func(map[string]any)
		signing bool
		wantErr string
	}{
		{"unsigned", func(map[string]any) {}, false, "signing_public_key"},
		{"no known_hosts", func(c map[string]any) { delete(c, "known_hosts_file") }, true, "known_hosts_file"},
		{"unrestricted scope", func(c map[string]any) { delete(c, "allowed_cidrs") }, true, "allowed_cidrs"},
		{"empty scope", func(c map[string]any) { c["allowed_cidrs"] = []any{} }, true, "allowed_cidrs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(cfg)
			_, err := SSHAccessConfig(cfg, tc.signing)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want mention of %q", err, tc.wantErr)
			}
		})
	}
}

func TestSSHAccessConfigIsDynamicAndScoped(t *testing.T) {
	kh := knownHostsFile(t)
	cfg, err := SSHAccessConfig(map[string]any{
		// JSON-decoded cloud push delivers []any, not []string.
		"allowed_cidrs":    []any{"192.0.2.10/32", "10.0.0.0/24"},
		"known_hosts_file": kh,
		"port":             2222,
	}, true)
	if err != nil {
		t.Fatalf("SSHAccessConfig: %v", err)
	}

	if cfg["host"] != "" {
		t.Errorf("host = %v, want empty (dynamic mode)", cfg["host"])
	}
	hosts, _ := cfg["allowed_hosts"].([]string)
	if len(hosts) != 2 || hosts[0] != "192.0.2.10/32" || hosts[1] != "10.0.0.0/24" {
		t.Errorf("allowed_hosts = %v, want the discovery scope", cfg["allowed_hosts"])
	}
	if cfg["known_hosts"] != kh {
		t.Errorf("known_hosts = %v, want %s", cfg["known_hosts"], kh)
	}
	if cfg["port"] != 2222 {
		t.Errorf("port = %v, want 2222", cfg["port"])
	}
}

func TestSSHAccessSiblingEntry(t *testing.T) {
	discovery := proxy.DatasourceEntry{
		ID: "local:segment-a", Type: "discovery", ProxyType: "discovery-proxy",
		Name: "segment-a", CredentialSource: "local",
	}
	cfg := map[string]any{
		"allowed_cidrs":    []string{"192.0.2.10/32"},
		"known_hosts_file": knownHostsFile(t),
	}
	creds := map[string]string{"username": "inventory", "password": "x"}

	entry, p, err := SSHAccessSibling(discovery, cfg, creds, true, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("SSHAccessSibling: %v", err)
	}
	defer p.Close() // nolint:errcheck

	if entry.ID != "local:segment-a:ssh" || entry.Name != "segment-a-ssh" {
		t.Errorf("entry id/name = %q/%q", entry.ID, entry.Name)
	}
	if entry.Type != "ssh" || entry.ProxyType != "ssh-proxy" {
		t.Errorf("entry type = %q/%q, want ssh/ssh-proxy", entry.Type, entry.ProxyType)
	}
	if entry.CredentialSource != "local" {
		t.Errorf("credential source = %q, want inherited", entry.CredentialSource)
	}
}

func TestSSHAccessSiblingNeedsUsername(t *testing.T) {
	cfg := map[string]any{
		"allowed_cidrs":    []string{"192.0.2.10/32"},
		"known_hosts_file": knownHostsFile(t),
	}
	_, _, err := SSHAccessSibling(proxy.DatasourceEntry{ID: "d"}, cfg, map[string]string{}, true, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("sibling configured without ssh credentials")
	}
}
