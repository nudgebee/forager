package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A discovery datasource must be fully configurable from local YAML: without
// this the only way to set a pack key or directory is server-pushed config,
// which does not exist yet.
func TestLoad_DiscoveryDatasource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forager.yaml")

	yaml := `
relay_url: wss://relay.example/register
access_key: k
access_secret: s
datasources:
  - type: discovery
    name: segment-a
    allowed_hosts:
      - 10.0.1.0/24
      - 10.0.2.5
    discovery:
      pack_public_key: AAAA
      pack_dir: /etc/nudgebee/packs
      known_hosts_file: /etc/nudgebee/known_hosts
      max_rate_pps: 50
      concurrency: 10
      ldap:
        host: dc.corp.local
        base_dn: dc=corp,dc=local
        tls: true
        page_size: 250
    credentials:
      username: nudgebee-ro
      password: pw
      ldap_bind_dn: CN=svc,DC=corp,DC=local
      ldap_bind_password: bindpw
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if len(cfg.Datasources) != 1 {
		t.Fatalf("datasources = %d, want 1", len(cfg.Datasources))
	}

	ds := cfg.Datasources[0]
	if ds.Type != "discovery" {
		t.Errorf("type = %q, want discovery", ds.Type)
	}
	if len(ds.AllowedHosts) != 2 {
		t.Errorf("allowed_hosts = %v, want 2 entries", ds.AllowedHosts)
	}

	d := ds.Discovery
	if d == nil {
		t.Fatal("discovery block did not survive parsing")
	}
	if d.PackPublicKey != "AAAA" {
		t.Errorf("pack_public_key = %q", d.PackPublicKey)
	}
	if d.PackDir != "/etc/nudgebee/packs" {
		t.Errorf("pack_dir = %q", d.PackDir)
	}
	if d.KnownHostsFile != "/etc/nudgebee/known_hosts" {
		t.Errorf("known_hosts_file = %q", d.KnownHostsFile)
	}
	if d.MaxRatePPS != 50 || d.Concurrency != 10 {
		t.Errorf("max_rate_pps = %d, concurrency = %d", d.MaxRatePPS, d.Concurrency)
	}

	if d.LDAP == nil {
		t.Fatal("ldap block did not survive parsing")
	}
	if d.LDAP.Host != "dc.corp.local" || d.LDAP.BaseDN != "dc=corp,dc=local" {
		t.Errorf("ldap host = %q, base_dn = %q", d.LDAP.Host, d.LDAP.BaseDN)
	}
	if !d.LDAP.TLS || d.LDAP.PageSize != 250 {
		t.Errorf("ldap tls = %v, page_size = %d", d.LDAP.TLS, d.LDAP.PageSize)
	}

	// Bind credentials belong with the other secrets, not in the ldap block.
	if ds.Credentials["ldap_bind_password"] != "bindpw" {
		t.Errorf("ldap bind password not carried in credentials: %v", ds.Credentials)
	}
}

// A datasource with no discovery block must still load — the proxy's own
// defaults apply.
func TestLoad_DiscoveryBlockOptional(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "forager.yaml")

	yaml := `
access_key: k
access_secret: s
datasources:
  - type: discovery
    name: sweep-only
    allowed_hosts: ["10.0.1.0/24"]
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if cfg.Datasources[0].Discovery != nil {
		t.Error("absent discovery block should stay nil rather than materialize defaults")
	}
}
