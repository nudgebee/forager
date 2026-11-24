package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadWithEnv writes body as a config file and loads it with the given
// environment set. A file is always used so a forager.yaml on the machine
// running the tests is never picked up.
func loadWithEnv(t *testing.T, body string, env map[string]string) *Config {
	t.Helper()
	for _, k := range []string{EnvDiscoveryCIDR, EnvDiscoveryName, EnvSSHUser, EnvPackDir, "NB_SIGNING_PUBLIC_KEY", "NB_DATA_DIR"} {
		t.Setenv(k, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	path := filepath.Join(t.TempDir(), "forager.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

const baseConfig = `
access_key: 3F2A9C1E-77b0-4d2e-9a10-0123456789ab
access_secret: s
data_dir: /data
`

func TestEnvDiscovery_Synthesized(t *testing.T) {
	cfg := loadWithEnv(t, baseConfig, map[string]string{
		EnvDiscoveryCIDR: "10.0.1.0/24, 192.168.1.7/23",
		EnvSSHUser:       "ops",
		EnvPackDir:       "/opt/packs",
	})

	ds, errs := cfg.EnvDiscovery()
	if len(errs) != 0 {
		t.Fatalf("errors = %v, want none", errs)
	}
	if ds == nil {
		t.Fatal("no datasource synthesized")
	}
	if len(cfg.Datasources) != 1 || cfg.Datasources[0].Name != ds.Name {
		t.Fatalf("synthesized datasource not in Datasources: %+v", cfg.Datasources)
	}

	if ds.Type != "discovery" || ds.CredentialSource != "local" {
		t.Errorf("type/credential_source = %q/%q", ds.Type, ds.CredentialSource)
	}
	// Normalized to the network address, as install.sh does.
	if got := strings.Join(ds.AllowedHosts, ","); got != "10.0.1.0/24,192.168.0.0/23" {
		t.Errorf("allowed_hosts = %s", got)
	}
	if ds.Credentials["username"] != "ops" {
		t.Errorf("username = %q, want ops", ds.Credentials["username"])
	}
	if ds.Credentials["private_key_file"] != "/data/ssh/id_ed25519" {
		t.Errorf("private_key_file = %q", ds.Credentials["private_key_file"])
	}
	d := ds.Discovery
	if d.PackDir != "/opt/packs" || d.KnownHostsFile != "/data/known_hosts" || d.HostKeyPolicy != "accept-new" {
		t.Errorf("discovery = %+v", d)
	}
	if d.SSHAccess {
		t.Error("ssh_access on without a signing key")
	}
}

func TestEnvDiscovery_Defaults(t *testing.T) {
	cfg := loadWithEnv(t, baseConfig, map[string]string{EnvDiscoveryCIDR: "10.0.1.0/24"})
	ds, _ := cfg.EnvDiscovery()
	if ds == nil {
		t.Fatal("no datasource synthesized")
	}
	if ds.Credentials["username"] != "ubuntu" {
		t.Errorf("username = %q, want ubuntu", ds.Credentials["username"])
	}
	if ds.Discovery.PackDir != "/etc/nudgebee/packs" {
		t.Errorf("pack_dir = %q", ds.Discovery.PackDir)
	}
}

// The relay keys integrations on (type, name, tenant): the default name must
// differ per agent, so it comes from the access key.
func TestEnvDiscovery_NameFromAccessKey(t *testing.T) {
	cfg := loadWithEnv(t, baseConfig, map[string]string{EnvDiscoveryCIDR: "10.0.1.0/24"})
	if ds, _ := cfg.EnvDiscovery(); ds.Name != "lan-3f2a9c1e" {
		t.Errorf("name = %q, want lan-3f2a9c1e", ds.Name)
	}

	cfg = loadWithEnv(t, baseConfig, map[string]string{EnvDiscoveryCIDR: "10.0.1.0/24", EnvDiscoveryName: "office"})
	if ds, _ := cfg.EnvDiscovery(); ds.Name != "office" {
		t.Errorf("name = %q, want office", ds.Name)
	}

	for key, want := range map[string]string{
		"AB_cd-12.EF34gh": "lan-abcd12ef",
		"x":               "lan-x",
		"--__--":          "lan",
	} {
		if got := defaultDiscoveryName(key); got != want {
			t.Errorf("defaultDiscoveryName(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestEnvDiscovery_BadCIDRSkipped(t *testing.T) {
	cfg := loadWithEnv(t, baseConfig, map[string]string{
		EnvDiscoveryCIDR: "10.0.0.0/16,not-a-cidr,10.0.1.0/24,2001:db8::/120,10.0.4.5",
	})
	ds, errs := cfg.EnvDiscovery()
	if ds == nil {
		t.Fatal("valid entry dropped along with the invalid ones")
	}
	if got := strings.Join(ds.AllowedHosts, ","); got != "10.0.1.0/24" {
		t.Errorf("allowed_hosts = %s, want 10.0.1.0/24", got)
	}
	if len(errs) != 4 {
		t.Fatalf("errors = %v, want 4", errs)
	}
	if !strings.Contains(errs[0].Error(), "wider than /22") {
		t.Errorf("errs[0] = %v, want a width error", errs[0])
	}
}

func TestEnvDiscovery_AllInvalid(t *testing.T) {
	cfg := loadWithEnv(t, baseConfig, map[string]string{EnvDiscoveryCIDR: "10.0.0.0/8"})
	ds, errs := cfg.EnvDiscovery()
	if ds != nil || len(cfg.Datasources) != 0 {
		t.Errorf("datasource synthesized from no valid CIDR: %+v", cfg.Datasources)
	}
	if len(errs) != 1 {
		t.Errorf("errors = %v, want 1", errs)
	}
}

func TestEnvDiscovery_Unset(t *testing.T) {
	cfg := loadWithEnv(t, baseConfig, nil)
	if ds, errs := cfg.EnvDiscovery(); ds != nil || errs != nil || len(cfg.Datasources) != 0 {
		t.Errorf("synthesized without NB_DISCOVERY_CIDR: %+v %v", ds, errs)
	}
}

func TestEnvDiscovery_FileDefinedWins(t *testing.T) {
	body := baseConfig + `
datasources:
  - type: discovery
    name: from-file
    allowed_hosts: ["10.0.2.0/24"]
`
	cfg := loadWithEnv(t, body, map[string]string{EnvDiscoveryCIDR: "10.0.1.0/24"})
	if ds, _ := cfg.EnvDiscovery(); ds != nil {
		t.Errorf("synthesized despite a file-defined discovery datasource: %+v", ds)
	}
	if len(cfg.Datasources) != 1 || cfg.Datasources[0].Name != "from-file" {
		t.Errorf("datasources = %+v", cfg.Datasources)
	}
}

// ssh_access widens the key from pack commands to arbitrary commands, so it
// follows any configured signing key, single or listed.
func TestEnvDiscovery_SSHAccessGatedOnSigningKeys(t *testing.T) {
	cfg := loadWithEnv(t, baseConfig, map[string]string{
		EnvDiscoveryCIDR:        "10.0.1.0/24",
		"NB_SIGNING_PUBLIC_KEY": "AAAA",
	})
	if ds, _ := cfg.EnvDiscovery(); !ds.Discovery.SSHAccess {
		t.Error("ssh_access off with signing_public_key set")
	}

	body := baseConfig + `
signing_public_keys:
  - key_id: k2
    key: BBBB
`
	cfg = loadWithEnv(t, body, map[string]string{EnvDiscoveryCIDR: "10.0.1.0/24"})
	if ds, _ := cfg.EnvDiscovery(); !ds.Discovery.SSHAccess {
		t.Error("ssh_access off with signing_public_keys set")
	}
}
