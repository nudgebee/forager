package config

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// Environment variables that build a discovery datasource without a config
// file. They exist for the container image, where the install scripts that
// write the datasource on other platforms never run.
const (
	EnvDiscoveryCIDR = "NB_DISCOVERY_CIDR"
	EnvDiscoveryName = "NB_DISCOVERY_NAME"
	EnvSSHUser       = "NB_SSH_USER"
	EnvPackDir       = "NB_PACK_DIR"
)

const (
	// maxDiscoveryPrefix is the widest scope accepted, as in install.sh:
	// discovery contacts every address in it.
	maxDiscoveryPrefix = 22

	defaultSSHUser = "ubuntu"
	defaultPackDir = "/etc/nudgebee/packs"
)

// EnvDiscovery returns the discovery datasource built from NB_DISCOVERY_CIDR
// (nil if none was), and the NB_DISCOVERY_CIDR entries dropped as invalid.
// The datasource is also in Datasources; it is returned on its own so the
// caller can provision what it points to (the SSH key) before configuring it.
func (c *Config) EnvDiscovery() (*LocalDatasource, []error) {
	return c.envDiscovery, c.envDiscoveryErrs
}

// applyEnvDiscovery adds a discovery datasource built from the environment
// when NB_DISCOVERY_CIDR is set and the config defines no discovery
// datasource of its own. A defined one always wins: the environment is a
// shortcut for the container, not a second source of truth.
//
// Invalid CIDR entries are dropped and recorded, never fatal: a typo in one
// range must not keep the agent, and every other datasource, from starting.
// When no entry is valid nothing is added.
func (c *Config) applyEnvDiscovery(getenv func(string) string) {
	raw := strings.TrimSpace(getenv(EnvDiscoveryCIDR))
	if raw == "" {
		return
	}
	for _, ds := range c.Datasources {
		if ds.Type == "discovery" {
			return
		}
	}

	var cidrs []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		cidr, err := validateDiscoveryCIDR(entry)
		if err != nil {
			c.envDiscoveryErrs = append(c.envDiscoveryErrs, err)
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	if len(cidrs) == 0 {
		return
	}

	name := strings.TrimSpace(getenv(EnvDiscoveryName))
	if name == "" {
		name = defaultDiscoveryName(c.AccessKey)
	}
	user := strings.TrimSpace(getenv(EnvSSHUser))
	if user == "" {
		user = defaultSSHUser
	}
	packDir := strings.TrimSpace(getenv(EnvPackDir))
	if packDir == "" {
		packDir = defaultPackDir
	}

	ds := LocalDatasource{
		Type:             "discovery",
		Name:             name,
		AllowedHosts:     cidrs,
		CredentialSource: "local",
		Credentials: map[string]string{
			"username":         user,
			"private_key_file": filepath.Join(c.DataDir, "ssh", "id_ed25519"),
		},
		Discovery: &DiscoveryDatasource{
			PackDir:        packDir,
			KnownHostsFile: filepath.Join(c.DataDir, "known_hosts"),
			HostKeyPolicy:  "accept-new",
			// ssh_access lets the key run arbitrary commands, which is only
			// acceptable when the relay's commands are signed.
			SSHAccess: len(c.SigningKeyEntries()) > 0,
		},
	}
	c.Datasources = append(c.Datasources, ds)
	c.envDiscovery = &c.Datasources[len(c.Datasources)-1]
}

// defaultDiscoveryName derives a per-agent name. The relay keys integrations
// on (type, name, tenant), so a fixed default would make two agents in one
// tenant share one integration.
func defaultDiscoveryName(accessKey string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(accessKey) {
		if b.Len() == 8 {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "lan"
	}
	return "lan-" + b.String()
}

// validateDiscoveryCIDR accepts an IPv4 CIDR no wider than /22 and returns it
// normalized to its network address (10.0.1.7/24 -> 10.0.1.0/24).
func validateDiscoveryCIDR(s string) (string, error) {
	_, network, err := net.ParseCIDR(s)
	if err != nil || strings.Contains(s, ":") || network.IP.To4() == nil {
		return "", fmt.Errorf("%s entry %q is not an IPv4 CIDR (expected something like 10.0.1.0/24)", EnvDiscoveryCIDR, s)
	}
	if ones, _ := network.Mask.Size(); ones < maxDiscoveryPrefix {
		return "", fmt.Errorf("%s entry %q is wider than /%d; discovery contacts every address in it", EnvDiscoveryCIDR, s, maxDiscoveryPrefix)
	}
	return network.String(), nil
}
