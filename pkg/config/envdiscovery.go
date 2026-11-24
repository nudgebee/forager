package config

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
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

// EnvDiscoveryIgnored reports whether NB_DISCOVERY_CIDR was set but ignored
// because the config already defines a discovery datasource.
func (c *Config) EnvDiscoveryIgnored() bool {
	return c.envDiscoveryIgnored
}

// discoveryNamePattern matches what the install scripts accept for
// NB_DISCOVERY_NAME; sshUserPattern is a POSIX login name.
var (
	discoveryNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	sshUserPattern       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
)

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
			c.envDiscoveryIgnored = true
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
	if name != "" && !discoveryNamePattern.MatchString(name) {
		c.envDiscoveryErrs = append(c.envDiscoveryErrs,
			fmt.Errorf("%s=%q may contain only letters, digits, '.', '_' and '-' (max 63); using the default name", EnvDiscoveryName, name))
		name = ""
	}
	if name == "" {
		name = defaultDiscoveryName(c.AccessKey)
	}
	user := strings.TrimSpace(getenv(EnvSSHUser))
	if user != "" && !sshUserPattern.MatchString(user) {
		c.envDiscoveryErrs = append(c.envDiscoveryErrs,
			fmt.Errorf("%s=%q is not a valid login name; using %q", EnvSSHUser, user, defaultSSHUser))
		user = ""
	}
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
