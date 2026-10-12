package discovery

import (
	"errors"
	"fmt"
	"log/slog"

	"nudgebee/forager/pkg/proxy"
	sshproxy "nudgebee/forager/pkg/proxy/ssh"
)

// SSHAccessSuffix is appended to a discovery datasource ID to form the ID of
// its SSH access sibling.
const SSHAccessSuffix = ":ssh"

// SSHAccessEnabled reports whether a discovery datasource config opts into
// exposing its hosts for ad-hoc commands.
func SSHAccessEnabled(cfg map[string]any) bool {
	v, _ := cfg["ssh_access"].(bool)
	return v
}

// SSHAccessConfig derives the ssh-proxy config for the SSH access sibling of
// a discovery datasource.
//
// Discovery credentials are granted for signed content packs. ssh_access lets
// the same credentials run arbitrary commands, so it is held to a stricter bar
// than inventory: the scope must be explicit (an empty allowed_cidrs means
// "anywhere" to discovery, which is not acceptable for a shell), host keys
// must be verified, and requests must be signed.
func SSHAccessConfig(cfg map[string]any, signingEnabled bool) (map[string]any, error) {
	if !signingEnabled {
		return nil, errors.New("ssh_access requires signing_public_key so commands are verified")
	}

	knownHosts, _ := cfg["known_hosts_file"].(string)
	if knownHosts == "" {
		return nil, errors.New("ssh_access requires known_hosts_file so host keys are verified")
	}

	cidrs := stringSlice(cfg["allowed_cidrs"])
	if len(cidrs) == 0 {
		return nil, errors.New("ssh_access requires a non-empty allowed_cidrs scope")
	}

	out := map[string]any{
		"host":          "", // dynamic mode: the target comes with each request
		"allowed_hosts": cidrs,
		"known_hosts":   knownHosts,
	}
	if port, ok := cfg["port"]; ok {
		out["port"] = port
	}
	if n, ok := cfg["max_output_bytes"]; ok {
		out["max_output_bytes"] = n
	}
	return out, nil
}

// SSHAccessSibling builds and configures the ssh-proxy that exposes a
// discovery datasource's hosts for ad-hoc commands. The returned entry
// registers it as its own datasource, reported to the server as type ssh
// for it, leaving the discovery datasource's type untouched.
func SSHAccessSibling(discovery proxy.DatasourceEntry, cfg map[string]any, creds map[string]string, signingEnabled bool, logger *slog.Logger) (proxy.DatasourceEntry, proxy.Proxy, error) {
	sshCfg, err := SSHAccessConfig(cfg, signingEnabled)
	if err != nil {
		return proxy.DatasourceEntry{}, nil, err
	}

	id := discovery.ID + SSHAccessSuffix
	p := sshproxy.New(logger.With("datasource", id))
	if err := p.Configure(sshCfg, creds); err != nil {
		return proxy.DatasourceEntry{}, nil, fmt.Errorf("configuring ssh access: %w", err)
	}

	entry := proxy.DatasourceEntry{
		ID:               id,
		Type:             "ssh",
		ProxyType:        p.Type(),
		Name:             discovery.Name + "-ssh",
		CredentialSource: discovery.CredentialSource,
		CredentialRef:    discovery.CredentialRef,
	}
	return entry, p, nil
}

// stringSlice accepts both []string (local config) and []any (JSON-decoded
// cloud push) forms, dropping empty entries from either.
func stringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if e != "" {
				out = append(out, e)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok && str != "" {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
