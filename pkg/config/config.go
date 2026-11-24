package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all agent configuration.
type Config struct {
	RelayURL     string `mapstructure:"relay_url"`
	AccessKey    string `mapstructure:"access_key"`
	AccessSecret string `mapstructure:"access_secret"`
	DataDir      string `mapstructure:"data_dir"`

	// EncPrivateKey is base64 of the 32-byte X25519 private key pushed
	// credentials are sealed to; EncPrivateKeyFile names a file holding the
	// same (base64, or the 32 raw bytes). Every replica of one forager
	// identity must share it. Neither set: {data_dir}/enc_key, created on
	// first start.
	EncPrivateKey     string `mapstructure:"enc_private_key"`
	EncPrivateKeyFile string `mapstructure:"enc_private_key_file"`

	// Local datasource overrides (credential_source: local)
	Datasources []LocalDatasource `mapstructure:"datasources"`

	// Health check interval in minutes (default: 10)
	HealthCheckIntervalMin int `mapstructure:"health_check_interval_min"`

	// Message signing: base64-encoded Ed25519 public key for verifying relay messages.
	// If empty and signing_public_keys is empty, signature verification is
	// disabled (warn-only mode).
	SigningPublicKey string `mapstructure:"signing_public_key"`

	// SigningPublicKeys lists further verification keys, each with the key_id
	// the relay signs with, so a relay key can be rotated: add the new key
	// here, switch the relay, then remove the old one.
	SigningPublicKeys []SigningKey `mapstructure:"signing_public_keys"`

	// SecretRefAllowlist lists the secret-manager reference prefixes an
	// http-proxy datasource pushed from Nudgebee may resolve (for example
	// "arn:aws:secretsmanager:eu-west-1:123456789012:secret:nudgebee/").
	// Empty: only HTTP Proxy, Prometheus, Loki and SigNoz datasources (which
	// used secret managers before this list) may resolve refs, any ref; other
	// http-proxy datasources cannot use a secret manager. Other proxy types
	// are not restricted.
	SecretRefAllowlist []string `mapstructure:"secret_ref_allowlist"`

	// Cloud secret provider configs
	AWS   AWSConfig   `mapstructure:"aws"`
	GCP   GCPConfig   `mapstructure:"gcp"`
	Azure AzureConfig `mapstructure:"azure"`

	// envDiscovery is the discovery datasource built from NB_DISCOVERY_CIDR
	// (see envdiscovery.go); nil when none was. envDiscoveryErrs holds the
	// entries of NB_DISCOVERY_CIDR that were dropped.
	envDiscovery     *LocalDatasource
	envDiscoveryErrs []error
	// envDiscoveryIgnored is set when NB_DISCOVERY_CIDR was set but the config
	// already defines a discovery datasource, which wins.
	envDiscoveryIgnored bool
}

// SigningKey is one entry of signing_public_keys.
type SigningKey struct {
	KeyID string `mapstructure:"key_id"`
	Key   string `mapstructure:"key"`
}

// SigningKeyEntries is every configured verification key: the single
// signing_public_key (no key id) followed by signing_public_keys.
func (c *Config) SigningKeyEntries() []SigningKey {
	var out []SigningKey
	if c.SigningPublicKey != "" {
		out = append(out, SigningKey{Key: c.SigningPublicKey})
	}
	return append(out, c.SigningPublicKeys...)
}

// DiscoveryDatasource configures a discovery datasource from local YAML.
// Field names mirror the discovery proxy's config keys so the two stay
// readable side by side.
type DiscoveryDatasource struct {
	// PackPublicKey verifies content packs. Optional: when set, every pack
	// must be signed by it; when empty, packs in pack_dir run unsigned.
	PackPublicKey string `mapstructure:"pack_public_key"`

	// PackDir holds packs as linux-inventory-v<N>.yaml.
	PackDir string `mapstructure:"pack_dir"`

	// KnownHostsFile enables SSH host key verification when set.
	KnownHostsFile string `mapstructure:"known_hosts_file"`

	// HostKeyPolicy is "strict" (default) or "accept-new": record the key of
	// a host known_hosts_file has no entry for, and still refuse a changed
	// key. Requires known_hosts_file. Also applies to the ssh_access sibling.
	HostKeyPolicy string `mapstructure:"host_key_policy"`

	// SSHAccess also exposes the in-scope hosts for ad-hoc commands through
	// a sibling ssh-proxy datasource, using the same credentials. Off by
	// default: it widens what the credentials were granted for. Requires
	// signing_public_key, known_hosts_file and a non-empty allowed_hosts.
	SSHAccess bool `mapstructure:"ssh_access"`

	Port           int `mapstructure:"port"`
	Concurrency    int `mapstructure:"concurrency"`
	HostTimeoutS   int `mapstructure:"host_timeout_seconds"`
	CommandTimeS   int `mapstructure:"command_timeout_seconds"`
	DialTimeoutS   int `mapstructure:"dial_timeout_seconds"`
	MaxOutputBytes int `mapstructure:"max_output_bytes"`
	MaxRatePPS     int `mapstructure:"max_rate_pps"`

	// LDAP enables discovery_ldap. Empty host leaves it unconfigured.
	LDAP *DiscoveryLDAP `mapstructure:"ldap"`
}

// DiscoveryLDAP is the directory connection for discovery_ldap. The bind
// credentials live in the datasource's credentials block (ldap_bind_dn,
// ldap_bind_password), not here, so they stay with the other secrets.
type DiscoveryLDAP struct {
	Host       string `mapstructure:"host"`
	Port       int    `mapstructure:"port"`
	TLS        bool   `mapstructure:"tls"`
	StartTLS   bool   `mapstructure:"start_tls"`
	SkipVer    bool   `mapstructure:"insecure_skip_verify"`
	BaseDN     string `mapstructure:"base_dn"`
	TimeoutS   int    `mapstructure:"timeout_seconds"`
	PageSize   uint32 `mapstructure:"page_size"`
	MaxResults int    `mapstructure:"max_results"`
}

// LocalDatasource represents a datasource configured locally in the agent YAML.
type LocalDatasource struct {
	Type             string            `mapstructure:"type"`
	Name             string            `mapstructure:"name"`
	URL              string            `mapstructure:"url"`
	Host             string            `mapstructure:"host"`
	Port             int               `mapstructure:"port"`
	Database         string            `mapstructure:"database"`
	Brokers          string            `mapstructure:"brokers"`        // Kafka: comma-separated broker list
	SSLMode          string            `mapstructure:"ssl_mode"`       // PostgreSQL: disable, require, verify-ca, verify-full
	TLSEnabled       bool              `mapstructure:"tls_enabled"`    // MySQL/MSSQL/ClickHouse: enable TLS
	ServiceName      string            `mapstructure:"service_name"`   // Oracle: service name override
	Encryption       string            `mapstructure:"encryption"`     // Oracle: ACCEPTED, REJECTED, REQUESTED, REQUIRED
	DataIntegrity    string            `mapstructure:"data_integrity"` // Oracle: ACCEPTED, REJECTED, REQUESTED, REQUIRED
	CredentialSource string            `mapstructure:"credential_source"`
	CredentialRef    string            `mapstructure:"credential_ref"`
	Credentials      map[string]string `mapstructure:"credentials"`

	// HTTP / Prometheus fields. CA and client certificates go in credentials
	// (ca_cert, client_cert, client_key, each also accepted as *_file).
	TLSSkipVerify    bool  `mapstructure:"tls_skip_verify"`
	FollowRedirects  bool  `mapstructure:"follow_redirects"`
	MaxResponseBytes int64 `mapstructure:"max_response_bytes"`

	// SSH dynamic mode: CIDR ranges or hostnames that this datasource is allowed to connect to.
	// When host is empty and allowed_hosts is set, the SSH proxy operates in dynamic/pool mode.
	AllowedHosts []string `mapstructure:"allowed_hosts"`

	// SSH host key verification: KnownHosts is an OpenSSH known_hosts path;
	// HostKeyPolicy is "strict" (default) or "accept-new" (record unknown
	// hosts' keys, refuse changed ones; requires known_hosts).
	KnownHosts    string `mapstructure:"known_hosts"`
	HostKeyPolicy string `mapstructure:"host_key_policy"`

	// Discovery fields. Scope (allowed_cidrs) reuses allowed_hosts above.
	// In production these arrive as server-pushed datasource config; these
	// exist so a discovery datasource can also be stood up from local YAML.
	Discovery *DiscoveryDatasource `mapstructure:"discovery"`

	// MCP fields
	Transport  string            `mapstructure:"transport"`   // http, sse, stdio
	Command    string            `mapstructure:"command"`     // MCP stdio: command to run
	Args       string            `mapstructure:"args"`        // MCP stdio: command args (space-separated)
	Env        map[string]string `mapstructure:"env"`         // MCP stdio: environment variables
	WorkingDir string            `mapstructure:"working_dir"` // MCP stdio: working directory
}

// AWSConfig holds AWS-specific configuration.
type AWSConfig struct {
	Region string `mapstructure:"region"`
}

// GCPConfig holds GCP-specific configuration.
type GCPConfig struct {
	ProjectID       string `mapstructure:"project_id"`
	CredentialsFile string `mapstructure:"credentials_file"`
}

// AzureConfig holds Azure-specific configuration.
type AzureConfig struct {
	VaultURL string `mapstructure:"vault_url"`
	TenantID string `mapstructure:"tenant_id"`
	ClientID string `mapstructure:"client_id"`
}

// Load reads configuration from file and environment variables.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("relay_url", "wss://relay.nudgebee.com/register")
	v.SetDefault("data_dir", DefaultDataDir)
	v.SetDefault("health_check_interval_min", 10)

	// Environment variable overrides (NB_ prefix)
	v.SetEnvPrefix("NB")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Explicitly bind keys that may only come from env vars,
	// since viper's AutomaticEnv + Unmarshal doesn't resolve
	// env vars for keys absent from the config file.
	_ = v.BindEnv("access_key")
	_ = v.BindEnv("access_secret")
	_ = v.BindEnv("enc_private_key")
	_ = v.BindEnv("enc_private_key_file")
	_ = v.BindEnv("relay_url")
	_ = v.BindEnv("data_dir")
	_ = v.BindEnv("health_check_interval_min")
	_ = v.BindEnv("signing_public_key")

	// Cloud secret provider env vars (nested keys need explicit binding)
	_ = v.BindEnv("aws.region")
	_ = v.BindEnv("gcp.project_id")
	_ = v.BindEnv("gcp.credentials_file")
	_ = v.BindEnv("azure.vault_url")
	_ = v.BindEnv("azure.tenant_id")
	_ = v.BindEnv("azure.client_id")

	// Config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("forager")
		v.SetConfigType("yaml")
		v.AddConfigPath(DefaultConfigDir)
		v.AddConfigPath(".")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
		// Config file not found is OK if env vars are set
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if cfg.AccessKey == "" {
		return nil, fmt.Errorf("access_key is required (set NB_ACCESS_KEY or access_key in config)")
	}
	if cfg.AccessSecret == "" {
		return nil, fmt.Errorf("access_secret is required (set NB_ACCESS_SECRET or access_secret in config)")
	}

	cfg.applyEnvDiscovery(os.Getenv)

	return &cfg, nil
}
