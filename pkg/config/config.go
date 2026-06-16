package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all agent configuration.
type Config struct {
	RelayURL     string `mapstructure:"relay_url"`
	AccessKey    string `mapstructure:"access_key"`
	AccessSecret string `mapstructure:"access_secret"`
	DataDir      string `mapstructure:"data_dir"`

	// Local datasource overrides (credential_source: local)
	Datasources []LocalDatasource `mapstructure:"datasources"`

	// Health check interval in minutes (default: 10)
	HealthCheckIntervalMin int `mapstructure:"health_check_interval_min"`

	// Message signing: base64-encoded Ed25519 public key for verifying relay messages.
	// If empty, signature verification is disabled (warn-only mode).
	SigningPublicKey string `mapstructure:"signing_public_key"`

	// Cloud secret provider configs
	AWS   AWSConfig   `mapstructure:"aws"`
	GCP   GCPConfig   `mapstructure:"gcp"`
	Azure AzureConfig `mapstructure:"azure"`
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

	// SSH dynamic mode: CIDR ranges or hostnames that this datasource is allowed to connect to.
	// When host is empty and allowed_hosts is set, the SSH proxy operates in dynamic/pool mode.
	AllowedHosts []string `mapstructure:"allowed_hosts"`

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

	// Validate relay_url scheme
	if cfg.RelayURL != "" {
		u, err := url.Parse(cfg.RelayURL)
		if err != nil {
			return nil, fmt.Errorf("relay_url must be a valid URL: %w", err)
		}
		if u.Scheme != "ws" && u.Scheme != "wss" {
			return nil, fmt.Errorf("relay_url must use ws:// or wss:// scheme, got: %q", cfg.RelayURL)
		}
	}

	return &cfg, nil
}
