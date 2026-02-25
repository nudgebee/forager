package config

import (
	"fmt"
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
	Brokers          string            `mapstructure:"brokers"` // Kafka: comma-separated broker list
	CredentialSource string            `mapstructure:"credential_source"`
	CredentialRef    string            `mapstructure:"credential_ref"`
	Credentials      map[string]string `mapstructure:"credentials"`
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
	v.SetDefault("data_dir", "/var/lib/nudgebee")

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
		v.AddConfigPath("/etc/nudgebee")
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

	return &cfg, nil
}
