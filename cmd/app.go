package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"nudgebee/forager/pkg/config"
	"nudgebee/forager/pkg/proxy"
	proxydb "nudgebee/forager/pkg/proxy/db"
	proxydiscovery "nudgebee/forager/pkg/proxy/discovery"
	proxyhttp "nudgebee/forager/pkg/proxy/http"
	proxykafka "nudgebee/forager/pkg/proxy/kafka"
	proxymcp "nudgebee/forager/pkg/proxy/mcp"
	proxymongo "nudgebee/forager/pkg/proxy/mongodb"
	proxyredis "nudgebee/forager/pkg/proxy/redis"
	proxyssh "nudgebee/forager/pkg/proxy/ssh"
	"nudgebee/forager/pkg/secrets"
	"nudgebee/forager/pkg/signing"
	"nudgebee/forager/pkg/ws"
)

// app holds the initialized application components.
type app struct {
	client   *ws.Client
	registry *proxy.Registry
}

// newApp builds the application from config. Does not start anything.
func newApp(configPath string, logger *slog.Logger) (*app, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	credStore, err := secrets.NewCloudPushStore(cfg.DataDir, cfg.AccessSecret)
	if err != nil {
		return nil, err
	}

	secretsMgr := secrets.NewManager(logger,
		secrets.NewAWSSM(cfg.AWS.Region, logger),
		secrets.NewGCPSM(cfg.GCP.ProjectID, cfg.GCP.CredentialsFile, logger),
		secrets.NewAzureKV(cfg.Azure.VaultURL, cfg.Azure.TenantID, cfg.Azure.ClientID, logger),
	)

	verifier, err := signing.NewVerifier(cfg.SigningPublicKey, logger)
	if err != nil {
		return nil, fmt.Errorf("signing verifier: %w", err)
	}

	registry := proxy.NewRegistry()

	for _, ds := range cfg.Datasources {
		configureDatasource(logger, registry, secretsMgr, ds)
	}

	handler := ws.NewHandler(registry, credStore, secretsMgr, verifier, logger)
	client := ws.NewClient(cfg.RelayURL, cfg.AccessKey, cfg.AccessSecret, handler, logger, cfg.HealthCheckIntervalMin)

	client.SetInventoryReporter(func() []ws.DatasourceInventoryItem {
		entries := registry.List()
		items := make([]ws.DatasourceInventoryItem, 0, len(entries))
		for id, entry := range entries {
			items = append(items, ws.DatasourceInventoryItem{
				ID:        id,
				Type:      entry.Type,
				ProxyType: entry.ProxyType,
				Name:      entry.Name,
			})
		}
		return items
	})

	client.SetMetadataReporter(func(ctx context.Context) map[string]map[string]any {
		return registry.CollectAllMetadata(ctx, 10*time.Second)
	})

	client.SetHealthReporter(func(ctx context.Context) map[string]any {
		report := registry.HealthReport(ctx)
		result := make(map[string]any, len(report))
		for id, h := range report {
			result[id] = h
		}
		return result
	})

	return &app{client: client, registry: registry}, nil
}

// run blocks until ctx is cancelled, then cleans up.
func (a *app) run(ctx context.Context) error {
	defer a.registry.CloseAll()
	return a.client.Run(ctx)
}

func configureDatasource(logger *slog.Logger, registry *proxy.Registry, secretsMgr *secrets.Manager, ds config.LocalDatasource) {
	logger.Info("configuring datasource", "name", ds.Name, "type", ds.Type, "credential_source", ds.CredentialSource)

	cfg := map[string]any{}
	if ds.URL != "" {
		cfg["base_url"] = ds.URL
	}
	if ds.Host != "" {
		cfg["host"] = ds.Host
	}
	if ds.Port != 0 {
		cfg["port"] = ds.Port
	}
	if ds.Database != "" {
		cfg["database"] = ds.Database
	}
	if ds.SSLMode != "" {
		cfg["ssl_mode"] = ds.SSLMode
	}
	if ds.TLSEnabled {
		cfg["tls_enabled"] = true
	}
	if ds.ServiceName != "" {
		cfg["service_name"] = ds.ServiceName
	}
	if ds.Encryption != "" {
		cfg["encryption"] = ds.Encryption
	}
	if ds.DataIntegrity != "" {
		cfg["data_integrity"] = ds.DataIntegrity
	}

	var p proxy.Proxy
	var proxyType string
	switch ds.Type {
	case "postgresql", "mysql", "mssql", "clickhouse", "oracle":
		proxyType = "db-proxy"
		p = proxydb.New(ds.Type, logger.With("datasource", ds.Name))
	case "http", "prometheus":
		proxyType = "http-proxy"
		if ds.Credentials != nil {
			if v, ok := ds.Credentials["auth_type"]; ok {
				cfg["auth_type"] = v
			}
		}
		p = proxyhttp.New(logger.With("datasource", ds.Name))
	case "ssh":
		proxyType = "ssh-proxy"
		if len(ds.AllowedHosts) > 0 {
			cfg["allowed_hosts"] = ds.AllowedHosts
		}
		p = proxyssh.New(logger.With("datasource", ds.Name))
	case "discovery":
		proxyType = "discovery-proxy"
		if len(ds.AllowedHosts) > 0 {
			cfg["allowed_cidrs"] = ds.AllowedHosts
		}
		applyDiscoveryConfig(cfg, ds.Discovery)
		p = proxydiscovery.New(logger.With("datasource", ds.Name))
	case "mongodb":
		proxyType = "mongo-proxy"
		p = proxymongo.New(logger.With("datasource", ds.Name))
	case "redis":
		proxyType = "redis-proxy"
		p = proxyredis.New(logger.With("datasource", ds.Name))
	case "kafka":
		proxyType = "kafka-proxy"
		if ds.Brokers != "" {
			cfg["brokers"] = ds.Brokers
		}
		p = proxykafka.New(logger.With("datasource", ds.Name))
	case "mcp":
		proxyType = "mcp-proxy"
		if ds.URL != "" {
			cfg["url"] = ds.URL
		}
		if ds.Transport != "" {
			cfg["transport"] = ds.Transport
		}
		if ds.Command != "" {
			cfg["command"] = ds.Command
		}
		if ds.Args != "" {
			cfg["args"] = ds.Args
		}
		if ds.WorkingDir != "" {
			cfg["working_dir"] = ds.WorkingDir
		}
		if len(ds.Env) > 0 {
			envMap := make(map[string]any, len(ds.Env))
			for k, v := range ds.Env {
				envMap[k] = v
			}
			cfg["env"] = envMap
		}
		if ds.Credentials != nil {
			if v, ok := ds.Credentials["auth_type"]; ok {
				cfg["auth_type"] = v
			}
		}
		p = proxymcp.New(logger.With("datasource", ds.Name))
	default:
		logger.Warn("unsupported local datasource type", "type", ds.Type)
		return
	}

	creds := ds.Credentials
	credSource := ds.CredentialSource
	if credSource == "" {
		credSource = "local"
	}
	if credSource != "local" && credSource != "cloud_push" {
		resolveCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resolved, err := secretsMgr.Resolve(resolveCtx, credSource, ds.CredentialRef)
		if err != nil {
			logger.Error("failed to resolve credentials from secret provider", "name", ds.Name, "source", credSource, "ref", ds.CredentialRef, "err", err)
			return
		}
		creds = resolved
		logger.Info("credentials resolved from secret provider", "name", ds.Name, "source", credSource)
	}

	if err := p.Configure(cfg, creds); err != nil {
		logger.Error("failed to configure datasource", "name", ds.Name, "err", err)
		return
	}

	entry := proxy.DatasourceEntry{
		ID:               "local:" + ds.Name,
		Type:             ds.Type,
		ProxyType:        proxyType,
		Name:             ds.Name,
		CredentialSource: credSource,
	}
	registry.Register(entry.ID, entry, p)
}

// applyDiscoveryConfig copies the discovery block from local YAML into the
// datasource config the proxy consumes. Only non-zero values are set, so the
// proxy's own defaults still apply to anything left out.
//
// In production this config is pushed from the server; this path exists so a
// discovery datasource can also be stood up from a values file.
func applyDiscoveryConfig(cfg map[string]any, d *config.DiscoveryDatasource) {
	if d == nil {
		return
	}

	setIfNotEmpty(cfg, "pack_public_key", d.PackPublicKey)
	setIfNotEmpty(cfg, "pack_dir", d.PackDir)
	setIfNotEmpty(cfg, "known_hosts_file", d.KnownHostsFile)

	setIfPositive(cfg, "port", d.Port)
	setIfPositive(cfg, "concurrency", d.Concurrency)
	setIfPositive(cfg, "host_timeout_seconds", d.HostTimeoutS)
	setIfPositive(cfg, "command_timeout_seconds", d.CommandTimeS)
	setIfPositive(cfg, "dial_timeout_seconds", d.DialTimeoutS)
	setIfPositive(cfg, "max_output_bytes", d.MaxOutputBytes)
	setIfPositive(cfg, "max_rate_pps", d.MaxRatePPS)

	if d.LDAP == nil || d.LDAP.Host == "" {
		return
	}
	ldap := map[string]any{"host": d.LDAP.Host}
	setIfPositive(ldap, "port", d.LDAP.Port)
	setIfPositive(ldap, "timeout_seconds", d.LDAP.TimeoutS)
	setIfPositive(ldap, "max_results", d.LDAP.MaxResults)
	setIfNotEmpty(ldap, "base_dn", d.LDAP.BaseDN)
	if d.LDAP.PageSize > 0 {
		ldap["page_size"] = d.LDAP.PageSize
	}
	if d.LDAP.TLS {
		ldap["tls"] = true
	}
	if d.LDAP.StartTLS {
		ldap["start_tls"] = true
	}
	if d.LDAP.SkipVer {
		ldap["insecure_skip_verify"] = true
	}
	cfg["ldap"] = ldap
}

func setIfNotEmpty(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}

func setIfPositive(m map[string]any, key string, value int) {
	if value > 0 {
		m[key] = value
	}
}
