package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nudgebee/forager/pkg/config"
	"nudgebee/forager/pkg/proxy"
	proxydb "nudgebee/forager/pkg/proxy/db"
	proxyhttp "nudgebee/forager/pkg/proxy/http"
	proxykafka "nudgebee/forager/pkg/proxy/kafka"
	proxymongo "nudgebee/forager/pkg/proxy/mongodb"
	proxyredis "nudgebee/forager/pkg/proxy/redis"
	proxyssh "nudgebee/forager/pkg/proxy/ssh"
	"nudgebee/forager/pkg/secrets"
	"nudgebee/forager/pkg/ws"
)

func main() {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	logger.Info("starting forager")

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// Initialize credential store
	credStore, err := secrets.NewCloudPushStore(cfg.DataDir, cfg.AccessSecret)
	if err != nil {
		logger.Error("failed to initialize credential store", "err", err)
		os.Exit(1)
	}

	// Initialize secret providers
	secretsMgr := secrets.NewManager(logger)

	// Initialize proxy registry
	registry := proxy.NewRegistry()
	defer registry.CloseAll()

	// Configure local datasources from config file
	for _, ds := range cfg.Datasources {
		configureLocalDatasource(logger, registry, ds)
	}

	// Initialize message handler
	handler := ws.NewHandler(registry, credStore, secretsMgr, logger)

	// Initialize WebSocket client
	client := ws.NewClient(cfg.RelayURL, cfg.AccessKey, cfg.AccessSecret, handler, logger)

	// Wire inventory reporter: sends local datasource list on connect for auto-registration
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

	// Wire metadata reporter: collects version + metadata from datasources async on connect
	client.SetMetadataReporter(func(ctx context.Context) map[string]map[string]any {
		return registry.CollectAllMetadata(ctx, 10*time.Second)
	})

	// Wire health reporter: periodically sends datasource health over WS
	client.SetHealthReporter(func(ctx context.Context) map[string]any {
		report := registry.HealthReport(ctx)
		result := make(map[string]any, len(report))
		for id, h := range report {
			result[id] = h
		}
		return result
	})

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Run WebSocket client (blocking with auto-reconnect)
	if err := client.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("websocket client exited with error", "err", err)
		os.Exit(1)
	}

	logger.Info("forager stopped")
}

func configureLocalDatasource(logger *slog.Logger, registry *proxy.Registry, ds config.LocalDatasource) {
	logger.Info("configuring local datasource", "name", ds.Name, "type", ds.Type)

	// Build config map from local datasource
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

	// Determine proxy type from datasource type
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
		p = proxyssh.New(logger.With("datasource", ds.Name))
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
	default:
		logger.Warn("unsupported local datasource type", "type", ds.Type)
		return
	}

	if err := p.Configure(cfg, ds.Credentials); err != nil {
		logger.Error("failed to configure local datasource", "name", ds.Name, "err", err)
		return
	}

	entry := proxy.DatasourceEntry{
		ID:               "local:" + ds.Name,
		Type:             ds.Type,
		ProxyType:        proxyType,
		Name:             ds.Name,
		CredentialSource: "local",
	}
	registry.Register(entry.ID, entry, p)
}
