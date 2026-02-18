package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"nudgebee/forager/pkg/proxy"
)

// readOnlyCommands is the whitelist of allowed commands for security.
var readOnlyCommands = map[string]bool{
	"get": true, "mget": true, "keys": true, "scan": true,
	"type": true, "ttl": true, "pttl": true, "exists": true,
	"dbsize": true, "info": true, "slowlog": true,
	"client": true, "memory": true, "cluster": true,
	"llen": true, "scard": true, "zcard": true, "hlen": true,
	"hgetall": true, "lrange": true, "smembers": true,
	"zrange": true, "strlen": true, "object": true,
}

// Proxy implements the proxy.Proxy interface for Redis.
type Proxy struct {
	mu     sync.RWMutex
	client *redis.Client
	config Config
	logger *slog.Logger
}

// Config holds Redis connection parameters.
type Config struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	DB         int    `json:"db"`
	TLSEnabled bool   `json:"tls_enabled"`
}

// New creates a new Redis proxy.
func New(logger *slog.Logger) *Proxy {
	return &Proxy{logger: logger}
}

func (p *Proxy) Type() string { return "redis-proxy" }

func (p *Proxy) Configure(config map[string]any, creds map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		_ = p.client.Close()
		p.client = nil
	}

	configJSON, _ := json.Marshal(config)
	var cfg Config
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing redis config: %w", err)
	}
	if cfg.Port == 0 {
		cfg.Port = 6379
	}
	p.config = cfg

	opts := &redis.Options{
		Addr: fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		DB:   cfg.DB,
	}
	if password := creds["password"]; password != "" {
		opts.Password = password
	}
	if username := creds["username"]; username != "" {
		opts.Username = username
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return fmt.Errorf("redis ping failed: %w", err)
	}

	p.client = client
	p.logger.Info("redis connection established",
		"host", cfg.Host, "port", cfg.Port, "db", cfg.DB)
	return nil
}

func (p *Proxy) HandleRequest(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("redis not configured")
	}

	switch req.Action {
	case "redis_info":
		return p.handleInfo(ctx, client, "")
	case "redis_info_section":
		section, _ := req.Params["section"].(string)
		return p.handleInfo(ctx, client, section)
	case "redis_slowlog":
		return p.handleSlowlog(ctx, client, req)
	case "redis_client_list":
		return p.handleClientList(ctx, client)
	case "redis_memory_stats":
		return p.handleMemoryStats(ctx, client)
	case "redis_command":
		return p.handleCommand(ctx, client, req)
	case "redis_cluster_info":
		return p.handleClusterInfo(ctx, client)
	case "redis_keyspace_stats":
		return p.handleInfo(ctx, client, "keyspace")
	default:
		return nil, fmt.Errorf("unknown redis action: %s", req.Action)
	}
}

func (p *Proxy) HealthCheck(ctx context.Context) error {
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("redis not configured")
	}
	return client.Ping(ctx).Err()
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		err := p.client.Close()
		p.client = nil
		return err
	}
	return nil
}

// handleInfo returns parsed INFO output.
func (p *Proxy) handleInfo(ctx context.Context, client *redis.Client, section string) (*proxy.ActionResponse, error) {
	var result string
	var err error
	if section != "" {
		result, err = client.Info(ctx, section).Result()
	} else {
		result, err = client.Info(ctx).Result()
	}
	if err != nil {
		return nil, fmt.Errorf("redis INFO failed: %w", err)
	}

	parsed := parseRedisInfo(result)
	return jsonResponse(parsed)
}

// handleSlowlog returns recent slow log entries.
func (p *Proxy) handleSlowlog(ctx context.Context, client *redis.Client, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	count := int64(10)
	if v, ok := req.Params["count"].(float64); ok && v > 0 {
		count = int64(v)
	}

	entries, err := client.SlowLogGet(ctx, count).Result()
	if err != nil {
		return nil, fmt.Errorf("redis SLOWLOG GET failed: %w", err)
	}

	results := make([]map[string]any, len(entries))
	for i, e := range entries {
		results[i] = map[string]any{
			"id":          e.ID,
			"time":        e.Time,
			"duration_us": e.Duration.Microseconds(),
			"args":        e.Args,
			"client_addr": e.ClientAddr,
			"client_name": e.ClientName,
		}
	}
	return jsonResponse(map[string]any{"entries": results, "count": len(results)})
}

// handleClientList returns connected clients.
func (p *Proxy) handleClientList(ctx context.Context, client *redis.Client) (*proxy.ActionResponse, error) {
	result, err := client.ClientList(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("redis CLIENT LIST failed: %w", err)
	}
	return jsonResponse(map[string]any{"clients": result})
}

// handleMemoryStats returns MEMORY STATS output.
func (p *Proxy) handleMemoryStats(ctx context.Context, client *redis.Client) (*proxy.ActionResponse, error) {
	result, err := client.Do(ctx, "MEMORY", "STATS").Result()
	if err != nil {
		return nil, fmt.Errorf("redis MEMORY STATS failed: %w", err)
	}
	return jsonResponse(map[string]any{"memory_stats": result})
}

// handleCommand executes a single read-only Redis command.
func (p *Proxy) handleCommand(ctx context.Context, client *redis.Client, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	command, _ := req.Params["command"].(string)
	if command == "" {
		return nil, fmt.Errorf("missing command parameter")
	}

	cmdLower := strings.ToLower(strings.Fields(command)[0])
	if !readOnlyCommands[cmdLower] {
		return nil, fmt.Errorf("command %q not allowed — only read-only commands are permitted", cmdLower)
	}

	argsRaw, _ := req.Params["args"].([]any)
	cmdArgs := make([]any, 0, len(argsRaw)+1)
	cmdArgs = append(cmdArgs, command)
	cmdArgs = append(cmdArgs, argsRaw...)

	result, err := client.Do(ctx, cmdArgs...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis command failed: %w", err)
	}
	return jsonResponse(map[string]any{"result": result})
}

// handleClusterInfo returns CLUSTER INFO output.
func (p *Proxy) handleClusterInfo(ctx context.Context, client *redis.Client) (*proxy.ActionResponse, error) {
	result, err := client.ClusterInfo(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("redis CLUSTER INFO failed: %w", err)
	}
	parsed := parseRedisInfo(result)
	return jsonResponse(parsed)
}

// CollectMetadata returns version and connection info for the Redis server.
func (p *Proxy) CollectMetadata(ctx context.Context) (map[string]any, error) {
	p.mu.RLock()
	client := p.client
	cfg := p.config
	p.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("redis not configured")
	}

	meta := map[string]any{
		"host": cfg.Host,
		"port": cfg.Port,
	}

	info, err := client.Info(ctx, "server").Result()
	if err == nil {
		parsed := parseRedisInfo(info)
		if v, ok := parsed["server.redis_version"]; ok {
			meta["version"] = v
		}
		if v, ok := parsed["server.redis_mode"]; ok {
			meta["redis_mode"] = v
		}
		if v, ok := parsed["server.os"]; ok {
			meta["os"] = v
		}
	}

	return meta, nil
}

// parseRedisInfo parses Redis INFO format (key:value lines, # section headers).
func parseRedisInfo(info string) map[string]any {
	result := make(map[string]any)
	var currentSection string

	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# ") {
			currentSection = strings.ToLower(strings.TrimPrefix(line, "# "))
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		if currentSection != "" {
			key = currentSection + "." + key
		}
		result[key] = parts[1]
	}
	return result
}

func jsonResponse(data any) (*proxy.ActionResponse, error) {
	b, _ := json.Marshal(data)
	return &proxy.ActionResponse{
		StatusCode: 200,
		Data:       string(b),
	}, nil
}
