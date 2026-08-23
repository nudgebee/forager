package redis

import (
	"context"
	"crypto/tls"
	"log/slog"
	"os"
	"strings"
	"testing"

	"nudgebee/forager/pkg/proxy"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestProxy_Type(t *testing.T) {
	p := New(testLogger())
	if p.Type() != "redis-proxy" {
		t.Errorf("expected redis-proxy, got %s", p.Type())
	}
}

func TestProxy_NotConfigured(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: "redis_info"})
	if err == nil || err.Error() != "redis not configured" {
		t.Errorf("expected 'redis not configured', got %v", err)
	}
}

func TestProxy_HealthCheck_NotConfigured(t *testing.T) {
	p := New(testLogger())
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Error("expected error for health check on unconfigured proxy")
	}
}

func TestProxy_Close_NoClient(t *testing.T) {
	p := New(testLogger())
	if err := p.Close(); err != nil {
		t.Errorf("Close on nil client should not error: %v", err)
	}
}

func TestProxy_UnknownAction(t *testing.T) {
	// Can't test with nil client (returns not configured), but verify the path
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: "redis_unknown"})
	if err == nil || err.Error() != "redis not configured" {
		t.Errorf("expected not configured error, got %v", err)
	}
}

func TestProxy_Command_MissingParam(t *testing.T) {
	// Verify handleCommand validates command parameter
	p := New(testLogger())
	_, err := p.handleCommand(context.Background(), nil, &proxy.ActionRequest{
		Params: map[string]any{},
	})
	if err == nil || err.Error() != "missing command parameter" {
		t.Errorf("expected missing command error, got %v", err)
	}
}

func TestProxy_Command_NotAllowed(t *testing.T) {
	p := New(testLogger())
	_, err := p.handleCommand(context.Background(), nil, &proxy.ActionRequest{
		Params: map[string]any{"command": "DEL"},
	})
	if err == nil {
		t.Error("expected error for disallowed command")
	}
}

func TestProxy_Command_Allowed(t *testing.T) {
	// GET is allowed, but will fail without a client — that's fine, we're testing the whitelist
	for _, cmd := range []string{"GET", "get", "INFO", "DBSIZE", "KEYS"} {
		if cmdLower := cmd; !readOnlyCommands[strings.ToLower(strings.Fields(cmdLower)[0])] {
			t.Errorf("expected %s to be in whitelist", cmd)
		}
	}
}

func TestParseRedisInfo(t *testing.T) {
	input := `# Server
redis_version:7.0.0
uptime_in_seconds:12345

# Clients
connected_clients:10
`
	result := parseRedisInfo(input)
	if result["server.redis_version"] != "7.0.0" {
		t.Errorf("expected 7.0.0, got %v", result["server.redis_version"])
	}
	if result["clients.connected_clients"] != "10" {
		t.Errorf("expected 10, got %v", result["clients.connected_clients"])
	}
	if result["server.uptime_in_seconds"] != "12345" {
		t.Errorf("expected 12345, got %v", result["server.uptime_in_seconds"])
	}
}

func TestReadOnlyCommands(t *testing.T) {
	allowed := []string{"get", "mget", "keys", "scan", "type", "ttl", "pttl",
		"exists", "dbsize", "info", "slowlog", "client", "memory", "cluster"}
	for _, cmd := range allowed {
		if !readOnlyCommands[cmd] {
			t.Errorf("expected %s to be in readOnlyCommands", cmd)
		}
	}

	disallowed := []string{"del", "set", "flushdb", "flushall", "config"}
	for _, cmd := range disallowed {
		if readOnlyCommands[cmd] {
			t.Errorf("expected %s to NOT be in readOnlyCommands", cmd)
		}
	}
}

func TestBuildRedisOptions_TLS(t *testing.T) {
	cfg := Config{
		Host:       "redis.internal.net",
		Port:       6380,
		DB:         2,
		TLSEnabled: true,
	}
	creds := map[string]string{
		"username": "admin",
		"password": "secret-password",
	}

	opts := buildRedisOptions(cfg, creds)
	if opts.Addr != "redis.internal.net:6380" {
		t.Errorf("expected Addr redis.internal.net:6380, got %s", opts.Addr)
	}
	if opts.DB != 2 {
		t.Errorf("expected DB 2, got %d", opts.DB)
	}
	if opts.Username != "admin" {
		t.Errorf("expected Username admin, got %s", opts.Username)
	}
	if opts.Password != "secret-password" {
		t.Errorf("expected Password secret-password, got %s", opts.Password)
	}
	if opts.TLSConfig == nil {
		t.Fatal("expected TLSConfig to be non-nil when TLSEnabled is true")
	}
	if opts.TLSConfig.ServerName != "redis.internal.net" {
		t.Errorf("expected ServerName redis.internal.net, got %s", opts.TLSConfig.ServerName)
	}
	if opts.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2 (%x), got %x", tls.VersionTLS12, opts.TLSConfig.MinVersion)
	}
}

func TestBuildRedisOptions_Plaintext(t *testing.T) {
	cfg := Config{
		Host:       "127.0.0.1",
		Port:       6379,
		DB:         0,
		TLSEnabled: false,
	}
	creds := map[string]string{}

	opts := buildRedisOptions(cfg, creds)
	if opts.Addr != "127.0.0.1:6379" {
		t.Errorf("expected Addr 127.0.0.1:6379, got %s", opts.Addr)
	}
	if opts.TLSConfig != nil {
		t.Errorf("expected TLSConfig to be nil when TLSEnabled is false, got %+v", opts.TLSConfig)
	}
}

func TestBuildRedisOptions_TLS_IP(t *testing.T) {
	cfg := Config{
		Host:       "10.0.0.1",
		Port:       6379,
		DB:         0,
		TLSEnabled: true,
	}
	creds := map[string]string{}

	opts := buildRedisOptions(cfg, creds)
	if opts.TLSConfig == nil {
		t.Fatal("expected TLSConfig to be non-nil")
	}
	if opts.TLSConfig.ServerName != "10.0.0.1" {
		t.Errorf("expected ServerName 10.0.0.1, got %s", opts.TLSConfig.ServerName)
	}
	if opts.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2 (%x), got %x", tls.VersionTLS12, opts.TLSConfig.MinVersion)
	}
}

func TestBuildRedisOptions_TLS_IPv6(t *testing.T) {
	cfg := Config{
		Host:       "2001:db8::1",
		Port:       6379,
		DB:         0,
		TLSEnabled: true,
	}
	creds := map[string]string{}

	opts := buildRedisOptions(cfg, creds)
	if opts.Addr != "[2001:db8::1]:6379" {
		t.Errorf("expected Addr [2001:db8::1]:6379, got %s", opts.Addr)
	}
	if opts.TLSConfig == nil {
		t.Fatal("expected TLSConfig to be non-nil")
	}
	if opts.TLSConfig.ServerName != "2001:db8::1" {
		t.Errorf("expected ServerName 2001:db8::1, got %s", opts.TLSConfig.ServerName)
	}
	if opts.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2 (%x), got %x", tls.VersionTLS12, opts.TLSConfig.MinVersion)
	}
}
