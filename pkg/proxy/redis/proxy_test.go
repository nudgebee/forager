package redis

import (
	"context"
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
