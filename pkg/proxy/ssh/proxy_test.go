package ssh

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"nudgebee/forager/pkg/proxy"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestProxy_Type(t *testing.T) {
	p := New(testLogger())
	if p.Type() != "ssh-proxy" {
		t.Fatalf("expected ssh-proxy, got %s", p.Type())
	}
}

func TestProxy_HandleRequest_NotConfigured(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "ls"},
	})
	if err == nil {
		t.Fatal("expected error for unconfigured proxy")
	}
}

func TestProxy_HandleRequest_UnknownAction(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "unknown_action",
	})
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestProxy_HandleExec_MissingCommand(t *testing.T) {
	p := New(testLogger())
	p.client = nil // force not connected path won't be hit since command check is first
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error for missing command")
	}
}

func TestProxy_HandleUpload_MissingPath(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_upload",
		Params: map[string]any{"content": "aGVsbG8="},
	})
	if err == nil {
		t.Fatal("expected error for missing remote_path")
	}
}

func TestProxy_HandleUpload_MissingContent(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_upload",
		Params: map[string]any{"remote_path": "/tmp/test"},
	})
	if err == nil {
		t.Fatal("expected error for missing content")
	}
}

func TestProxy_HandleUpload_InvalidBase64(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_upload",
		Params: map[string]any{"remote_path": "/tmp/test", "content": "not-valid-base64!!!"},
	})
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestProxy_HandleDownload_MissingPath(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_download",
		Params: map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error for missing remote_path")
	}
}

func TestProxy_HandleListDir_MissingPath(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_list_dir",
		Params: map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error for missing remote_path")
	}
}

func TestProxy_Configure_MissingHost_StaticMode(t *testing.T) {
	// With no host and no allowed_hosts, dynamic mode still works (no allowlist = allow all)
	p := New(testLogger())
	err := p.Configure(map[string]any{}, map[string]string{"username": "u", "password": "p"})
	if err != nil {
		t.Fatalf("expected dynamic mode configure to succeed, got %v", err)
	}
	if !p.dynamic {
		t.Fatal("expected proxy to be in dynamic mode when host is empty")
	}
}

func TestProxy_Configure_MissingUsername(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{"host": "example.com"}, map[string]string{"password": "p"})
	if err == nil {
		t.Fatal("expected error for missing username")
	}
}

func TestProxy_Configure_NoAuth(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{"host": "example.com"}, map[string]string{"username": "u"})
	if err == nil {
		t.Fatal("expected error for no auth method")
	}
}

func TestProxy_Configure_InvalidKey(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{"host": "example.com"}, map[string]string{
		"username":    "u",
		"private_key": "not-a-valid-pem-key",
	})
	if err == nil {
		t.Fatal("expected error for invalid PEM key")
	}
}

func TestProxy_Configure_Defaults(t *testing.T) {
	p := New(testLogger())
	// This will fail at ssh.Dial but config should be parsed with defaults
	_ = p.Configure(map[string]any{"host": "192.0.2.1"}, map[string]string{
		"username": "u",
		"password": "p",
	})
	// Check defaults were applied (config is set even though Dial fails)
	if p.config.Port != defaultPort {
		t.Fatalf("expected default port %d, got %d", defaultPort, p.config.Port)
	}
	if p.config.MaxOutputBytes != defaultMaxOutputBytes {
		t.Fatalf("expected default max_output_bytes %d, got %d", defaultMaxOutputBytes, p.config.MaxOutputBytes)
	}
}

func TestProxy_HealthCheck_NotConfigured(t *testing.T) {
	p := New(testLogger())
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error for health check without connection")
	}
}

func TestProxy_Close_NoClient(t *testing.T) {
	p := New(testLogger())
	err := p.Close()
	if err != nil {
		t.Fatalf("expected no error closing nil client, got %v", err)
	}
}

func TestBuildAuthMethods_Password(t *testing.T) {
	methods, err := buildAuthMethods(map[string]string{"password": "secret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected 1 auth method, got %d", len(methods))
	}
}

func TestBuildAuthMethods_Empty(t *testing.T) {
	_, err := buildAuthMethods(map[string]string{})
	if err == nil {
		t.Fatal("expected error for empty auth methods")
	}
}

func TestParseFileMode(t *testing.T) {
	m := parseFileMode(0755)
	if m != os.FileMode(0755) {
		t.Fatalf("expected 0755, got %v", m)
	}
}

// --- Dynamic mode tests ---

func TestProxy_Configure_DynamicMode(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{
		"allowed_hosts": []any{"10.0.0.0/8", "192.168.1.0/24"},
	}, map[string]string{"username": "u", "password": "p"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.dynamic {
		t.Fatal("expected proxy to be in dynamic mode")
	}
	if p.sshConfig == nil {
		t.Fatal("expected sshConfig to be set in dynamic mode")
	}
	if len(p.allowedNets) != 2 {
		t.Fatalf("expected 2 allowed nets, got %d", len(p.allowedNets))
	}
	_ = p.Close()
}

func TestProxy_Configure_DynamicMode_WithHostnames(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{
		"allowed_hosts": []any{"10.0.0.0/8", "bastion.example.com"},
	}, map[string]string{"username": "u", "password": "p"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.allowedNets) != 1 {
		t.Fatalf("expected 1 CIDR net, got %d", len(p.allowedNets))
	}
	if len(p.allowedHosts) != 1 {
		t.Fatalf("expected 1 hostname, got %d", len(p.allowedHosts))
	}
	_ = p.Close()
}

func TestProxy_DynamicMode_MissingHost(t *testing.T) {
	p := New(testLogger())
	_ = p.Configure(map[string]any{}, map[string]string{"username": "u", "password": "p"})

	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "ls"},
	})
	if err == nil {
		t.Fatal("expected error when host is missing in dynamic mode request")
	}
	_ = p.Close()
}

func TestProxy_DynamicMode_HostNotAllowed(t *testing.T) {
	p := New(testLogger())
	_ = p.Configure(map[string]any{
		"allowed_hosts": []any{"10.0.0.0/8"},
	}, map[string]string{"username": "u", "password": "p"})

	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "ls", "host": "192.168.1.1"},
	})
	if err == nil {
		t.Fatal("expected error for host not in allowlist")
	}
	_ = p.Close()
}

func TestProxy_DynamicMode_HostAllowed_CIDR(t *testing.T) {
	p := New(testLogger())
	_ = p.Configure(map[string]any{
		"allowed_hosts": []any{"10.0.0.0/8"},
	}, map[string]string{"username": "u", "password": "p"})

	// This will fail at dial (no real SSH server) but should pass the allowlist check
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "ls", "host": "10.0.1.5"},
	})
	// Error should be about connection, not about allowlist
	if err == nil {
		t.Fatal("expected connection error")
	}
	if err.Error() == "ssh_command: host 10.0.1.5 is not in the allowed hosts list" {
		t.Fatal("host should have been allowed by CIDR")
	}
	_ = p.Close()
}

func TestProxy_DynamicMode_HostAllowed_ExactMatch(t *testing.T) {
	p := New(testLogger())
	_ = p.Configure(map[string]any{
		"allowed_hosts": []any{"myserver.local"},
	}, map[string]string{"username": "u", "password": "p"})

	// Will fail at dial but should pass allowlist
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "ls", "host": "myserver.local"},
	})
	if err == nil {
		t.Fatal("expected connection error")
	}
	if err.Error() == "ssh_command: host myserver.local is not in the allowed hosts list" {
		t.Fatal("host should have been allowed by exact match")
	}
	_ = p.Close()
}

func TestProxy_DynamicMode_NoAllowlist_AllowsAll(t *testing.T) {
	p := New(testLogger())
	_ = p.Configure(map[string]any{}, map[string]string{"username": "u", "password": "p"})

	// Will fail at dial but should pass allowlist (no restrictions)
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "ssh_command",
		Params: map[string]any{"command": "ls", "host": "192.168.99.99"},
	})
	if err == nil {
		t.Fatal("expected connection error")
	}
	if err.Error() == "ssh_command: host 192.168.99.99 is not in the allowed hosts list" {
		t.Fatal("host should be allowed when no allowlist is set")
	}
	_ = p.Close()
}

func TestProxy_HealthCheck_DynamicMode(t *testing.T) {
	p := New(testLogger())
	_ = p.Configure(map[string]any{}, map[string]string{"username": "u", "password": "p"})

	err := p.HealthCheck(context.Background())
	if err != nil {
		t.Fatalf("health check should pass in dynamic mode with valid config: %v", err)
	}
	_ = p.Close()
}

func TestProxy_CollectMetadata_DynamicMode(t *testing.T) {
	p := New(testLogger())
	_ = p.Configure(map[string]any{
		"allowed_hosts": []any{"10.0.0.0/8"},
	}, map[string]string{"username": "u", "password": "p"})

	meta, err := p.CollectMetadata(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta["mode"] != "dynamic" {
		t.Fatalf("expected mode=dynamic, got %v", meta["mode"])
	}
	if meta["active_connections"] != 0 {
		t.Fatalf("expected 0 active connections, got %v", meta["active_connections"])
	}
	_ = p.Close()
}

func TestProxy_CollectMetadata_StaticMode(t *testing.T) {
	p := New(testLogger())
	// Configure will fail at dial but metadata should still reflect static mode
	_ = p.Configure(map[string]any{"host": "192.0.2.1"}, map[string]string{
		"username": "u",
		"password": "p",
	})

	meta, err := p.CollectMetadata(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta["mode"] != "static" {
		t.Fatalf("expected mode=static, got %v", meta["mode"])
	}
	if meta["host"] != "192.0.2.1" {
		t.Fatalf("expected host=192.0.2.1, got %v", meta["host"])
	}
}

func TestIsHostAllowed(t *testing.T) {
	p := New(testLogger())

	_, net1, _ := net.ParseCIDR("10.0.0.0/8")
	_, net2, _ := net.ParseCIDR("172.16.0.0/12")
	p.allowedNets = []*net.IPNet{net1, net2}
	p.allowedHosts = []string{"special-host.local"}

	tests := []struct {
		host    string
		allowed bool
	}{
		{"10.0.1.5", true},
		{"10.255.255.255", true},
		{"172.16.5.10", true},
		{"172.31.255.255", true},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"special-host.local", true},
		{"other-host.local", false},
	}

	for _, tt := range tests {
		got := p.isHostAllowed(tt.host)
		if got != tt.allowed {
			t.Errorf("isHostAllowed(%s) = %v, want %v", tt.host, got, tt.allowed)
		}
	}
}

func TestEvictOldest(t *testing.T) {
	p := New(testLogger())
	p.pool = map[string]*poolEntry{
		"a:22": {lastUsed: mustParseTime("2024-01-01T00:00:00Z")},
		"b:22": {lastUsed: mustParseTime("2024-01-02T00:00:00Z")},
		"c:22": {lastUsed: mustParseTime("2024-01-03T00:00:00Z")},
	}

	p.evictOldestLocked()

	if _, ok := p.pool["a:22"]; ok {
		t.Fatal("expected oldest entry (a:22) to be evicted")
	}
	if len(p.pool) != 2 {
		t.Fatalf("expected 2 entries after eviction, got %d", len(p.pool))
	}
}

func mustParseTime(s string) (t time.Time) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
