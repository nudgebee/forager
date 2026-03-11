package ssh

import (
	"context"
	"log/slog"
	"os"
	"testing"

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

func TestProxy_Configure_MissingHost(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{}, map[string]string{"username": "u", "password": "p"})
	if err == nil {
		t.Fatal("expected error for missing host")
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
