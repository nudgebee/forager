package mongodb

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
	if p.Type() != "mongo-proxy" {
		t.Errorf("expected mongo-proxy, got %s", p.Type())
	}
}

func TestProxy_NotConfigured(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: "mongo_query"})
	if err == nil || err.Error() != "mongodb not configured" {
		t.Errorf("expected 'mongodb not configured', got %v", err)
	}
}

func TestProxy_HealthCheck_NotConfigured(t *testing.T) {
	p := New(testLogger())
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Error("expected error for health check on unconfigured proxy")
	}
}

func TestProxy_UnknownAction(t *testing.T) {
	p := New(testLogger())
	p.client = nil // ensure not configured path is different
	// We can't test with a real client, but we can test the action dispatch
	// by temporarily setting client to non-nil... skip since it requires real mongo
}

func TestProxy_Close_NoClient(t *testing.T) {
	p := New(testLogger())
	if err := p.Close(); err != nil {
		t.Errorf("Close on nil client should not error: %v", err)
	}
}

func TestProxy_BuildURI_Basic(t *testing.T) {
	p := New(testLogger())
	p.config = Config{
		Host:       "localhost",
		Port:       27017,
		Database:   "testdb",
		AuthSource: "admin",
	}
	uri := p.buildURI(map[string]string{"username": "user", "password": "pass"})
	expected := "mongodb://user:pass@localhost:27017/testdb?authSource=admin"
	if uri != expected {
		t.Errorf("expected %s, got %s", expected, uri)
	}
}

func TestProxy_BuildURI_WithReplicaSet(t *testing.T) {
	p := New(testLogger())
	p.config = Config{
		Host:       "mongo1",
		Port:       27017,
		Database:   "mydb",
		AuthSource: "admin",
		ReplicaSet: "rs0",
	}
	uri := p.buildURI(map[string]string{"username": "u", "password": "p"})
	if uri != "mongodb://u:p@mongo1:27017/mydb?authSource=admin&replicaSet=rs0" {
		t.Errorf("unexpected URI: %s", uri)
	}
}

func TestProxy_BuildURI_WithTLS(t *testing.T) {
	p := New(testLogger())
	p.config = Config{
		Host:       "mongo1",
		Port:       27017,
		Database:   "mydb",
		AuthSource: "admin",
		TLSEnabled: true,
	}
	uri := p.buildURI(map[string]string{"username": "u", "password": "p"})
	if uri != "mongodb://u:p@mongo1:27017/mydb?authSource=admin&tls=true" {
		t.Errorf("unexpected URI: %s", uri)
	}
}

func TestProxy_BuildURI_NoAuth(t *testing.T) {
	p := New(testLogger())
	p.config = Config{
		Host:       "localhost",
		Port:       27017,
		Database:   "testdb",
		AuthSource: "admin",
	}
	uri := p.buildURI(map[string]string{})
	expected := "mongodb://localhost:27017/testdb?authSource=admin"
	if uri != expected {
		t.Errorf("expected %s, got %s", expected, uri)
	}
}

func TestProxy_GetDatabase(t *testing.T) {
	p := New(testLogger())
	p.config = Config{Database: "default_db"}

	// No override
	req := &proxy.ActionRequest{Params: map[string]any{}}
	if db := p.getDatabase(req); db != "default_db" {
		t.Errorf("expected default_db, got %s", db)
	}

	// With override
	req.Params["database"] = "override_db"
	if db := p.getDatabase(req); db != "override_db" {
		t.Errorf("expected override_db, got %s", db)
	}
}

func TestMapToBsonD(t *testing.T) {
	m := map[string]any{
		"name": "test",
		"nested": map[string]any{
			"key": "value",
		},
	}
	d := mapToBsonD(m)
	if len(d) != 2 {
		t.Errorf("expected 2 elements, got %d", len(d))
	}
}
