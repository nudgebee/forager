package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"nudgebee/forager/pkg/proxy"
	"nudgebee/forager/pkg/secrets"
	"nudgebee/forager/pkg/signing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	dir := t.TempDir()
	credStore, err := secrets.NewCloudPushStore(dir, "test-secret")
	if err != nil {
		t.Fatalf("NewCloudPushStore: %v", err)
	}
	secretsMgr := secrets.NewManager(testLogger())
	registry := proxy.NewRegistry()
	verifier, err := signing.NewVerifier("", testLogger()) // disabled for tests
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	return NewHandler(registry, credStore, secretsMgr, verifier, testLogger())
}

func TestHandler_HandleMessage_InvalidJSON(t *testing.T) {
	h := newTestHandler(t)
	_, err := h.HandleMessage(context.Background(), []byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestHandler_HandleMessage_UnrecognizedFormat(t *testing.T) {
	h := newTestHandler(t)
	msg := `{"action": "something_else", "request_id": "req-1"}`
	resp, err := h.HandleMessage(context.Background(), []byte(msg))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}

	var r proxy.ActionResponse
	if err := json.Unmarshal(resp, &r); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if r.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", r.StatusCode)
	}
}

func TestHandler_HandleMessage_ActionRequest_MissingDatasource(t *testing.T) {
	h := newTestHandler(t)
	msg := `{
		"request_id": "req-1",
		"body": {
			"action_name": "db_query",
			"action_params": {}
		}
	}`
	resp, err := h.HandleMessage(context.Background(), []byte(msg))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}

	var r proxy.ActionResponse
	_ = json.Unmarshal(resp, &r)
	if r.StatusCode != 400 {
		t.Fatalf("expected 400 for missing datasource_id, got %d", r.StatusCode)
	}
}

func TestHandler_HandleMessage_ActionRequest_DatasourceNotFound(t *testing.T) {
	h := newTestHandler(t)
	msg := `{
		"request_id": "req-2",
		"body": {
			"action_name": "db_query",
			"action_params": {"datasource_id": "nonexistent"}
		}
	}`
	resp, err := h.HandleMessage(context.Background(), []byte(msg))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}

	var r proxy.ActionResponse
	_ = json.Unmarshal(resp, &r)
	if r.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", r.StatusCode)
	}
}

func TestHandler_HandleMessage_HTTPRequest_NoProxy(t *testing.T) {
	h := newTestHandler(t)
	msg := `{"method": "GET", "url": "/api/v1/query", "request_id": "req-3"}`
	resp, err := h.HandleMessage(context.Background(), []byte(msg))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}

	var r proxy.ActionResponse
	_ = json.Unmarshal(resp, &r)
	if r.StatusCode != 404 {
		t.Fatalf("expected 404 for no http-proxy, got %d", r.StatusCode)
	}
}

func TestHandler_ConfigSync_HTTPProxy(t *testing.T) {
	h := newTestHandler(t)

	// This will fail at Configure (no real server) but we can test the parsing
	// Use a config sync with an http-proxy that has a valid base_url
	msg := `{
		"action": "datasource_config_sync",
		"account_id": "acc-123",
		"datasources": [
			{
				"id": "ds-http-1",
				"type": "prometheus",
				"proxy_type": "http-proxy",
				"name": "test-prom",
				"config": {"base_url": "http://localhost:9999"},
				"credentials": {},
				"credential_source": "cloud_push"
			}
		]
	}`

	resp, err := h.HandleMessage(context.Background(), []byte(msg))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}

	var ack struct {
		Action string `json:"action"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(resp, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Action != "datasource_config_sync_ack" {
		t.Fatalf("expected ack action, got %s", ack.Action)
	}
	if ack.Status != "ok" {
		t.Fatalf("expected ok status, got %s", ack.Status)
	}

	// Verify proxy was registered
	_, ok := h.registry.Get("ds-http-1")
	if !ok {
		t.Fatal("expected ds-http-1 to be registered")
	}
}

func TestHandler_ConfigSync_RemovesStale(t *testing.T) {
	h := newTestHandler(t)

	// First sync with 2 datasources
	msg1 := `{
		"action": "datasource_config_sync",
		"account_id": "acc-1",
		"datasources": [
			{"id": "ds-1", "type": "prometheus", "proxy_type": "http-proxy", "name": "a", "config": {"base_url": "http://localhost:1"}, "credential_source": "cloud_push"},
			{"id": "ds-2", "type": "prometheus", "proxy_type": "http-proxy", "name": "b", "config": {"base_url": "http://localhost:2"}, "credential_source": "cloud_push"}
		]
	}`
	_, _ = h.HandleMessage(context.Background(), []byte(msg1))

	if len(h.registry.All()) != 2 {
		t.Fatalf("expected 2 datasources, got %d", len(h.registry.All()))
	}

	// Second sync with only ds-1 — ds-2 should be removed
	msg2 := `{
		"action": "datasource_config_sync",
		"account_id": "acc-1",
		"datasources": [
			{"id": "ds-1", "type": "prometheus", "proxy_type": "http-proxy", "name": "a", "config": {"base_url": "http://localhost:1"}, "credential_source": "cloud_push"}
		]
	}`
	_, _ = h.HandleMessage(context.Background(), []byte(msg2))

	if _, ok := h.registry.Get("ds-1"); !ok {
		t.Fatal("ds-1 should still exist")
	}
	if _, ok := h.registry.Get("ds-2"); ok {
		t.Fatal("ds-2 should have been removed")
	}
}

func TestHandler_ConfigSync_UnknownProxyType(t *testing.T) {
	h := newTestHandler(t)
	msg := `{
		"action": "datasource_config_sync",
		"account_id": "acc-1",
		"datasources": [
			{"id": "ds-bad", "type": "unknown", "proxy_type": "grpc-proxy", "name": "bad", "config": {}, "credential_source": "cloud_push"}
		]
	}`
	_, _ = h.HandleMessage(context.Background(), []byte(msg))

	// Unknown proxy type should be skipped, not registered
	if _, ok := h.registry.Get("ds-bad"); ok {
		t.Fatal("unknown proxy type should not be registered")
	}
}

func TestHandler_ConfigSync_CloudPushCredentials(t *testing.T) {
	h := newTestHandler(t)

	msg := `{
		"action": "datasource_config_sync",
		"account_id": "acc-1",
		"datasources": [
			{
				"id": "ds-cred",
				"type": "prometheus",
				"proxy_type": "http-proxy",
				"name": "with-creds",
				"config": {"base_url": "http://localhost:9090"},
				"credentials": {"username": "admin", "password": "secret"},
				"credential_source": "cloud_push"
			}
		]
	}`
	_, _ = h.HandleMessage(context.Background(), []byte(msg))

	// Verify credentials were stored
	creds, ok := h.credStore.Get("ds-cred")
	if !ok {
		t.Fatal("expected credentials to be stored")
	}
	if creds["username"] != "admin" || creds["password"] != "secret" {
		t.Fatalf("unexpected stored creds: %v", creds)
	}
}

func TestHandler_BuildErrorResponse(t *testing.T) {
	h := newTestHandler(t)
	resp := h.buildErrorResponse("req-123", 500, "something broke")

	var r proxy.ActionResponse
	if err := json.Unmarshal(resp, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.StatusCode != 500 {
		t.Fatalf("expected 500, got %d", r.StatusCode)
	}
	if r.RequestID != "req-123" {
		t.Fatalf("expected req-123, got %s", r.RequestID)
	}
}
