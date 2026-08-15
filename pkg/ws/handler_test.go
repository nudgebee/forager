package ws

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"nudgebee/forager/pkg/proxy"
	"nudgebee/forager/pkg/secrets"
	"nudgebee/forager/pkg/signing"
)

// fakeProxy is a minimal Proxy implementation for tests.
type fakeProxy struct {
	proxyType string
}

func (f *fakeProxy) Type() string                                      { return f.proxyType }
func (f *fakeProxy) Configure(map[string]any, map[string]string) error { return nil }
func (f *fakeProxy) HandleRequest(context.Context, *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	return &proxy.ActionResponse{StatusCode: 200}, nil
}
func (f *fakeProxy) HealthCheck(context.Context) error { return nil }
func (f *fakeProxy) Close() error                      { return nil }

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

func TestHandler_ConfigSync_PreservesLocalDatasources(t *testing.T) {
	h := newTestHandler(t)

	// Pre-register a local datasource (simulates cmd/app.go local config)
	localEntry := proxy.DatasourceEntry{
		ID:        "local:prod-pg",
		Type:      "postgresql",
		ProxyType: "db-proxy",
		Name:      "prod-pg",
	}
	h.registry.Register(localEntry.ID, localEntry, &fakeProxy{proxyType: "db-proxy"})

	// Cloud config sync with a different datasource — should NOT remove local:prod-pg
	msg := `{
		"action": "datasource_config_sync",
		"account_id": "acc-1",
		"datasources": [
			{"id": "ds-cloud-1", "type": "prometheus", "proxy_type": "http-proxy", "name": "cloud-prom", "config": {"base_url": "http://localhost:9090"}, "credential_source": "cloud_push"}
		]
	}`
	_, _ = h.HandleMessage(context.Background(), []byte(msg))

	if _, ok := h.registry.Get("local:prod-pg"); !ok {
		t.Fatal("local:prod-pg should NOT be removed by cloud config sync")
	}
	if _, ok := h.registry.Get("ds-cloud-1"); !ok {
		t.Fatal("ds-cloud-1 should be registered")
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

func TestHandler_SignatureEnforcement(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	verifier, err := signing.NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if !verifier.Enabled() {
		t.Fatal("verifier should be enabled")
	}

	registry := proxy.NewRegistry()
	registry.Register("ds-kafka", proxy.DatasourceEntry{ID: "ds-kafka", ProxyType: "kafka-proxy"}, &fakeProxy{proxyType: "kafka-proxy"})
	registry.Register("ds-mongo", proxy.DatasourceEntry{ID: "ds-mongo", ProxyType: "mongo-proxy"}, &fakeProxy{proxyType: "mongo-proxy"})
	registry.Register("ds-redis", proxy.DatasourceEntry{ID: "ds-redis", ProxyType: "redis-proxy"}, &fakeProxy{proxyType: "redis-proxy"})

	dir := t.TempDir()
	credStore, _ := secrets.NewCloudPushStore(dir, "test-secret")
	secretsMgr := secrets.NewManager(testLogger())
	h := NewHandler(registry, credStore, secretsMgr, verifier, testLogger())

	actionsToTest := []struct {
		datasourceID string
		action       string
	}{
		{"ds-kafka", "kafka_consumer_lag"},
		{"ds-kafka", "kafka_topics"},
		{"ds-kafka", "kafka_brokers"},
		{"ds-mongo", "mongo_list_databases"},
		{"ds-mongo", "mongo_current_ops"},
		{"ds-mongo", "mongo_server_status"},
		{"ds-redis", "redis_slowlog"},
		{"ds-redis", "redis_client_list"},
		{"ds-redis", "redis_info"},
	}

	for _, tc := range actionsToTest {
		t.Run("Unsigned_"+tc.action, func(t *testing.T) {
			unsignedMsg := map[string]any{
				"request_id":    "req-" + tc.action,
				"datasource_id": tc.datasourceID,
				"action":        tc.action,
				"params":        map[string]any{},
			}
			msgBytes, _ := json.Marshal(unsignedMsg)
			respBytes, err := h.HandleMessage(context.Background(), msgBytes)
			if err != nil {
				t.Fatalf("HandleMessage failed: %v", err)
			}

			var resp proxy.ActionResponse
			if err := json.Unmarshal(respBytes, &resp); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if resp.StatusCode != 403 {
				t.Errorf("action %s: expected 403 Forbidden for unsigned message, got %d", tc.action, resp.StatusCode)
			}
		})

		t.Run("Signed_"+tc.action, func(t *testing.T) {
			msgMap := map[string]any{
				"request_id":    "req-signed-" + tc.action,
				"datasource_id": tc.datasourceID,
				"action":        tc.action,
				"params":        map[string]any{},
			}

			signedPayloadMap := map[string]any{
				"action":        tc.action,
				"datasource_id": tc.datasourceID,
				"params":        map[string]any{},
			}
			payloadBytes, _ := json.Marshal(signedPayloadMap)
			msgMap["signed_payload"] = string(payloadBytes)
			msgMap["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payloadBytes))
			msgMap["signed_at"] = time.Now().UTC().Format(time.RFC3339)
			msgMap["nonce"] = uuid.NewString()

			msgBytes, _ := json.Marshal(msgMap)
			respBytes, err := h.HandleMessage(context.Background(), msgBytes)
			if err != nil {
				t.Fatalf("HandleMessage failed: %v", err)
			}

			var resp proxy.ActionResponse
			if err := json.Unmarshal(respBytes, &resp); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if resp.StatusCode != 200 {
				t.Errorf("action %s: expected 200 OK for signed message, got %d (%s)", tc.action, resp.StatusCode, resp.Data)
			}
		})
	}

	t.Run("Unsigned_UnknownAction_BlockedWhenVerifierEnabled", func(t *testing.T) {
		unsignedMsg := map[string]any{
			"request_id":    "req-unknown",
			"datasource_id": "ds-redis",
			"action":        "unregistered_custom_action",
			"params":        map[string]any{},
		}
		msgBytes, _ := json.Marshal(unsignedMsg)
		respBytes, err := h.HandleMessage(context.Background(), msgBytes)
		if err != nil {
			t.Fatalf("HandleMessage failed: %v", err)
		}

		var resp proxy.ActionResponse
		_ = json.Unmarshal(respBytes, &resp)
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 Forbidden for unsigned unknown action, got %d", resp.StatusCode)
		}
	})
}

