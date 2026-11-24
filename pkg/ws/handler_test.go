package ws

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"nudgebee/forager/pkg/proxy"
	httpproxy "nudgebee/forager/pkg/proxy/http"
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

// syncAck is the per-datasource ack a config sync returns.
type syncAck struct {
	Action      string `json:"action"`
	Status      string `json:"status"`
	Datasources []struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		ErrorCode string `json:"error_code"`
		Error     string `json:"error"`
	} `json:"datasources"`
}

func syncAndParse(t *testing.T, h *Handler, msg string) syncAck {
	t.Helper()
	resp, err := h.HandleMessage(context.Background(), []byte(msg))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	var ack syncAck
	if err := json.Unmarshal(resp, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	return ack
}

func newTestHandlerWithKey(t *testing.T) (*Handler, *secrets.EncKeypair) {
	t.Helper()
	h := newTestHandler(t)
	k, err := secrets.LoadOrCreateEncKeypair(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateEncKeypair: %v", err)
	}
	h.SetEncKeypair(k)
	return h, k
}

// sealedDatasource is an http-proxy datasource whose credentials are sealed for
// id and the host of baseURL — the way api-server seals them at save time.
func sealedDatasource(t *testing.T, pubB64, id, baseURL string, creds map[string]string) string {
	t.Helper()
	return sealedDatasourceAt(t, pubB64, id, baseURL, baseURL, creds)
}

// sealedDatasourceAt seals for the host of sealedFor but pushes base_url
// pushedURL, so a test can present a blob for one host under another.
func sealedDatasourceAt(t *testing.T, pubB64, id, sealedFor, pushedURL string, creds map[string]string) string {
	t.Helper()
	host := datasourceBinding(pushedDatasource{ProxyType: "http-proxy", Config: map[string]any{"base_url": sealedFor}})
	blob, keyID, err := secrets.SealCredentials(pubB64, id, host, creds)
	if err != nil {
		t.Fatalf("SealCredentials: %v", err)
	}
	return `{"id":"` + id + `","type":"grafana_tempo","proxy_type":"http-proxy","name":"t",` +
		`"config":{"base_url":"` + pushedURL + `"},"credential_source":"cloud_push",` +
		`"credentials_enc":"` + blob + `","enc_key_id":"` + keyID + `"}`
}

// A captured blob replayed for another host or under another datasource id
// is refused: the id and host are sealed with the credentials.
func TestHandler_ConfigSync_SealedBlobBoundToDatasourceAndHost(t *testing.T) {
	h, k := newTestHandlerWithKey(t)
	creds := map[string]string{"bearer_token": "tk"}

	otherHost := sealedDatasourceAt(t, k.PublicKey(), "ds-a", "https://good.internal", "https://evil.example", creds)
	ack := syncAndParse(t, h, `{"action":"datasource_config_sync","account_id":"acc","datasources":[`+otherHost+`]}`)
	if ack.Status != "partial" || ack.Datasources[0].ErrorCode != errCodeSealedForOther {
		t.Fatalf("other host: ack %+v", ack)
	}

	// Same blob content, pushed under a different datasource id.
	host := datasourceBinding(pushedDatasource{ProxyType: "http-proxy", Config: map[string]any{"base_url": "https://good.internal"}})
	blob, keyID, _ := secrets.SealCredentials(k.PublicKey(), "ds-a", host, creds)
	otherID := `{"id":"ds-b","type":"grafana_tempo","proxy_type":"http-proxy","config":{"base_url":"https://good.internal"},` +
		`"credential_source":"cloud_push","credentials_enc":"` + blob + `","enc_key_id":"` + keyID + `"}`
	ack = syncAndParse(t, h, `{"action":"datasource_config_sync","account_id":"acc","datasources":[`+otherID+`]}`)
	if ack.Status != "partial" || ack.Datasources[0].ErrorCode != errCodeSealedForOther {
		t.Fatalf("other id: ack %+v", ack)
	}

	for _, id := range []string{"ds-a", "ds-b"} {
		if _, ok := h.credStore.Get(id); ok {
			t.Fatalf("%s: refused blob must store nothing", id)
		}
		if _, ok := h.registry.Get(id); ok {
			t.Fatalf("%s: refused blob must not register", id)
		}
	}
}

// Credentials are persisted only once a proxy accepted them, so a failed
// configure leaves nothing a later stored-credential fallback could use.
func TestHandler_ConfigSync_StoresCredentialsOnlyAfterConfigure(t *testing.T) {
	h := newTestHandler(t)
	ack := syncAndParse(t, h, `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-fail","type":"unknown","proxy_type":"grpc-proxy","config":{"host":"x"},
		 "credentials":{"password":"p"},"credential_source":"cloud_push"}]}`)
	if ack.Status != "partial" {
		t.Fatalf("ack %+v", ack)
	}
	if _, ok := h.credStore.Get("ds-fail"); ok {
		t.Fatal("credentials of a datasource that never configured must not be stored")
	}
}

// An entry written before host binding (no host) is bound to the host of
// its first reuse, after which a move without credentials is refused.
// An entry stored before bindings existed is not bound to whatever the first
// sync names (trust on first use): it is reused only where the datasource is
// registered right now, and bound to that.
func TestHandler_ConfigSync_LegacyUnboundEntryOnlyWhereItRuns(t *testing.T) {
	h := newTestHandler(t)
	if err := h.credStore.Set("ds-old", map[string]string{"bearer_token": "tk"}); err != nil {
		t.Fatal(err)
	}
	reuse := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-old","type":"prometheus","proxy_type":"http-proxy","config":{"base_url":"http://a.internal:9090"},"credential_source":"cloud_push"}]}`
	if ack := syncAndParse(t, h, reuse); ack.Status != "partial" || ack.Datasources[0].ErrorCode != errCodeHostChanged {
		t.Fatalf("an unbound entry must not bind to the first host it is asked for: %+v", ack)
	}

	h.setRegisteredBinding("ds-old", "http://a.internal:9090") // registered there by an earlier push
	if ack := syncAndParse(t, h, reuse); ack.Status != "ok" {
		t.Fatalf("reuse where it runs %+v", ack)
	}
	if got := h.credStore.Host("ds-old"); got != "http://a.internal:9090" {
		t.Fatalf("legacy entry not bound on reuse: %q", got)
	}
	moved := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-old","type":"prometheus","proxy_type":"http-proxy","config":{"base_url":"http://b.internal:9090"},"credential_source":"cloud_push"}]}`
	if ack := syncAndParse(t, h, moved); ack.Status != "partial" || ack.Datasources[0].ErrorCode != errCodeHostChanged {
		t.Fatalf("moved %+v", ack)
	}
}

// The binding is the origin: same host but another scheme or port must carry
// the credentials, so a token never goes out in the clear or to another
// service on the host.
func TestHandler_ConfigSync_SchemeOrPortChangeNeedsCredentials(t *testing.T) {
	h := newTestHandler(t)
	first := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-o","type":"prometheus","proxy_type":"http-proxy","config":{"base_url":"https://prom.internal"},
		 "credentials":{"bearer_token":"tk"},"credential_source":"cloud_push"}]}`
	if ack := syncAndParse(t, h, first); ack.Status != "ok" {
		t.Fatalf("first %+v", ack)
	}
	for _, u := range []string{"http://prom.internal", "https://prom.internal:8443"} {
		moved := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
			{"id":"ds-o","type":"prometheus","proxy_type":"http-proxy","config":{"base_url":"` + u + `"},"credential_source":"cloud_push"}]}`
		if ack := syncAndParse(t, h, moved); ack.Status != "partial" || ack.Datasources[0].ErrorCode != errCodeHostChanged {
			t.Fatalf("%s: %+v", u, ack)
		}
	}
}

// A dynamic ssh scope may narrow without new credentials, never grow.
func TestHandler_ConfigSync_SSHScopeCannotGrowWithStoredCredentials(t *testing.T) {
	h := newTestHandler(t)
	if err := h.credStore.SetBound("ds-ssh", map[string]string{"password": "p"}, "scope:10.0.0.1,10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	ds := pushedDatasource{ID: "ds-ssh", ProxyType: "ssh-proxy", Config: map[string]any{}, CredentialSource: "cloud_push"}

	ds.AllowedHosts = []string{"10.0.0.1"}
	if _, _, code, err := h.resolveCredentials(context.Background(), ds); err != nil {
		t.Fatalf("narrowed scope should reuse: %s %v", code, err)
	}
	ds.AllowedHosts = []string{"10.0.0.1", "10.0.0.2", "10.9.9.9"}
	if _, _, code, err := h.resolveCredentials(context.Background(), ds); err == nil || code != errCodeHostChanged {
		t.Fatalf("grown scope must carry credentials: %s %v", code, err)
	}
}

// Stored credentials of a datasource that never registered are deleted when
// a sync does not list it, like those of a registered one.
func TestHandler_ConfigSync_DeletesOrphanStoredCredentials(t *testing.T) {
	h := newTestHandler(t)
	if err := h.credStore.Set("ds-orphan", map[string]string{"password": "p"}); err != nil {
		t.Fatal(err)
	}
	syncAndParse(t, h, `{"action":"datasource_config_sync","account_id":"acc","datasources":[]}`)
	if _, ok := h.credStore.Get("ds-orphan"); ok {
		t.Fatal("orphan stored credentials must be deleted")
	}
}

func TestHandler_ConfigSync_EncryptedCredentials_StoredAndBound(t *testing.T) {
	h, k := newTestHandlerWithKey(t)
	msg := `{"action":"datasource_config_sync","account_id":"acc","datasources":[` +
		sealedDatasource(t, k.PublicKey(), "ds-enc", "https://tempo.acme.internal", map[string]string{"bearer_token": "tk_123"}) + `]}`

	ack := syncAndParse(t, h, msg)
	if ack.Status != "ok" || len(ack.Datasources) != 1 || ack.Datasources[0].Status != "ok" {
		t.Fatalf("ack %+v", ack)
	}
	if _, ok := h.registry.Get("ds-enc"); !ok {
		t.Fatal("datasource not registered")
	}
	creds, ok := h.credStore.Get("ds-enc")
	if !ok || creds["bearer_token"] != "tk_123" {
		t.Fatalf("stored creds %v %v", creds, ok)
	}
	if got := h.credStore.Host("ds-enc"); got != "https://tempo.acme.internal:443" {
		t.Fatalf("bound host %q", got)
	}
}

func TestHandler_ConfigSync_EncryptedCredentials_Refusals(t *testing.T) {
	h, k := newTestHandlerWithKey(t)
	other, err := secrets.LoadOrCreateEncKeypair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		ds       string
		wantCode string
	}{
		{"sealed to another key", sealedDatasource(t, other.PublicKey(), "ds-x", "http://localhost:1", map[string]string{"a": "b"}), errCodeKeyMismatch},
		{"garbage blob", `{"id":"ds-x","type":"grafana_tempo","proxy_type":"http-proxy","config":{"base_url":"http://localhost:1"},"credential_source":"cloud_push","credentials_enc":"AAAA"}`, errCodeDecryptFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ack := syncAndParse(t, h, `{"action":"datasource_config_sync","account_id":"acc","datasources":[`+tc.ds+`]}`)
			if ack.Status != "partial" || len(ack.Datasources) != 1 || ack.Datasources[0].ErrorCode != tc.wantCode {
				t.Fatalf("ack %+v, want error_code %s", ack, tc.wantCode)
			}
			if _, ok := h.registry.Get("ds-x"); ok {
				t.Fatal("refused datasource must not be registered")
			}
			if _, ok := h.credStore.Get("ds-x"); ok {
				t.Fatal("refused datasource must store nothing")
			}
		})
	}

	t.Run("forager without an encryption key", func(t *testing.T) {
		noKey := newTestHandler(t)
		ack := syncAndParse(t, noKey, `{"action":"datasource_config_sync","account_id":"acc","datasources":[`+
			sealedDatasource(t, k.PublicKey(), "ds-x", "http://localhost:1", map[string]string{"a": "b"})+`]}`)
		if ack.Status != "partial" || ack.Datasources[0].ErrorCode != errCodeNoEncryptionKey {
			t.Fatalf("ack %+v", ack)
		}
	})
}

// A sync that moves a datasource to another host without carrying its
// credentials cannot reuse the stored ones: the datasource stops serving,
// and its stored credentials stay bound to the host they were pushed for.
func TestHandler_ConfigSync_StoredCredentialsBoundToHost(t *testing.T) {
	h := newTestHandler(t)
	first := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-1","type":"prometheus","proxy_type":"http-proxy","name":"a","config":{"base_url":"http://prom.internal:9090"},
		 "credentials":{"bearer_token":"tk"},"credential_source":"cloud_push"}]}`
	if ack := syncAndParse(t, h, first); ack.Status != "ok" {
		t.Fatalf("first sync %+v", ack)
	}

	// Same host, no credentials: reused.
	same := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-1","type":"prometheus","proxy_type":"http-proxy","name":"a","config":{"base_url":"http://PROM.internal:9090/prefix"},
		 "credential_source":"cloud_push"}]}`
	if ack := syncAndParse(t, h, same); ack.Status != "ok" {
		t.Fatalf("same-host sync %+v", ack)
	}

	// Other host, no credentials: refused, stored credentials untouched.
	moved := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-1","type":"prometheus","proxy_type":"http-proxy","name":"a","config":{"base_url":"http://attacker.example:9090"},
		 "credential_source":"cloud_push"}]}`
	ack := syncAndParse(t, h, moved)
	if ack.Status != "partial" || ack.Datasources[0].ErrorCode != errCodeHostChanged {
		t.Fatalf("moved sync %+v", ack)
	}
	if got := h.credStore.Host("ds-1"); got != "http://prom.internal:9090" {
		t.Fatalf("stored host changed to %q", got)
	}
	if _, ok := h.registry.Get("ds-1"); ok {
		t.Fatal("a refused sync must not leave the previous registration serving")
	}

	// Other host WITH credentials: accepted and re-bound.
	movedWithCreds := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-1","type":"prometheus","proxy_type":"http-proxy","name":"a","config":{"base_url":"http://new.internal:9090"},
		 "credentials":{"bearer_token":"tk2"},"credential_source":"cloud_push"}]}`
	if ack := syncAndParse(t, h, movedWithCreds); ack.Status != "ok" {
		t.Fatalf("moved-with-creds sync %+v", ack)
	}
	if got := h.credStore.Host("ds-1"); got != "http://new.internal:9090" {
		t.Fatalf("host not re-bound: %q", got)
	}
}

// A datasource whose reconfigure fails stops serving: the proxy an earlier
// sync registered would otherwise keep answering with the configuration and
// credentials this sync replaced. The ack still reports the failure, and the
// stored credentials stay for the next good sync.
func TestHandler_ConfigSync_FailedReconfigureRemovesOldProxy(t *testing.T) {
	h := newTestHandler(t)
	good := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-a","type":"prometheus","proxy_type":"http-proxy","name":"a","config":{"base_url":"http://localhost:1"},
		 "credentials":{"bearer_token":"tk"},"credential_source":"cloud_push"}]}`
	if ack := syncAndParse(t, h, good); ack.Status != "ok" {
		t.Fatalf("first sync %+v", ack)
	}
	old, ok := h.registry.Get("ds-a")
	if !ok {
		t.Fatal("ds-a should be registered after the first sync")
	}

	// A rotation that carries new credentials but a base_url the http proxy
	// refuses at Configure.
	bad := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-a","type":"prometheus","proxy_type":"http-proxy","name":"a","config":{"base_url":"ftp://localhost:1"},
		 "credentials":{"bearer_token":"rotated"},"credential_source":"cloud_push"}]}`
	ack := syncAndParse(t, h, bad)
	if ack.Status != "partial" || len(ack.Datasources) != 1 ||
		ack.Datasources[0].ID != "ds-a" || ack.Datasources[0].ErrorCode != errCodeConfigureFailed {
		t.Fatalf("failed sync ack %+v", ack)
	}
	if _, ok := h.registry.Get("ds-a"); ok {
		t.Fatal("a failed reconfigure must remove the previously registered proxy")
	}
	if _, err := old.HandleRequest(context.Background(), &proxy.ActionRequest{Method: "GET", URL: "/"}); err == nil {
		t.Fatal("the removed proxy must be closed")
	}
	if _, ok := h.credStore.Get("ds-a"); ok {
		t.Fatal("a failed push that carried credentials must drop the old ones, or the next sync serves the rotated-out token")
	}
}

func TestHandler_ConfigSync_RemovalDeletesStoredCredentials(t *testing.T) {
	h := newTestHandler(t)
	with := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-gone","type":"prometheus","proxy_type":"http-proxy","name":"a","config":{"base_url":"http://localhost:1"},
		 "credentials":{"password":"p"},"credential_source":"cloud_push"}]}`
	syncAndParse(t, h, with)
	if _, ok := h.credStore.Get("ds-gone"); !ok {
		t.Fatal("credentials should be stored after the first sync")
	}

	syncAndParse(t, h, `{"action":"datasource_config_sync","account_id":"acc","datasources":[]}`)
	if _, ok := h.registry.Get("ds-gone"); ok {
		t.Fatal("datasource should be removed")
	}
	if _, ok := h.credStore.Get("ds-gone"); ok {
		t.Fatal("stored credentials must be deleted with the datasource")
	}
}

func TestHandler_ConfigSync_AckListsEveryDatasource(t *testing.T) {
	h := newTestHandler(t)
	ack := syncAndParse(t, h, `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-ok","type":"prometheus","proxy_type":"http-proxy","name":"a","config":{"base_url":"http://localhost:1"},"credential_source":"cloud_push"},
		{"id":"ds-bad","type":"unknown","proxy_type":"grpc-proxy","name":"b","config":{},"credential_source":"cloud_push"}]}`)
	if ack.Status != "partial" {
		t.Fatalf("status %q", ack.Status)
	}
	if len(ack.Datasources) != 2 {
		t.Fatalf("want 2 results, got %d", len(ack.Datasources))
	}
	byID := map[string]string{}
	for _, d := range ack.Datasources {
		byID[d.ID] = d.Status + "/" + d.ErrorCode
	}
	if byID["ds-ok"] != "ok/" || byID["ds-bad"] != "error/"+errCodeUnknownProxy {
		t.Fatalf("results %v", byID)
	}
}

func TestHandler_TestDatasourceConfig_EncryptedCredentials_NotStored(t *testing.T) {
	h, k := newTestHandlerWithKey(t)
	resp, err := h.HandleMessage(context.Background(), []byte(`{"action":"test_datasource_config","request_id":"r","datasource":`+
		sealedDatasource(t, k.PublicKey(), "ds-test", "http://localhost:1", map[string]string{"bearer_token": "tk"})+`}`))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	var r struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(resp, &r)
	if !r.Success {
		t.Fatalf("test should pass for an http-proxy that does not dial: %s", r.Error)
	}
	if _, ok := h.credStore.Get("ds-test"); ok {
		t.Fatal("a test must not store credentials")
	}
	if _, ok := h.registry.Get("ds-test"); ok {
		t.Fatal("a test must not register the datasource")
	}

	other, _ := secrets.LoadOrCreateEncKeypair(t.TempDir())
	resp, _ = h.HandleMessage(context.Background(), []byte(`{"action":"test_datasource_config","request_id":"r","datasource":`+
		sealedDatasource(t, other.PublicKey(), "ds-test", "http://localhost:1", map[string]string{"bearer_token": "tk"})+`}`))
	var bad struct {
		Success   bool   `json:"success"`
		ErrorCode string `json:"error_code"`
	}
	_ = json.Unmarshal(resp, &bad)
	if bad.Success || bad.ErrorCode != errCodeKeyMismatch {
		t.Fatalf("want key_mismatch failure, got %+v", bad)
	}
}

// The binding vectors are shared with api-server, which seals credentials
// for the same value the forager checks.
func TestDatasourceBinding_SharedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "datasource_binding_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			ProxyType    string         `json:"proxy_type"`
			Config       map[string]any `json:"config"`
			AllowedHosts []string       `json:"allowed_hosts"`
			Want         string         `json:"want"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, v := range file.Vectors {
		got := datasourceBinding(pushedDatasource{ProxyType: v.ProxyType, Config: v.Config, AllowedHosts: v.AllowedHosts})
		if got != v.Want {
			t.Errorf("%s %v %v: got %q want %q", v.ProxyType, v.Config, v.AllowedHosts, got, v.Want)
		}
	}
}

func TestBindingAllows(t *testing.T) {
	cases := []struct {
		bound, current string
		want           bool
	}{
		{"https://es:443", "https://es:443", true},
		{"https://es:443", "http://es:80", false},
		{"https://es:443", "https://es:9200", false},
		{"scope:a,b,c", "scope:a,b", true},
		{"scope:a,b", "scope:a,b,c", false},
		{"scope:a", "a", false},
	}
	for _, c := range cases {
		if got := bindingAllows(c.bound, c.current); got != c.want {
			t.Errorf("bindingAllows(%q, %q) = %v, want %v", c.bound, c.current, got, c.want)
		}
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
	credStore, err := secrets.NewCloudPushStore(dir, "test-secret")
	if err != nil {
		t.Fatalf("NewCloudPushStore: %v", err)
	}
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
		if err := json.Unmarshal(respBytes, &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if resp.StatusCode != 403 {
			t.Errorf("expected 403 Forbidden for unsigned unknown action, got %d", resp.StatusCode)
		}
	})

	t.Run("NilVerifier_DoesNotPanic", func(t *testing.T) {
		nilVerifierHandler := NewHandler(registry, credStore, secretsMgr, nil, testLogger())
		msg := map[string]any{
			"request_id":    "req-nil-verifier",
			"datasource_id": "ds-redis",
			"action":        "redis_info",
			"params":        map[string]any{},
		}
		msgBytes, _ := json.Marshal(msg)
		respBytes, err := nilVerifierHandler.HandleMessage(context.Background(), msgBytes)
		if err != nil {
			t.Fatalf("HandleMessage failed: %v", err)
		}

		var resp proxy.ActionResponse
		if err := json.Unmarshal(respBytes, &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Errorf("expected 200 OK for nil verifier handler, got %d", resp.StatusCode)
		}
	})
}

func TestHandler_DatasourceNotFound_ErrorCode(t *testing.T) {
	h := newTestHandler(t)
	resp, err := h.HandleMessage(context.Background(), []byte(`{"request_id":"r","datasource_id":"nope","action":"http_request"}`))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	var r proxy.ActionResponse
	_ = json.Unmarshal(resp, &r)
	if r.StatusCode != 404 || r.ErrorCode != proxy.ErrCodeDatasourceNotFound {
		t.Fatalf("got status=%d code=%q", r.StatusCode, r.ErrorCode)
	}
}

func TestHandler_LegacyHTTP_AmbiguousDatasource(t *testing.T) {
	h := newTestHandler(t)
	h.registry.Register("a", proxy.DatasourceEntry{ID: "a", ProxyType: "http-proxy"}, &fakeProxy{proxyType: "http-proxy"})
	h.registry.Register("b", proxy.DatasourceEntry{ID: "b", ProxyType: "http-proxy"}, &fakeProxy{proxyType: "http-proxy"})

	resp, err := h.HandleMessage(context.Background(), []byte(`{"method":"GET","url":"/api/v1/query","request_id":"r"}`))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	var r proxy.ActionResponse
	_ = json.Unmarshal(resp, &r)
	if r.StatusCode != 400 || r.ErrorCode != proxy.ErrCodeAmbiguousDatasource {
		t.Fatalf("got status=%d code=%q", r.StatusCode, r.ErrorCode)
	}
}

func TestHandler_LegacyHTTP_SingleProxyStillRoutes(t *testing.T) {
	h := newTestHandler(t)
	h.registry.Register("a", proxy.DatasourceEntry{ID: "a", ProxyType: "http-proxy"}, &fakeProxy{proxyType: "http-proxy"})

	resp, err := h.HandleMessage(context.Background(), []byte(`{"method":"GET","url":"/api/v1/query","request_id":"r"}`))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	var r proxy.ActionResponse
	_ = json.Unmarshal(resp, &r)
	if r.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", r.StatusCode)
	}
}

func TestHandler_ConfigSync_TriggersCallback(t *testing.T) {
	h := newTestHandler(t)
	called := 0
	h.SetOnConfigSynced(func() { called++ })
	if _, err := h.HandleMessage(context.Background(), []byte(`{"action":"datasource_config_sync","account_id":"a","datasources":[]}`)); err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if called != 1 {
		t.Fatalf("expected callback once, got %d", called)
	}
}

// The relay forwards an execute request to a proxy agent as the legacy envelope, with the
// HTTP request inside action_params. It must reach the datasource with its path intact.
func TestHandler_LegacyHTTPRequest_KeepsPathAndQuery(t *testing.T) {
	var gotURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.URL.RequestURI()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	h := newTestHandler(t)
	p := httpproxy.New(testLogger())
	if err := p.Configure(map[string]any{"base_url": srv.URL, "datasource_type": "prometheus"}, nil); err != nil {
		t.Fatal(err)
	}
	h.registry.Register("ds-1", proxy.DatasourceEntry{ID: "ds-1", Type: "prometheus", ProxyType: "http-proxy"}, p)

	msg := `{"request_id":"r1","body":{"account_id":"acc","action_name":"http_request","action_params":{
		"datasource_id":"ds-1","method":"GET","url":"/api/v1/query?query=up"}}}`
	resp, err := h.HandleMessage(context.Background(), []byte(msg))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	var r proxy.ActionResponse
	_ = json.Unmarshal(resp, &r)
	if r.StatusCode != 200 {
		t.Fatalf("status %d: %s", r.StatusCode, resp)
	}
	if gotURI != "/api/v1/query?query=up" {
		t.Fatalf("datasource received %q, want the path and query from action_params", gotURI)
	}
}

// The rest of the HTTP request (method, header, body) rides in action_params too.
func TestHandler_LegacyHTTPRequest_KeepsMethodHeaderAndBody(t *testing.T) {
	var gotMethod, gotHeader, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotMethod, gotHeader, gotBody = r.Method, r.Header.Get("X-Scope-OrgID"), string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	h := newTestHandler(t)
	p := httpproxy.New(testLogger())
	if err := p.Configure(map[string]any{"base_url": srv.URL, "datasource_type": "prometheus"}, nil); err != nil {
		t.Fatal(err)
	}
	h.registry.Register("ds-1", proxy.DatasourceEntry{ID: "ds-1", Type: "prometheus", ProxyType: "http-proxy"}, p)

	msg := `{"request_id":"r1","body":{"action_name":"http_request","action_params":{
		"datasource_id":"ds-1","method":"POST","url":"/api/v1/query",
		"header":{"X-Scope-OrgID":["tenant-1"]},"body":"` + base64.StdEncoding.EncodeToString([]byte("query=up")) + `"}}}`
	resp, err := h.HandleMessage(context.Background(), []byte(msg))
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	var r proxy.ActionResponse
	_ = json.Unmarshal(resp, &r)
	if r.StatusCode != 200 {
		t.Fatalf("status %d: %s", r.StatusCode, resp)
	}
	if gotMethod != "POST" || gotHeader != "tenant-1" || gotBody != "query=up" {
		t.Fatalf("got %s hdr=%q body=%q", gotMethod, gotHeader, gotBody)
	}
}

func TestHandler_LegacyHTTP_NoProxyIsCodedNotFound(t *testing.T) {
	h := newTestHandler(t)
	resp, err := h.HandleMessage(context.Background(), []byte(`{"request_id":"r1","method":"GET","url":"/x"}`))
	if err != nil {
		t.Fatal(err)
	}
	var r proxy.ActionResponse
	_ = json.Unmarshal(resp, &r)
	if r.StatusCode != 404 || r.ErrorCode != proxy.ErrCodeDatasourceNotFound {
		t.Fatalf("got %d %q", r.StatusCode, r.ErrorCode)
	}
}

// A test whose proxy type is unknown reports an error code like every other
// failure path.
func TestHandler_TestDatasourceConfig_UnknownProxyTypeHasCode(t *testing.T) {
	h := newTestHandler(t)
	resp, err := h.HandleMessage(context.Background(), []byte(`{"action":"test_datasource_config","request_id":"r","datasource":{"type":"x","proxy_type":"nope-proxy","config":{},"credential_source":"local"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Success   bool   `json:"success"`
		ErrorCode string `json:"error_code"`
	}
	_ = json.Unmarshal(resp, &r)
	if r.Success || r.ErrorCode != errCodeUnknownProxy {
		t.Fatalf("got %+v", r)
	}
}

// The pre-save test runs an http-proxy datasource's probe, so a wrong key is
// refused (bad_credentials) before Nudgebee stores it; a datasource without a
// probe keeps today's configure-only test.
func TestHandler_TestDatasourceConfig_RunsProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := newTestHandler(t)
	run := func(token string, withProbe bool) (bool, string) {
		cfg := `{"base_url":"` + srv.URL + `","auth_type":"bearer"`
		if withProbe {
			cfg += `,"probe":{"path":"/api/v2/search/tags"}`
		}
		cfg += `}`
		resp, err := h.HandleMessage(context.Background(), []byte(`{"action":"test_datasource_config","request_id":"r","datasource":{"type":"grafana_tempo","proxy_type":"http-proxy","config":`+cfg+`,"credentials":{"bearer_token":"`+token+`"},"credential_source":"cloud_push"}}`))
		if err != nil {
			t.Fatalf("HandleMessage: %v", err)
		}
		var r struct {
			Success   bool   `json:"success"`
			ErrorCode string `json:"error_code"`
		}
		_ = json.Unmarshal(resp, &r)
		return r.Success, r.ErrorCode
	}

	if ok, code := run("good", true); !ok {
		t.Fatalf("right key should pass, got %s", code)
	}
	if ok, code := run("wrong", true); ok || code != errCodeBadCredentials {
		t.Fatalf("wrong key: success=%v code=%q", ok, code)
	}
	if ok, _ := run("wrong", false); !ok {
		t.Fatal("without a probe the test stays configure-only")
	}
	// "probe": null is no probe, not a fall-through to the generic health check.
	resp, err := h.HandleMessage(context.Background(), []byte(`{"action":"test_datasource_config","request_id":"r","datasource":{"type":"grafana_tempo","proxy_type":"http-proxy","config":{"base_url":"`+srv.URL+`","auth_type":"bearer","probe":null},"credentials":{"bearer_token":"wrong"},"credential_source":"cloud_push"}}`))
	if err != nil || !strings.Contains(string(resp), `"success":true`) {
		t.Fatalf("probe:null should stay configure-only: %s %v", resp, err)
	}
}

// http-proxy datasources may only resolve allow-listed secret refs; other
// proxy types are not restricted.
func TestHandler_SecretRefAllowlist(t *testing.T) {
	h := newTestHandler(t)
	sync := func(proxyType, dsType, ref string) syncAck {
		return syncAndParse(t, h, `{"action":"datasource_config_sync","account_id":"acc","datasources":[`+
			`{"id":"ds","type":"`+dsType+`","proxy_type":"`+proxyType+`","config":{"base_url":"http://localhost:1","host":"db"},`+
			`"credential_source":"aws_sm","credential_ref":"`+ref+`"}]}`)
	}
	const outside = "arn:aws:secretsmanager:eu:1:secret:prod-db"

	// No list: types that read secret managers before the list keep working,
	// so an upgrade breaks nothing; any other http-proxy type is denied.
	for _, legacy := range []string{"http_proxy", "prometheus", "loki", "signoz"} {
		if ack := sync("http-proxy", legacy, outside); ack.Datasources[0].ErrorCode == errCodeSecretRefDenied {
			t.Fatalf("%s with no allow-list must not be denied: %+v", legacy, ack)
		}
	}
	if ack := sync("http-proxy", "grafana_tempo", outside); ack.Datasources[0].ErrorCode != errCodeSecretRefDenied {
		t.Fatalf("a new http-proxy type with no allow-list must be denied: %+v", ack)
	}

	h.SetSecretRefAllowlist([]string{"arn:aws:secretsmanager:eu:1:secret:nudgebee/"})
	if ack := sync("http-proxy", "prometheus", outside); ack.Datasources[0].ErrorCode != errCodeSecretRefDenied {
		t.Fatalf("outside the prefix: %+v", ack)
	}
	if ack := sync("http-proxy", "grafana_tempo", "arn:aws:secretsmanager:eu:1:secret:nudgebee/tempo"); ack.Datasources[0].ErrorCode == errCodeSecretRefDenied {
		t.Fatalf("inside the prefix must reach the secret manager: %+v", ack)
	}
	if ack := sync("db-proxy", "postgresql", outside); ack.Datasources[0].ErrorCode == errCodeSecretRefDenied {
		t.Fatalf("db-proxy is not restricted: %+v", ack)
	}
}

// The greeting and health reports tell Nudgebee whether secret refs are
// restricted, so it can refuse a new secret_ref on an unrestricted forager.
func TestAgentFacts_ReportsSecretRefAllowlist(t *testing.T) {
	if got := (AgentFacts{}).fields()["secret_ref_allowlist_set"]; got != false {
		t.Fatalf("unset: %v", got)
	}
	if got := (AgentFacts{SecretRefAllowlistSet: true}).fields()["secret_ref_allowlist_set"]; got != true {
		t.Fatalf("set: %v", got)
	}
}

// With no list, the refusal says there is no list rather than that the
// secret is missing from one.
func TestHandler_SecretRefRefusalWithoutList(t *testing.T) {
	h := newTestHandler(t)
	ack := syncAndParse(t, h, `{"action":"datasource_config_sync","account_id":"acc","datasources":[`+
		`{"id":"ds","type":"grafana_tempo","proxy_type":"http-proxy","config":{"base_url":"http://localhost:1"},`+
		`"credential_source":"aws_sm","credential_ref":"arn:aws:secretsmanager:eu:1:secret:x"}]}`)
	if ack.Datasources[0].ErrorCode != errCodeSecretRefDenied || !strings.Contains(ack.Datasources[0].Error, "no secret_ref_allowlist is set") {
		t.Fatalf("got %+v", ack)
	}
}

// A server push cannot turn on accept-new: that policy writes to
// known_hosts_file, whose path the push would otherwise choose.
func TestStripLocalOnlyConfigDropsHostKeyPolicy(t *testing.T) {
	cfg := map[string]any{"host_key_policy": "accept-new", "known_hosts_file": "/tmp/kh", "port": 22}
	stripLocalOnlyConfig(cfg)
	if _, ok := cfg["host_key_policy"]; ok {
		t.Fatalf("host_key_policy survived a push: %v", cfg)
	}
	if cfg["known_hosts_file"] != "/tmp/kh" || cfg["port"] != 22 {
		t.Fatalf("other keys must be kept: %v", cfg)
	}
}
