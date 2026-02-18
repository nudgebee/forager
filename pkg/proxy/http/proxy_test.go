package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"nudgebee/forager/pkg/proxy"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestProxy_Type(t *testing.T) {
	p := New(testLogger())
	if p.Type() != "http-proxy" {
		t.Fatalf("expected http-proxy, got %s", p.Type())
	}
}

func TestProxy_ConfigureRequiresBaseURL(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{}, nil)
	if err == nil {
		t.Fatal("expected error when base_url is missing")
	}
}

func TestProxy_ConfigureBasic(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{
		"base_url":  "http://localhost:9090",
		"auth_type": "basic",
	}, map[string]string{"username": "admin", "password": "pass"})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if p.baseURL != "http://localhost:9090" {
		t.Fatalf("unexpected baseURL: %s", p.baseURL)
	}
	if p.authType != "basic" {
		t.Fatalf("unexpected authType: %s", p.authType)
	}
}

func TestProxy_InjectAuth_Basic(t *testing.T) {
	p := New(testLogger())
	p.authType = "basic"
	p.creds = map[string]string{"username": "user", "password": "pass"}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	p.injectAuth(req)

	user, pass, ok := req.BasicAuth()
	if !ok || user != "user" || pass != "pass" {
		t.Fatalf("expected basic auth user/pass, got %s/%s (ok=%v)", user, pass, ok)
	}
}

func TestProxy_InjectAuth_Bearer(t *testing.T) {
	p := New(testLogger())
	p.authType = "bearer"
	p.creds = map[string]string{"bearer_token": "my-token-123"}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	p.injectAuth(req)

	if got := req.Header.Get("Authorization"); got != "Bearer my-token-123" {
		t.Fatalf("expected Bearer token, got %q", got)
	}
}

func TestProxy_InjectAuth_CustomHeader(t *testing.T) {
	p := New(testLogger())
	p.authType = "custom_header"
	p.creds = map[string]string{
		"custom_header_name":  "X-Api-Key",
		"custom_header_value": "secret-key",
	}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	p.injectAuth(req)

	if got := req.Header.Get("X-Api-Key"); got != "secret-key" {
		t.Fatalf("expected X-Api-Key=secret-key, got %q", got)
	}
}

func TestProxy_InjectAuth_None(t *testing.T) {
	p := New(testLogger())
	p.authType = "none"

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	p.injectAuth(req)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected no auth header, got %q", got)
	}
}

func TestProxy_HandleRequest(t *testing.T) {
	// Start a test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer ts.Close()

	p := New(testLogger())
	err := p.Configure(map[string]any{"base_url": ts.URL}, nil)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Method: "GET",
		URL:    "/api/v1/query",
	})
	if err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Parse the response data
	var httpResp struct {
		StatusCode int                 `json:"status_code"`
		Header     map[string][]string `json:"header"`
		Body       string              `json:"body"`
	}
	if err := json.Unmarshal([]byte(resp.Data), &httpResp); err != nil {
		t.Fatalf("unmarshal response data: %v", err)
	}
	if httpResp.StatusCode != 200 {
		t.Fatalf("expected inner status 200, got %d", httpResp.StatusCode)
	}

	// Decode body
	bodyBytes, err := base64.StdEncoding.DecodeString(httpResp.Body)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if string(bodyBytes) != `{"status":"success"}` {
		t.Fatalf("unexpected body: %s", bodyBytes)
	}
}

func TestProxy_HandleRequest_WithBasicAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	p := New(testLogger())
	err := p.Configure(map[string]any{
		"base_url":  ts.URL,
		"auth_type": "basic",
	}, map[string]string{"username": "admin", "password": "secret"})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Method: "GET",
		URL:    "/test",
	})
	if err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	var httpResp struct {
		StatusCode int `json:"status_code"`
	}
	_ = json.Unmarshal([]byte(resp.Data), &httpResp)
	if httpResp.StatusCode != 200 {
		t.Fatalf("expected 200 (auth passed), got %d", httpResp.StatusCode)
	}
}

func TestProxy_HandleRequest_DefaultGET(t *testing.T) {
	var receivedMethod string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(200)
	}))
	defer ts.Close()

	p := New(testLogger())
	_ = p.Configure(map[string]any{"base_url": ts.URL}, nil)

	_, _ = p.HandleRequest(context.Background(), &proxy.ActionRequest{URL: "/test"})
	if receivedMethod != "GET" {
		t.Fatalf("expected default GET, got %s", receivedMethod)
	}
}

func TestProxy_HealthCheck_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	p := New(testLogger())
	_ = p.Configure(map[string]any{"base_url": ts.URL}, nil)

	if err := p.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestProxy_HealthCheck_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	p := New(testLogger())
	_ = p.Configure(map[string]any{"base_url": ts.URL}, nil)

	if err := p.HealthCheck(context.Background()); err == nil {
		t.Fatal("expected error for 500 status")
	}
}

func TestProxy_Close(t *testing.T) {
	p := New(testLogger())
	_ = p.Configure(map[string]any{"base_url": "http://localhost"}, nil)

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
