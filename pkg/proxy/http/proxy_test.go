package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
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

func TestProxy_ConfigureInvalidBaseURL(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{"base_url": "http://invalid-url\x7f"}, nil)
	if err == nil {
		t.Fatal("expected error when base_url is malformed")
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

func TestProxy_ConfigureFollowRedirects(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{
		"base_url":         "http://localhost:8080",
		"follow_redirects": true,
	}, nil)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if !p.followRedirects {
		t.Fatal("expected followRedirects to be true")
	}
}

func TestProxy_HandleRequest_DefaultDoesNotFollowRedirect(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("redirected destination"))
	}))
	defer targetServer.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL, http.StatusFound)
	}))
	defer ts.Close()

	p := New(testLogger())
	err := p.Configure(map[string]any{"base_url": ts.URL}, nil)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Method: "GET",
		URL:    "/redirect",
	})
	if err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	var httpResp struct {
		StatusCode int                 `json:"status_code"`
		Header     map[string][]string `json:"header"`
		Body       string              `json:"body"`
	}
	if err := json.Unmarshal([]byte(resp.Data), &httpResp); err != nil {
		t.Fatalf("unmarshal response data: %v", err)
	}

	// Default must return 302 Found directly without following redirect to targetServer
	if httpResp.StatusCode != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, httpResp.StatusCode)
	}
	locs := httpResp.Header["Location"]
	if len(locs) == 0 || locs[0] != targetServer.URL {
		t.Fatalf("expected Location header %s, got %v", targetServer.URL, locs)
	}
}

func TestProxy_HandleRequest_FollowRedirectsEnabled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/destination", http.StatusFound)
			return
		}
		if r.URL.Path == "/destination" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("redirected destination"))
			return
		}
	}))
	defer ts.Close()

	p := New(testLogger())
	err := p.Configure(map[string]any{
		"base_url":         ts.URL,
		"follow_redirects": true,
	}, nil)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Method: "GET",
		URL:    "/redirect",
	})
	if err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}

	var httpResp struct {
		StatusCode int                 `json:"status_code"`
		Header     map[string][]string `json:"header"`
		Body       string              `json:"body"`
	}
	if err := json.Unmarshal([]byte(resp.Data), &httpResp); err != nil {
		t.Fatalf("unmarshal response data: %v", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 after following redirect, got %d", httpResp.StatusCode)
	}

	bodyBytes, _ := base64.StdEncoding.DecodeString(httpResp.Body)
	if string(bodyBytes) != "redirected destination" {
		t.Fatalf("expected body %q, got %q", "redirected destination", string(bodyBytes))
	}
}

func TestProxy_HandleRequest_FollowRedirects_BlocksCrossOrigin(t *testing.T) {
	externalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("external resource"))
	}))
	defer externalServer.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, externalServer.URL+"/secret", http.StatusFound)
	}))
	defer ts.Close()

	p := New(testLogger())
	err := p.Configure(map[string]any{
		"base_url":         ts.URL,
		"follow_redirects": true,
	}, nil)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	_, err = p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Method: "GET",
		URL:    "/redirect",
	})
	if err == nil {
		t.Fatal("expected cross-origin redirect to be blocked with error")
	}
}

func TestEffectivePort(t *testing.T) {
	uHTTP, _ := url.Parse("http://example.com/path")
	if port := effectivePort(uHTTP); port != "80" {
		t.Fatalf("expected port 80 for http URL, got %q", port)
	}

	uHTTPS, _ := url.Parse("https://example.com/path")
	if port := effectivePort(uHTTPS); port != "443" {
		t.Fatalf("expected port 443 for https URL, got %q", port)
	}

	uExplicit, _ := url.Parse("http://example.com:8080/path")
	if port := effectivePort(uExplicit); port != "8080" {
		t.Fatalf("expected port 8080 for explicit port URL, got %q", port)
	}

	if port := effectivePort(nil); port != "" {
		t.Fatalf("expected empty string for nil URL, got %q", port)
	}
}

func TestProxy_Configure_ClosesPreviousIdleConnections(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	p := New(testLogger())
	err := p.Configure(map[string]any{"base_url": ts.URL}, nil)
	if err != nil {
		t.Fatalf("initial Configure: %v", err)
	}

	// Reconfiguring should not fail and should close idle connections of the old client
	err = p.Configure(map[string]any{"base_url": ts.URL, "follow_redirects": true}, nil)
	if err != nil {
		t.Fatalf("reconfiguration Configure: %v", err)
	}
}

func TestProxy_Configure_ValidatesSchemeAndHost(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr string
	}{
		{
			name:    "unsupported scheme ftp",
			baseURL: "ftp://example.com/resource",
			wantErr: `base_url scheme must be http or https, got "ftp"`,
		},
		{
			name:    "missing scheme with port",
			baseURL: "localhost:8080",
			wantErr: `base_url scheme must be http or https, got "localhost"`,
		},
		{
			name:    "missing scheme without port",
			baseURL: "example.com/api",
			wantErr: `base_url scheme must be http or https, got ""`,
		},
		{
			name:    "relative url",
			baseURL: "/api/v1",
			wantErr: `base_url scheme must be http or https, got ""`,
		},
		{
			name:    "missing host",
			baseURL: "http://",
			wantErr: `base_url must specify a host`,
		},
		{
			name:    "valid http",
			baseURL: "http://localhost:8080",
			wantErr: "",
		},
		{
			name:    "valid https",
			baseURL: "https://example.com:8443",
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(testLogger())
			err := p.Configure(map[string]any{"base_url": tt.baseURL}, nil)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("expected error %q, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestProxy_Configure_ClosedProxy(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{"base_url": "http://localhost:8080"}, nil)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = p.Configure(map[string]any{"base_url": "http://localhost:8080"}, nil)
	if err == nil || err.Error() != "proxy is closed" {
		t.Fatalf("expected 'proxy is closed' error, got %v", err)
	}
}

func TestProxy_ConcurrentConfigureAndRequests(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	p := New(testLogger())
	_ = p.Configure(map[string]any{"base_url": ts.URL}, nil)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			_ = p.Configure(map[string]any{
				"base_url":         ts.URL,
				"follow_redirects": idx%2 == 0,
			}, nil)
		}(i)
		go func() {
			defer wg.Done()
			_, _ = p.HandleRequest(context.Background(), &proxy.ActionRequest{
				Method: "GET",
				URL:    "/test",
			})
		}()
	}
	wg.Wait()
}
