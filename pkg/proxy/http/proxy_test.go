package http

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

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

	uMixedHTTP, _ := url.Parse("HTTP://example.com/path")
	if port := effectivePort(uMixedHTTP); port != "80" {
		t.Fatalf("expected port 80 for HTTP URL, got %q", port)
	}

	uMixedHTTPS, _ := url.Parse("Https://example.com/path")
	if port := effectivePort(uMixedHTTPS); port != "443" {
		t.Fatalf("expected port 443 for Https URL, got %q", port)
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
			name:    "missing host with port",
			baseURL: "http://:8080",
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

func TestProxy_Configure_CredsDefensiveCopy(t *testing.T) {
	p := New(testLogger())
	creds := map[string]string{
		"bearer_token": "original-token",
	}
	err := p.Configure(map[string]any{
		"base_url":  "http://localhost:8080",
		"auth_type": "bearer",
	}, creds)
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	// Mutate the original map
	creds["bearer_token"] = "mutated-token"

	req, _ := http.NewRequest("GET", "http://localhost:8080/test", nil)
	p.injectAuth(req)

	if got := req.Header.Get("Authorization"); got != "Bearer original-token" {
		t.Fatalf("expected original-token, got %q", got)
	}
}

func TestProxy_HandleRequest_NilRequest(t *testing.T) {
	p := New(testLogger())
	_ = p.Configure(map[string]any{"base_url": "http://localhost:8080"}, nil)

	_, err := p.HandleRequest(context.Background(), nil)
	if err == nil || err.Error() != "request cannot be nil" {
		t.Fatalf("expected 'request cannot be nil' error, got %v", err)
	}
}

func newPromProxy(t *testing.T, srv *httptest.Server, extra map[string]any, creds map[string]string) *Proxy {
	t.Helper()
	cfg := map[string]any{"base_url": srv.URL, "datasource_type": "prometheus"}
	for k, v := range extra {
		cfg[k] = v
	}
	p := New(testLogger())
	if err := p.Configure(cfg, creds); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return p
}

func TestProxy_PrometheusHealth(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr bool
	}{
		{"ready 200", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/-/ready" {
				w.WriteHeader(200)
				return
			}
			w.WriteHeader(404)
		}, false},
		{"fallback to buildinfo", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/status/buildinfo" {
				w.WriteHeader(200)
				return
			}
			w.WriteHeader(404)
		}, false},
		{"all 404 is unhealthy", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }, true},
		{"401 is unhealthy", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }, true},
		{"503 is unhealthy", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			err := newPromProxy(t, srv, nil, nil).HealthCheck(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestProxy_NonPrometheusHealthUnchanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer srv.Close()
	p := New(testLogger())
	if err := p.Configure(map[string]any{"base_url": srv.URL}, nil); err != nil {
		t.Fatal(err)
	}
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Fatalf("generic http 404 should stay healthy: %v", err)
	}
}

func TestProxy_UpstreamUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	p := newPromProxy(t, srv, nil, nil)
	srv.Close() // connection refused from here on

	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Method: "GET", URL: "/api/v1/query?query=up"})
	if !errors.Is(err, proxy.ErrUpstreamUnreachable) {
		t.Fatalf("expected ErrUpstreamUnreachable, got %v", err)
	}
}

func TestProxy_UpstreamHTTPErrorPassesThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	resp, err := newPromProxy(t, srv, nil, nil).HandleRequest(context.Background(), &proxy.ActionRequest{URL: "/x"})
	if err != nil {
		t.Fatalf("upstream 500 must not be an error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestProxy_MaxResponseBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 100))
	}))
	defer srv.Close()
	p := newPromProxy(t, srv, map[string]any{"max_response_bytes": 50}, nil)
	if _, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{URL: "/x"}); err == nil {
		t.Fatal("expected error for oversized response")
	}
	p = newPromProxy(t, srv, map[string]any{"max_response_bytes": 100}, nil)
	if _, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{URL: "/x"}); err != nil {
		t.Fatalf("response at the limit must pass: %v", err)
	}
}

func pemCert(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

func TestProxy_CustomCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()

	// Without the CA the handshake fails and surfaces as unreachable.
	_, err := newPromProxy(t, srv, nil, nil).HandleRequest(context.Background(), &proxy.ActionRequest{URL: "/x"})
	if !errors.Is(err, proxy.ErrUpstreamUnreachable) {
		t.Fatalf("expected untrusted cert to fail as unreachable, got %v", err)
	}

	p := newPromProxy(t, srv, nil, map[string]string{"ca_cert": pemCert(t, srv)})
	if _, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{URL: "/x"}); err != nil {
		t.Fatalf("custom CA should trust server: %v", err)
	}
}

func TestProxy_InvalidTLSMaterial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	for name, creds := range map[string]map[string]string{
		"bad ca":       {"ca_cert": "not pem"},
		"cert no key":  {"client_cert": "x"},
		"key no cert":  {"client_key": "x"},
		"mismatch pem": {"client_cert": "x", "client_key": "y"},
	} {
		p := New(testLogger())
		if err := p.Configure(map[string]any{"base_url": srv.URL}, creds); err == nil {
			t.Errorf("%s: expected Configure error", name)
		}
	}
}

func TestProxy_MutualTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	defer srv.Close()

	certPEM, keyPEM := selfSignedClientPair(t)
	creds := map[string]string{"ca_cert": pemCert(t, srv), "client_cert": certPEM, "client_key": keyPEM}
	if err := newPromProxy(t, srv, nil, creds).HealthCheck(context.Background()); err != nil {
		t.Fatalf("mTLS health check: %v", err)
	}
	// No client cert: server rejects the handshake.
	if err := newPromProxy(t, srv, nil, map[string]string{"ca_cert": pemCert(t, srv)}).HealthCheck(context.Background()); err == nil {
		t.Fatal("expected failure without client certificate")
	}
}

func selfSignedClientPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "forager-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"canceled", context.Canceled, false},
		{"redirect loop wrapped by url.Error", &url.Error{Op: "Get", URL: "http://x", Err: errors.New("stopped after 10 redirects")}, false},
		{"unsupported scheme wrapped by url.Error", &url.Error{Op: "Get", URL: "ftp://x", Err: errors.New(`unsupported protocol scheme "ftp"`)}, false},
		{"dial error wrapped by url.Error", &url.Error{Op: "Get", URL: "http://x", Err: &net.OpError{Op: "dial", Err: errors.New("refused")}}, true},
		{"timeout wrapped by url.Error", &url.Error{Op: "Get", URL: "http://x", Err: context.DeadlineExceeded}, true},
		{"cert verification", &url.Error{Op: "Get", URL: "https://x", Err: &tls.CertificateVerificationError{}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNetworkError(tt.err); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProxy_MaxResponseBytesMaxInt64DoesNotTruncate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("hello")) }))
	defer srv.Close()
	p := newPromProxy(t, srv, map[string]any{"max_response_bytes": int64(math.MaxInt64)}, nil)
	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{URL: "/x"})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal([]byte(resp.Data), &out); err != nil {
		t.Fatal(err)
	}
	if got, _ := base64.StdEncoding.DecodeString(out.Body); string(got) != "hello" {
		t.Fatalf("body truncated: %q", got)
	}
}

// A legacy execute envelope carries the request in action_params, which reach the proxy
// as Params with the top-level URL empty. They must not be dropped: the request used to
// go to the base URL and Prometheus answered 302 for "/".
func TestProxy_ReadsRequestFromParamsWhenTopLevelURLIsEmpty(t *testing.T) {
	var gotMethod, gotURI, gotHeader, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotMethod, gotURI, gotHeader, gotBody = r.Method, r.URL.RequestURI(), r.Header.Get("X-Scope-OrgID"), string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	p := newPromProxy(t, srv, nil, nil)
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "http_request",
		Params: map[string]any{
			"method": "POST",
			"url":    "/api/v1/query?query=up&time=1",
			"header": map[string]any{"X-Scope-OrgID": []any{"tenant-1"}},
			"body":   base64.StdEncoding.EncodeToString([]byte("a=b")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != "POST" || gotURI != "/api/v1/query?query=up&time=1" || gotHeader != "tenant-1" || gotBody != "a=b" {
		t.Fatalf("request was not read from Params: %s %s hdr=%q body=%q", gotMethod, gotURI, gotHeader, gotBody)
	}
}

func TestProxy_TopLevelFieldsWinOverParams(t *testing.T) {
	var gotURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotURI = r.URL.RequestURI() }))
	defer srv.Close()

	p := newPromProxy(t, srv, nil, nil)
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		URL:    "/top",
		Params: map[string]any{"url": "/params"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotURI != "/top" {
		t.Fatalf("top-level URL must win, got %s", gotURI)
	}
}

func TestHeadersFromParams(t *testing.T) {
	got := headersFromParams(map[string]any{"A": "1", "B": []any{"2", "3", 4}, "C": []string{"5"}, "D": 6})
	want := map[string][]string{"A": {"1"}, "B": {"2", "3"}, "C": {"5"}}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for k, v := range want {
		if len(got[k]) != len(v) {
			t.Fatalf("%s: got %v want %v", k, got[k], v)
		}
	}
	if headersFromParams("not a map") != nil || headersFromParams(nil) != nil {
		t.Fatal("non-object input must give nil")
	}
}
