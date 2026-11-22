package mcp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func apiKeyProxy(t *testing.T, mcpURL string) *Proxy {
	t.Helper()
	p := New(quietLogger())
	t.Cleanup(func() { _ = p.Close() })
	err := p.Configure(map[string]any{"transport": "http", "url": mcpURL, "auth_type": "api_key"},
		map[string]string{"api_key_name": "X-API-Key", "api_key_value": "secret-key"})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return p
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// When the MCP server redirects to another host, that host must not receive
// the datasource's API key, or any request at all.
func TestProxy_CrossOriginRedirectKeepsKeyOnOrigin(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		if r.Header.Get("X-API-Key") != "" {
			t.Errorf("the other host received the API key")
		}
	}))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	err := apiKeyProxy(t, origin.URL+"/mcp").HealthCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "another origin") {
		t.Fatalf("expected the redirect to be refused, got %v", err)
	}
	if n := otherHits.Load(); n != 0 {
		t.Fatalf("the other host was contacted %d times", n)
	}
}

// A redirect within the MCP server (a trailing slash, a moved path) is still
// followed, with the key.
func TestProxy_SameOriginRedirectIsFollowed(t *testing.T) {
	var gotKey atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			http.Redirect(w, r, "/mcp/", http.StatusTemporaryRedirect)
			return
		}
		gotKey.Store(r.Header.Get("X-API-Key"))
	}))
	defer srv.Close()

	if err := apiKeyProxy(t, srv.URL+"/mcp").HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if gotKey.Load() != "secret-key" {
		t.Fatalf("the redirected request lost the key: %v", gotKey.Load())
	}
}

func TestRedirectAllowed(t *testing.T) {
	for _, c := range []struct {
		target, origin string
		want           bool
	}{
		{"https://MCP.example.com./y", "https://mcp.example.com/x", true},
		{"https://mcp.example.com/y", "https://mcp.example.com:443/x", true},
		// An upgrade to https on the same server keeps the key on that server.
		{"https://mcp.example.com/x", "http://mcp.example.com/x", true},
		{"https://mcp.example.com:8080/x", "http://mcp.example.com:8080/x", true},
		// A downgrade, or a change of port or host, is refused.
		{"http://mcp.example.com/x", "https://mcp.example.com/x", false},
		{"https://mcp.example.com:8443/x", "http://mcp.example.com:8080/x", false},
		{"https://mcp.example.com/x", "https://mcp.example.com:8443/x", false},
		{"https://evil.example.com/x", "https://mcp.example.com/x", false},
		{"https://evil.example.com/x", "http://mcp.example.com/x", false},
	} {
		target, origin := mustURL(t, c.target), mustURL(t, c.origin)
		if got := redirectAllowed(target, origin); got != c.want {
			t.Errorf("redirectAllowed(%s, from %s) = %v, want %v", c.target, c.origin, got, c.want)
		}
	}
}

// The client never dials a cloud metadata address, whatever the URL is.
func TestProxy_TransportRefusesMetadataDial(t *testing.T) {
	p := New(quietLogger())
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	resp, err := p.client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("expected a dial refusal, got %v", err)
	}
}

// A URL or OAuth token URL that names a metadata endpoint is refused at
// configure time, which still holds behind an HTTP(S)_PROXY.
func TestProxy_ConfigureRefusesMetadataHost(t *testing.T) {
	for _, c := range []struct {
		url   string
		creds map[string]string
		field string
	}{
		{"http://169.254.169.254/mcp", nil, "url"},
		{"http://metadata.google.internal/mcp", nil, "url"},
		{"https://mcp.example.com/mcp", map[string]string{"oauth_token_url": "http://[fd00:ec2::254]/token"}, "oauth_token_url"},
	} {
		err := New(quietLogger()).Configure(map[string]any{"url": c.url}, c.creds)
		if err == nil {
			t.Errorf("%s %v: expected Configure to refuse", c.url, c.creds)
			continue
		}
		// The error names the field, so an OAuth datasource's admin knows which URL to fix.
		if !strings.Contains(err.Error(), "invalid MCP "+c.field+":") {
			t.Errorf("%s %v: error %q does not name %s", c.url, c.creds, err, c.field)
		}
	}
	p := New(quietLogger())
	defer func() { _ = p.Close() }()
	if err := p.Configure(map[string]any{"url": "https://mcp.example.com/mcp"}, nil); err != nil {
		t.Fatalf("ordinary host refused: %v", err)
	}
}
