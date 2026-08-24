package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"nudgebee/forager/pkg/proxy"
)

// Proxy is a generic HTTP reverse proxy for any HTTP-based datasource.
type Proxy struct {
	configMu        sync.Mutex
	mu              sync.RWMutex
	closed          bool
	baseURL         string
	authType        string // none, basic, bearer, custom_header
	creds           map[string]string
	tlsSkipVerify   bool
	followRedirects bool
	client          *http.Client
	logger          *slog.Logger
}

// New creates a new HTTP proxy.
func New(logger *slog.Logger) *Proxy {
	return &Proxy{
		logger: logger,
		client: &http.Client{
			Timeout: 120 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *Proxy) Type() string { return "http-proxy" }

func (p *Proxy) Configure(config map[string]any, creds map[string]string) error {
	p.configMu.Lock()
	defer p.configMu.Unlock()

	var baseURL string
	if v, ok := config["base_url"].(string); ok {
		baseURL = v
	}
	if baseURL == "" {
		return fmt.Errorf("base_url is required for http-proxy")
	}

	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base_url %q: %w", baseURL, err)
	}
	if baseParsed.Scheme != "http" && baseParsed.Scheme != "https" {
		return fmt.Errorf("base_url scheme must be http or https, got %q", baseParsed.Scheme)
	}
	if baseParsed.Host == "" {
		return fmt.Errorf("base_url must specify a host")
	}

	var authType string
	if v, ok := config["auth_type"].(string); ok {
		authType = v
	}

	skipVerify := false
	if v, ok := config["tls_skip_verify"].(bool); ok {
		skipVerify = v
	}

	followRedirects := false
	if v, ok := config["follow_redirects"].(bool); ok {
		followRedirects = v
	}

	var checkRedirect func(req *http.Request, via []*http.Request) error
	if !followRedirects {
		checkRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		checkRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			reqPort := effectivePort(req.URL)
			basePort := effectivePort(baseParsed)
			if req.URL.Scheme != baseParsed.Scheme || req.URL.Hostname() != baseParsed.Hostname() || reqPort != basePort {
				return fmt.Errorf("cross-origin redirect to %q not permitted", req.URL.String())
			}
			return nil
		}
	}

	newClient := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify}, // nolint:gosec
		},
		CheckRedirect: checkRedirect,
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		newClient.CloseIdleConnections()
		return fmt.Errorf("proxy is closed")
	}

	oldClient := p.client
	p.baseURL = baseURL
	p.authType = authType
	p.tlsSkipVerify = skipVerify
	p.followRedirects = followRedirects
	p.creds = creds
	p.client = newClient
	p.mu.Unlock()

	if oldClient != nil {
		oldClient.CloseIdleConnections()
	}

	return nil
}

// resolveTargetURL appends the request path/query to the configured base_url
// and guarantees the result still targets the base_url's scheme and host. The
// request URL comes from the control plane (untrusted from CodeQL's point of
// view); without this guard a value such as "@evil.com/..." or "//evil.com"
// could redirect the request to an arbitrary server (SSRF, CWE-918).
func (p *Proxy) resolveTargetURL(baseURL, reqURL string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base_url %q: %w", baseURL, err)
	}

	// The request URL must be a path/query relative to base_url; it must not
	// carry its own scheme or host.
	ref, err := url.Parse(reqURL)
	if err != nil {
		return "", fmt.Errorf("invalid request url %q: %w", reqURL, err)
	}
	if ref.IsAbs() || ref.Host != "" {
		return "", fmt.Errorf("request url must be relative to base_url, got %q", reqURL)
	}

	// Build the target from base_url's trusted scheme/host/userinfo, appending
	// the request path and query. The destination host can never derive from the
	// request URL. Collapse a duplicated slash at the join boundary so a
	// trailing-slash base_url plus a leading-slash request path does not produce
	// "//"; otherwise the path is appended verbatim to preserve existing routing.
	basePath, refPath := base.Path, ref.Path
	if strings.HasSuffix(basePath, "/") && strings.HasPrefix(refPath, "/") {
		refPath = refPath[1:]
	}
	out := &url.URL{
		Scheme:   base.Scheme,
		User:     base.User,
		Host:     base.Host,
		Path:     basePath + refPath,
		RawQuery: ref.RawQuery,
		Fragment: ref.Fragment,
	}
	return out.String(), nil
}

func (p *Proxy) HandleRequest(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, fmt.Errorf("proxy is closed")
	}
	baseURL := p.baseURL
	authType := p.authType
	creds := p.creds
	client := p.client
	p.mu.RUnlock()

	if client == nil || baseURL == "" {
		return nil, fmt.Errorf("http proxy not configured")
	}

	targetURL, err := p.resolveTargetURL(baseURL, req.URL)
	if err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if req.Body != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			bodyReader = bytes.NewReader([]byte(req.Body))
		} else {
			bodyReader = bytes.NewReader(decoded)
		}
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Copy headers from the original request
	for k, vals := range req.Header {
		for _, v := range vals {
			httpReq.Header.Add(k, v)
		}
	}

	// Inject auth
	p.injectAuthWith(httpReq, authType, creds)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Build response in the same format as the K8s agent HTTPResponse
	httpResp := map[string]any{
		"status_code": resp.StatusCode,
		"header":      resp.Header,
		"body":        base64.StdEncoding.EncodeToString(respBody),
	}

	respData, _ := json.Marshal(httpResp)
	return &proxy.ActionResponse{
		StatusCode: 200,
		Data:       string(respData),
	}, nil
}

func (p *Proxy) HealthCheck(ctx context.Context) error {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return fmt.Errorf("proxy is closed")
	}
	baseURL := p.baseURL
	authType := p.authType
	creds := p.creds
	client := p.client
	p.mu.RUnlock()

	if client == nil || baseURL == "" {
		return fmt.Errorf("http proxy not configured")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return err
	}
	p.injectAuthWith(req, authType, creds)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}
	return nil
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	client := p.client
	p.client = nil
	p.mu.Unlock()

	if client != nil {
		client.CloseIdleConnections()
	}
	return nil
}

// CollectMetadata returns connection info for the HTTP datasource.
func (p *Proxy) CollectMetadata(_ context.Context) (map[string]any, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return map[string]any{
		"base_url": p.baseURL,
	}, nil
}

func (p *Proxy) injectAuth(req *http.Request) {
	p.mu.RLock()
	authType := p.authType
	creds := p.creds
	p.mu.RUnlock()
	p.injectAuthWith(req, authType, creds)
}

func (p *Proxy) injectAuthWith(req *http.Request, authType string, creds map[string]string) {
	switch authType {
	case "basic":
		req.SetBasicAuth(creds["username"], creds["password"])
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+creds["bearer_token"])
	case "custom_header":
		if name := creds["custom_header_name"]; name != "" {
			req.Header.Set(name, creds["custom_header_value"])
		}
	}
}

func effectivePort(u *url.URL) string {
	if u == nil {
		return ""
	}
	port := u.Port()
	if port != "" {
		return port
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}
