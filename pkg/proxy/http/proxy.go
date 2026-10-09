package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
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
	baseParsed      *url.URL
	authType        string // none, basic, bearer, custom_header
	creds           map[string]string
	tlsSkipVerify   bool
	followRedirects bool
	dsType          string // datasource type label, e.g. "prometheus"
	maxRespBytes    int64
	client          *http.Client
	logger          *slog.Logger
}

// defaultMaxResponseBytes caps buffered upstream responses (256 MiB). Responses
// are held in memory and base64-encoded into one websocket message.
const defaultMaxResponseBytes int64 = 256 << 20

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
	if baseParsed.Hostname() == "" {
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

	dsType, _ := config["datasource_type"].(string)

	maxRespBytes := defaultMaxResponseBytes
	switch v := config["max_response_bytes"].(type) {
	case int:
		if v > 0 {
			maxRespBytes = int64(v)
		}
	case int64:
		if v > 0 {
			maxRespBytes = v
		}
	case float64:
		if v > 0 {
			maxRespBytes = int64(v)
		}
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
			reqHost := strings.TrimSuffix(req.URL.Hostname(), ".")
			baseHost := strings.TrimSuffix(baseParsed.Hostname(), ".")
			if !strings.EqualFold(req.URL.Scheme, baseParsed.Scheme) || !strings.EqualFold(reqHost, baseHost) || reqPort != basePort {
				return fmt.Errorf("cross-origin redirect to %q not permitted", req.URL.Redacted())
			}
			return nil
		}
	}

	var transport *http.Transport
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaultTransport.Clone()
	} else {
		transport = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.InsecureSkipVerify = skipVerify // nolint:gosec
	transport.TLSClientConfig.ServerName = baseParsed.Hostname()
	if err := applyTLSMaterial(transport.TLSClientConfig, creds); err != nil {
		return err
	}

	newClient := &http.Client{
		Timeout:       120 * time.Second,
		Transport:     transport,
		CheckRedirect: checkRedirect,
	}

	var credsCopy map[string]string
	if creds != nil {
		credsCopy = make(map[string]string, len(creds))
		for k, v := range creds {
			credsCopy[k] = v
		}
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		if newClient.Transport != nil {
			newClient.CloseIdleConnections()
		}
		return fmt.Errorf("proxy is closed")
	}

	oldClient := p.client
	p.baseURL = baseURL
	p.baseParsed = baseParsed
	p.authType = authType
	p.tlsSkipVerify = skipVerify
	p.followRedirects = followRedirects
	p.dsType = dsType
	p.maxRespBytes = maxRespBytes
	p.creds = credsCopy
	p.client = newClient
	p.mu.Unlock()

	if oldClient != nil && oldClient.Transport != nil {
		oldClient.CloseIdleConnections()
	}

	return nil
}

// httpRequestFields is the HTTP request to make, wherever the sender put it.
type httpRequestFields struct {
	method string
	url    string
	header map[string][]string
	body   string
}

// requestFields reads the HTTP request from either envelope the relay uses.
//
// The unified shape carries method, url, header and body at the top level. The legacy
// execute envelope ({body: {action_name, action_params}}) carries them inside
// action_params, and the websocket handler hands those over as req.Params only. Reading
// the top level alone sent every request through that route to the datasource's base URL
// (a Prometheus answered 302 for "/"), so fall back to Params when the top level has no
// URL. The top level wins when both are present.
func requestFields(req *proxy.ActionRequest) httpRequestFields {
	f := httpRequestFields{method: req.Method, url: req.URL, header: req.Header, body: req.Body}
	if f.url != "" || req.Params == nil {
		return f
	}
	if v, ok := req.Params["url"].(string); ok {
		f.url = v
	}
	if f.method == "" {
		if v, ok := req.Params["method"].(string); ok {
			f.method = v
		}
	}
	if f.body == "" {
		if v, ok := req.Params["body"].(string); ok {
			f.body = v
		}
	}
	if len(f.header) == 0 {
		f.header = headersFromParams(req.Params["header"])
	}
	return f
}

// headersFromParams converts the JSON-decoded header object ({"K": ["v"]} or {"K": "v"})
// to the shape http.Header takes. Values that are neither are skipped.
func headersFromParams(raw any) map[string][]string {
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string][]string, len(obj))
	for k, v := range obj {
		switch vals := v.(type) {
		case string:
			out[k] = []string{vals}
		case []any:
			for _, item := range vals {
				if str, ok := item.(string); ok {
					out[k] = append(out[k], str)
				}
			}
		case []string:
			out[k] = append(out[k], vals...)
		}
	}
	return out
}

// resolveTargetURL appends the request path/query to the configured base_url
// and guarantees the result still targets the base_url's scheme and host. The
// request URL comes from the control plane (untrusted from CodeQL's point of
// view); without this guard a value such as "@evil.com/..." or "//evil.com"
// could redirect the request to an arbitrary server (SSRF, CWE-918).
func (p *Proxy) resolveTargetURL(base *url.URL, reqURL string) (string, error) {
	if base == nil {
		return "", fmt.Errorf("base_url is not configured")
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
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, fmt.Errorf("proxy is closed")
	}
	baseParsed := p.baseParsed
	authType := p.authType
	creds := p.creds
	client := p.client
	maxRespBytes := p.maxRespBytes
	p.mu.RUnlock()

	if client == nil || baseParsed == nil {
		return nil, fmt.Errorf("http proxy not configured")
	}

	fields := requestFields(req)

	targetURL, err := p.resolveTargetURL(baseParsed, fields.url)
	if err != nil {
		return nil, err
	}

	var bodyReader io.Reader
	if fields.body != "" {
		decoded, err := base64.StdEncoding.DecodeString(fields.body)
		if err != nil {
			bodyReader = bytes.NewReader([]byte(fields.body))
		} else {
			bodyReader = bytes.NewReader(decoded)
		}
	}

	method := fields.method
	if method == "" {
		method = "GET"
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Copy headers from the original request
	for k, vals := range fields.header {
		for _, v := range vals {
			httpReq.Header.Add(k, v)
		}
	}

	// Inject auth
	p.injectAuthWith(httpReq, authType, creds)

	resp, err := client.Do(httpReq)
	if err != nil {
		if isNetworkError(err) {
			return nil, fmt.Errorf("executing request: %w: %w", proxy.ErrUpstreamUnreachable, err)
		}
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read one byte past the cap to tell "exactly at the limit" from "over it".
	// Guard the +1 so a cap of MaxInt64 cannot wrap negative and read nothing.
	readLimit := maxRespBytes
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if int64(len(respBody)) > maxRespBytes {
		return nil, fmt.Errorf("response exceeds max_response_bytes (%d)", maxRespBytes)
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
	baseParsed := p.baseParsed
	authType := p.authType
	creds := p.creds
	client := p.client
	dsType := p.dsType
	p.mu.RUnlock()

	if client == nil || baseURL == "" {
		return fmt.Errorf("http proxy not configured")
	}

	if dsType == "prometheus" {
		return p.prometheusHealthCheck(ctx, client, baseParsed, authType, creds)
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

// prometheusHealthCheck requires a 2xx from /-/ready, falling back to the
// buildinfo API for Prometheus-compatible stores (Mimir, VictoriaMetrics,
// Thanos) that do not serve /-/ready under the base path. A bare 404 or 401
// from a wrong host or reverse proxy must not count as a reachable store.
func (p *Proxy) prometheusHealthCheck(ctx context.Context, client *http.Client, base *url.URL, authType string, creds map[string]string) error {
	var lastErr error
	for _, path := range []string{"/-/ready", "/api/v1/status/buildinfo"} {
		target, err := p.resolveTargetURL(base, path)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return err
		}
		p.injectAuthWith(req, authType, creds)

		resp, err := client.Do(req)
		if err != nil {
			// Unreachable on the first path means unreachable on the second.
			return fmt.Errorf("health check failed: %w", err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("health check %s returned status %d", path, resp.StatusCode)
	}
	return lastErr
}

// applyTLSMaterial loads optional custom CA and client certificate (mTLS)
// material from credentials: ca_cert, client_cert and client_key, all PEM.
func applyTLSMaterial(cfg *tls.Config, creds map[string]string) error {
	if ca := creds["ca_cert"]; ca != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(ca)) {
			return fmt.Errorf("ca_cert contains no valid PEM certificates")
		}
		cfg.RootCAs = pool
	}

	cert, key := creds["client_cert"], creds["client_key"]
	if (cert == "") != (key == "") {
		return fmt.Errorf("client_cert and client_key must be provided together")
	}
	if cert != "" {
		pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
		if err != nil {
			return fmt.Errorf("invalid client_cert/client_key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return nil
}

// isNetworkError reports whether err is a failure to reach the upstream
// (DNS, dial, TLS handshake, timeout) rather than a protocol-level error.
func isNetworkError(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	// http.Client.Do wraps every failure in *url.Error, which itself satisfies
	// net.Error. Look at what it wraps, or a redirect loop or unsupported scheme
	// would be reported as the target being unreachable.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var certErr *tls.CertificateVerificationError
	return errors.As(err, &certErr)
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

	if client != nil && client.Transport != nil {
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
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}
